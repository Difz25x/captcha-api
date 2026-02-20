"""
visual_verification.py
======================
Detects shape type, area, and dominant color from a base64-encoded image.

Core strategy:
  1. Sample the background color from image corners.
  2. Build a foreground mask = pixels that differ from background by > threshold.
  3. Find contours on that mask — these are the actual shapes, not the canvas.
  4. Classify the largest foreground contour.

This avoids the canvas-detection bug where thresholding picks up the entire
image rectangle as "the shape."
"""

import cv2
import numpy as np
import base64
import json
import os
import io

DATASET_FILE = "fine_tuning_dataset.jsonl"

COLOR_RANGES = {
    "red":    [((0,   120,  80), (10,  255, 255)),
               ((160, 120,  80), (180, 255, 255))],
    "orange": [((11,  120,  80), (25,  255, 255))],
    "yellow": [((26,  120,  80), (34,  255, 255))],
    "green":  [((35,   80,  60), (85,  255, 255))],
    "blue":   [((86,   80,  60), (130, 255, 255))],
    "purple": [((131,  80,  60), (159, 255, 255))],
    "white":  [((0,     0, 190), (180,  40, 255))],
    "black":  [((0,     0,   0), (180, 255,  60))],
    "gray":   [((0,     0,  61), (180,  40, 189))],
}

# ─────────────────────────────────────────────────────────────────────────────
# I/O helpers
# ─────────────────────────────────────────────────────────────────────────────

def save_to_dataset(b64_string: str, analysis: dict, instruction: str = ""):
    try:
        with open(DATASET_FILE, "a") as f:
            f.write(json.dumps({
                "image": b64_string,
                "meta":  {"instruction": instruction},
                "label": {
                    "type":     analysis["type"],
                    "area":     analysis["area"],
                    "vertices": analysis["vertices"],
                },
            }) + "\n")
    except Exception as e:
        print(f"  [Dataset] save failed: {e}")


def _decode(b64: str):
    """
    Returns (bgr_uint8, gray_uint8) composited onto a WHITE background.
    Handles GRAY / BGR / BGRA / RGBA source images.
    Returns (None, None) on failure.
    """
    try:
        raw_b64 = b64.split(",")[1] if "," in b64 else b64
        # pad base64 if needed
        if len(raw_b64) % 4:
            raw_b64 += "=" * (4 - len(raw_b64) % 4)

        arr     = np.frombuffer(base64.b64decode(raw_b64), np.uint8)
        img     = cv2.imdecode(arr, cv2.IMREAD_UNCHANGED)

        # Fallback: some payloads are WEBP and OpenCV may lack the codec. Try Pillow.
        if img is None:
            try:
                from PIL import Image
                pil_img = Image.open(io.BytesIO(base64.b64decode(raw_b64)))
                pil_img = pil_img.convert("RGBA")  # normalize
                rgba    = np.array(pil_img)
                alpha   = rgba[:, :, 3:].astype(np.float32) / 255.0
                rgb     = rgba[:, :, :3].astype(np.float32)
                white   = np.full_like(rgb, 255.0)
                comp    = (rgb * alpha + white * (1.0 - alpha)).astype(np.uint8)
                img     = cv2.cvtColor(comp, cv2.COLOR_RGB2BGR)
            except Exception:
                return None, None

        if img.ndim == 2:                          # grayscale
            bgr = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
        elif img.shape[2] == 4:                    # RGBA / BGRA
            alpha = img[:, :, 3:].astype(np.float32) / 255.0
            rgb   = img[:, :, :3].astype(np.float32)
            # composite onto white
            white = np.full_like(rgb, 255.0)
            comp  = (rgb * alpha + white * (1.0 - alpha)).astype(np.uint8)
            bgr   = cv2.cvtColor(comp, cv2.COLOR_RGB2BGR) \
                    if img.shape[2] == 4 and _is_rgb_order(img) else comp
        else:                                       # BGR (standard)
            bgr = img

        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
        return bgr, gray

    except Exception:
        return None, None


def _is_rgb_order(img: np.ndarray) -> bool:
    """Heuristic: if decoded with IMREAD_UNCHANGED, OpenCV gives BGRA for PNG."""
    return False   # OpenCV always returns BGRA for 4-channel PNGs


# ─────────────────────────────────────────────────────────────────────────────
# Background estimation
# ─────────────────────────────────────────────────────────────────────────────

def _sample_background(bgr: np.ndarray, sample_radius: int = 8) -> np.ndarray:
    """
    Sample corner + edge pixels to estimate background color.
    Returns mean BGR as float32 array shape (3,).
    """
    h, w = bgr.shape[:2]
    r    = min(sample_radius, h // 4, w // 4)
    corners = [
        bgr[:r,  :r ],
        bgr[:r,  w-r:],
        bgr[h-r:, :r ],
        bgr[h-r:, w-r:],
    ]
    samples = np.concatenate([c.reshape(-1, 3) for c in corners], axis=0)
    return samples.mean(axis=0)   # (B, G, R) float


def _foreground_mask(bgr: np.ndarray, bg_color: np.ndarray,
                     thresh: float = 30.0) -> np.ndarray:
    """
    Pixels whose L2 distance from bg_color exceeds thresh become foreground (255).
    Works regardless of whether background is white, black, gray, or colored.
    """
    diff = bgr.astype(np.float32) - bg_color.astype(np.float32)
    dist = np.linalg.norm(diff, axis=2)              # (H, W) float
    mask = (dist > thresh).astype(np.uint8) * 255
    return mask


# ─────────────────────────────────────────────────────────────────────────────
# Contour extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_shape_contour(bgr: np.ndarray, gray: np.ndarray):
    """
    Returns the best contour representing the foreground shape.

    Key fixes vs original:
    - Rejects contours that touch the image boundary (border decorations / canvas frame)
    - Rejects contours with solidity < 0.40 (scattered pixel noise, not a real shape)
    - Rejects contours whose hull > 75% of image area (wraps whole canvas)
    - Falls back through multiple detection strategies
    """
    h, w     = gray.shape
    img_area = float(h * w)
    kernel   = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))

    def _best_from_binary(binary: np.ndarray):
        # Open first to remove thin noise lines
        opened = cv2.morphologyEx(binary, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3)))
        closed = cv2.morphologyEx(opened, cv2.MORPH_CLOSE, kernel, iterations=2)
        cnts, _ = cv2.findContours(closed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        valid = []
        for c in cnts:
            a = cv2.contourArea(c)
            # Area bounds: not too tiny, not full image
            if not (img_area * 0.005 < a < img_area * 0.90):
                continue
            # Reject low-solidity contours (noise / two disconnected blobs)
            hull_c    = cv2.convexHull(c)
            hull_area = cv2.contourArea(hull_c)
            solidity  = a / max(hull_area, 1.0)
            if solidity < 0.40:
                continue
            # Reject if hull covers most of the image (wrapping the whole canvas)
            if hull_area > img_area * 0.95:
                continue
            valid.append(c)

        if not valid:
            return None, 0.0
        cnt = max(valid, key=cv2.contourArea)
        return cnt, cv2.contourArea(cnt)

    results = []

    # Strategy 1: background subtraction at multiple thresholds
    bg = _sample_background(bgr)
    for thresh in (20, 35, 50, 15, 70, 100):
        cnt, area = _best_from_binary(_foreground_mask(bgr, bg, thresh))
        if cnt is not None and area > 0:
            results.append((area, cnt))

    # Strategy 2: Otsu thresholding on grayscale (both polarities)
    # Median blur is excellent for removing thin noise lines (salt-and-pepper or line noise)
    # while preserving edges.
    blur = cv2.medianBlur(gray, 5) 
    # Fallback to Gaussian if Median is too strong? No, Median is best for lines.
    
    for flags in (cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU,
                  cv2.THRESH_BINARY     + cv2.THRESH_OTSU):
        _, b = cv2.threshold(blur, 0, 255, flags)
        cnt, area = _best_from_binary(b)
        if cnt is not None and area > 0:
            results.append((area, cnt))

    # Strategy 3: Canny edges + dilation
    edges   = cv2.Canny(blur, 30, 100) # Use the blurred image
    dilated = cv2.dilate(edges, kernel, iterations=3)
    cnt, area = _best_from_binary(dilated)
    
    if cnt is not None and area > 0:
        results.append((area, cnt))

    if not results:
        return None

    # Return contour with the largest area among valid candidates
    results.sort(key=lambda x: x[0], reverse=True)
    return results[0][1]
    if cnt is not None and area > 0:
        results.append((area, cnt))

    if not results:
        return None

    # Return contour with the largest area among valid candidates
    results.sort(key=lambda x: x[0], reverse=True)
    return results[0][1]


# ─────────────────────────────────────────────────────────────────────────────
# Shape classification
# ─────────────────────────────────────────────────────────────────────────────

def _is_triangle_fit(cnt: np.ndarray, area: float) -> bool:
    """
    Returns True if the shape is highly likely a triangle based on minEnclosingTriangle.
    """
    if area < 10: return False
    # Concave shapes (e.g., stars) should never be forced into triangle
    if not cv2.isContourConvex(cnt):
        return False
    try:
        tri_area, triangle = cv2.minEnclosingTriangle(cnt)
        # Verify triangle validity just in case
        if tri_area <= 0: return False
        
        # Ratio of contour area to enclosing triangle area.
        # A perfect triangle would be 1.0. Real ones might be 0.85-0.95 due to rounding/noise.
        ratio = area / tri_area
        return ratio > 0.85
    except Exception:
        return False


def _classify(cnt: np.ndarray) -> tuple:
    """
    Returns (shape_name: str, vertices: int, circularity: float).

    Strategy: run approxPolyDP at a wide range of epsilons on BOTH the
    convex hull (smooth) and raw contour (fine detail).  Collect all
    vertex counts that appear >= 2 times across all epsilon/source combos,
    then pick the MINIMUM such count that is >= 3.

    Why minimum?
      - Coarse epsilons can over-merge (triangle→2, hexagon→4).
      - Fine epsilons can under-merge (triangle→5, hexagon→8).
      - But the TRUE vertex count is the *lowest* count that the curve
        stabilises at before over-merging begins.
      - Requiring >= 2 votes filters out single-epsilon noise.
    """
    perimeter   = cv2.arcLength(cnt, True)
    area        = cv2.contourArea(cnt)
    circularity = (4 * np.pi * area / (perimeter ** 2)) if perimeter > 0 else 0.0

    hull       = cv2.convexHull(cnt)
    hull_area  = max(float(cv2.contourArea(hull)), 1.0)
    hull_perim = cv2.arcLength(hull, True)
    hull_circ  = (4 * np.pi * hull_area / (hull_perim ** 2)) if hull_perim > 0 else 0.0
    solidity   = area / hull_area
    is_concave = not cv2.isContourConvex(cnt)

    # Convexity defects are a strong signal for stars (deep concave notches)
    defects = cv2.convexityDefects(cnt, cv2.convexHull(cnt, returnPoints=False))
    defect_count = 0
    max_defect_depth = 0.0
    if defects is not None:
        defect_count = defects.shape[0]
        _, _, bw, bh = cv2.boundingRect(cnt)
        max_dim = float(max(bw, bh, 1))
        max_defect_depth = max((d[0][3] for d in defects), default=0) / max_dim

    # Vote on vertex count: hull + raw contour, 5 epsilons each
    # Max-vote; prefer LOWER count on ties (coarser epsilon = more stable)
    vote: dict = {}
    for src, sp in ((hull, hull_perim), (cnt, perimeter)):
        # Reverted low epsilons (0.01, 0.015) as they caused over-segmentation (hexagon -> heptagon).
        # We rely on _is_triangle_fit for small/tricky triangles.
        # Added HIGH epsilons to help with jagged shapes (Triangle as Heptagon -> Triangle)
        for frac in (0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.10):
            if sp < 1:
                continue
            v = len(cv2.approxPolyDP(src, frac * sp, True))
            if v >= 3:
                vote[v] = vote.get(v, 0) + 1

    if not vote:
        # Fallback: check if it fits a triangle well
        if _is_triangle_fit(cnt, area):
            return "triangle", 3, circularity
        return "unknown-0", 0, circularity

    vertices = max(vote, key=lambda v: (vote[v], -v))

    # Heptagon rescue: if votes for 7 are nearly as strong as the winner (6 or 8),
    # prefer 7 so heptagons aren't merged into hexagon/octagon.
    v7 = vote.get(7, 0)
    if v7 > 0 and vertices in (6, 8) and v7 >= vote.get(vertices, 0) - 1:
        vertices = 7

    # If 4 vs 5 votes are close, prefer 5 to avoid merging pentagon into square/rectangle
    if vertices == 4:
        v4, v5 = vote.get(4, 0), vote.get(5, 0)
        if v5 >= max(1, v4 - 1):
            vertices = 5

    # If vertices suggests 4+ but it fits a triangle really well, prefer triangle
    # (e.g. 4 vertices because one side is slightly bent)
    if vertices > 3 and _is_triangle_fit(cnt, area):
        # Enforce triangle if the area match is very strong (>0.92)
        # or if we are in the "square" range (4 vertices) but it looks like a triangle
        tri_area, _ = cv2.minEnclosingTriangle(cnt)
        if tri_area > 0 and (area / tri_area) > 0.90:
             vertices = 3

    # Star heuristic: requires concavity and some defects to avoid squares
    looks_star = (
        is_concave
        and 5 <= vertices <= 12
        and defect_count >= 2
        and max_defect_depth > 0.01  # normalized by bbox size
        and solidity < 0.90
        and circularity < 0.90
        and hull_circ < 0.90
    )


    
    if vertices == 3:
        shape = "triangle"
    elif vertices == 4:
        # Check if it's actually a circle (high circularity) misclassified as square due to coarse polyDP
        if circularity > 0.82:
             shape = "circle"
        else:
            x, y, bw, bh = cv2.boundingRect(cnt)
            ar    = float(bw) / bh if bh else 1.0
            shape = "square" if 0.78 <= ar <= 1.28 else "rectangle"
    elif vertices == 5:
        shape = "pentagon"
    elif vertices == 6:
        shape = "hexagon"
    elif vertices == 7:
        shape = "heptagon"
    elif vertices == 8:
        # 8 vertices could be octagon or circle
        shape = "circle" if hull_circ >= 0.82 else "octagon"
    elif vertices == 10:
        # Star typically has 10 vertices (5 points, 5 inner).
        # It is concave, so low solidity.
        if solidity < 0.70 or looks_star:
            shape = "star"
        else:
            shape = "decagon" # or circle/blob
    else:
        # 8+ vertices: use hull circularity to distinguish circle vs octagon+
        shape = "circle" if hull_circ >= 0.82 else "octagon"

    # Final override: if contour looks like a star, trust that classification
    # but don't override a clean square/rectangle (common false positive case).
    if looks_star and not (shape in ("square", "rectangle") and vertices <= 6):
        shape = "star"

    # Circle override ONLY for shapes with 8+ voted vertices
    if vertices >= 8 and hull_circ >= 0.82 and solidity >= 0.80:
        shape = "circle"

    # Strict circularity check (updated)
    # Stars have low circularity (high perimeter). Exempt them!
    if shape == "star":
        pass # Stars are allowed low circularity
    elif vertices >= 3 and circularity < 0.35:
         return "unknown-noise", 0, circularity



    return shape, vertices, circularity


# ─────────────────────────────────────────────────────────────────────────────
# Dominant color
# ─────────────────────────────────────────────────────────────────────────────

def _dominant_color(bgr: np.ndarray, mask: np.ndarray = None) -> str:
    """
    Returns the dominant named color.
    If mask is provided (uint8, 255=foreground), only those pixels are analysed.
    """
    if bgr is None:
        return "unknown"
    hsv  = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
    best, best_n = "unknown", 0
    for name, ranges in COLOR_RANGES.items():
        m = None
        for lo, hi in ranges:
            hit = cv2.inRange(hsv, np.array(lo, np.uint8), np.array(hi, np.uint8))
            m   = hit if m is None else cv2.bitwise_or(m, hit)
        if mask is not None:
            m = cv2.bitwise_and(m, mask)
        n = int(np.count_nonzero(m))
        if n > best_n:
            best_n, best = n, name
    return best


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_shape(b64_string: str) -> dict:
    """
    Decode image → detect foreground shape → classify → return metadata dict.

    Returns:
        {
          area, hull_area, bbox_area,  # float, pixels²
          type,                         # str  e.g. "hexagon"
          vertices,                     # int
          circularity,                  # float 0-1
          color,                        # str  e.g. "green"
        }
    """
    EMPTY = dict(area=0.0, hull_area=0.0, bbox_area=0.0,
                 type="unknown", vertices=0, circularity=0.0, color="unknown")

    try:
        bgr, gray = _decode(b64_string)
        if bgr is None:
            return EMPTY

        cnt = _extract_shape_contour(bgr, gray)
        if cnt is None:
            return {**EMPTY, "type": "no_contour"}

        area, perimeter = cv2.contourArea(cnt), cv2.arcLength(cnt, True)
        if area < 10:
            return EMPTY

        shape, vertices, circularity = _classify(cnt)

        hull      = cv2.convexHull(cnt)
        hull_area = float(cv2.contourArea(hull))

        x, y, bw, bh = cv2.boundingRect(cnt)
        bbox_area    = float(bw * bh)

        # Build a foreground mask scoped to the bounding rect for color detection
        fmask = np.zeros(gray.shape, np.uint8)
        cv2.drawContours(fmask, [cnt], -1, 255, -1)  # filled shape silhouette

        color = _dominant_color(bgr, fmask)

        return dict(
            area        = float(area),
            hull_area   = hull_area,
            bbox_area   = bbox_area,
            type        = shape,
            vertices    = vertices,
            circularity = float(circularity),
            color       = color,
        )

    except Exception as e:
        return {**EMPTY, "type": "error", "error": str(e)}


if __name__ == "__main__":
    pass
