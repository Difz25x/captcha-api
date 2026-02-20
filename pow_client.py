"""
pow_client.py  —  platorelay PoW multi-stage shape captcha solver

Env vars:
  WAIT_MS=3000        ms before verify (default 3000)
  COLLECT_DATASET=1   save labeled images
  DUMP_REQUEST=1      print full /request response JSON
"""

import json
import math
import os
import random
import time
import urllib.error
import urllib.request
import http.cookiejar
from typing import Any, Dict, List

REQUEST_URL = "https://sentry.platorelay.com/.gs/pow/captcha/request"
VERIFY_URL  = "https://sentry.platorelay.com/.gs/pow/captcha/verify"

try:
    import visual_verification
except ImportError:
    visual_verification = None

BASE_HEADERS = {
    "Accept":             "*/*",
    "Accept-Encoding":    "gzip, deflate, br, zstd",
    "Accept-Language":    "en-US,en;q=0.9",
    "Connection":         "keep-alive",
    "Content-Type":       "application/json",
    "Host":               "sentry.platorelay.com",
    "Origin":             "https://sentry.platorelay.com",
    "Referer":            "https://sentry.platorelay.com/a?d=WCSs0mZ72PLex3emy4RWALM8b5w3gxOwOtX4PWD8f2osTC329aqP9xCminMsCjqMz2sGiYob79QN2lz0RZhTsUSgX5b0iHW0Dj6G40kzui6e6kTDc54UvkprZyx1H2DBce5kM7fAqkrho0haQ4qAIeNYVE5sPwN0twGmVDJYJJoaSadETOkVQ86QM66sgnX8FjQCIFalKd9utvSfL3Bgm4ZV5EO3m66FwYZXVjuh715Yz2OEgSchlJXtiQhGWVpXSM0qabtFhbyndi6rrMqhqjZ3FG5EHGuyTlw8BLwYW6wmm5iPM9qqiFPlzlNsxhTiEkst3YZ8Dfoi4kpxiY9fKxPvxvAh2vWc17K8EAgQHHOU8Qi5gjIc8hfpEkY9EPy2EEjKrvnafd12uRXazvUQr561SoxC2hiSOfeVivapekEvnKuWttEE5eikwVLlyxKu9YcUvTd5zDI623sqLjDnBBkweChPVJ3Z19MjMSWUp37joQLntVbqfUQiu0DbPp2ZRTHCEjDP2h2FCHAbWu8xaV0pNJUITQQ4sjpVsTafOhz3TpEYcX8mjoQHIqHkDaO3Wiei1qMJQE7YPkPs7cwjCxKQtCp2Z0HPBFuxiyVjHwkgosdRyGyWNoMfRxImKFqw0pyP1ltXl2Swkdq8De7yPqiqYylMROiyQgAPDVo8mB4VOEX0qWTQvosGNlRIOnweHxUmAyR1jqdjNqF1aZuI67ltiN99iofLo6oJdT8PnWqAXuziM2yw02MQPJ41kg7KpdJ1njL6nfEAqIm0eOZl2ZbTXt40NVhDbNPUbxh2EcuIkisJXJ8ePEoBKZeRRiWgX8GrEVS53zrhyuf2uHsPpUGDPEm5OyjY4rSHHpbi9oplgyTrIJimKUrXESmdNNRaJ2FvILuxu2sEvAEBX8XuatOkykdx0RckHCLxSkbb0PwEdkvCjAsfqHupdpPwmGzdltZt7qpLwZb97MRq36gdHaFUF4UscNKEzyzt3H3c13bKS5O8E798T1ne5JuZaMixCHT43YulPptmsUwvlgMZnQu3b8Zyb1qcxwelC3wI2MY5fifrY8ij6C5GiYgeUKc53YF",
    "sec-ch-ua":          '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
    "sec-ch-ua-mobile":   "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest":     "empty",
    "Sec-Fetch-Mode":     "cors",
    "Sec-Fetch-Site":     "same-origin",
    "User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
}

SHAPE_KEYWORDS = ["circle", "square", "triangle", "rectangle",
                  "hexagon", "pentagon", "heptagon", "polygon",
                  "star"]  # add star so instructions like "tap the star" are parsed
COLOR_KEYWORDS = ["red", "orange", "yellow", "green", "blue",
                  "purple", "white", "black", "gray"]
_POLY_ORDER    = ["triangle", "square", "rectangle", "pentagon", "hexagon", "heptagon"]


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry / fingerprint generation
# ─────────────────────────────────────────────────────────────────────────────

def _gen_fingerprint() -> str:
    """
    Generate a fingerprint string matching the observed format: '-XXXXXXXX'
    (minus sign + 8 hex chars representing a signed 32-bit int).
    """
    val = random.randint(-0x7FFFFFFF, 0x7FFFFFFF)
    if val >= 0:
        return f"{val:08x}"
    else:
        # Represent as negative hex like '-419fd23c'
        return f"-{(-val):08x}"


def _gen_telemetry(dwell_ms: float, moves: int = None) -> dict:
    """
    Generate realistic mouse-movement telemetry.
    moveDensity = dwellMs / moves  (confirmed from real payloads)
    """
    if moves is None:
        moves = random.randint(180, 320)

    speed_min    = round(random.uniform(0.0005, 0.005), 15)
    speed_max    = round(random.uniform(8.0, 16.0), 15)
    speed_median = round(random.uniform(0.15, 0.65), 15)
    speed_avg    = round(random.uniform(0.45, 1.30), 15)
    speed_p25    = round(random.uniform(0.05, 0.20), 15)
    speed_p75    = round(random.uniform(0.55, 1.55), 15)
    vel_var      = round(random.uniform(1.0, 5.0), 15)
    dir_changes  = random.randint(0, 5)
    # CORRECT formula: dwellMs / moves (ms per move)
    move_density = dwell_ms / moves if moves > 0 else 0

    return {
        "dwellMs":          round(dwell_ms, 1),
        "moves":            moves,
        "velocityVar":      vel_var,
        "velocityMedian":   speed_median,
        "velocityAvg":      speed_avg,
        "velocityMin":      speed_min,
        "velocityMax":      speed_max,
        "velocityP25":      speed_p25,
        "velocityP75":      speed_p75,
        "directionChanges": dir_changes,
        "keypresses":       0,
        "speedSamples":     moves,
        "moveDensity":      move_density,
    }


def _gen_path(dwell_ms: float) -> dict:
    """
    Generate click path matching real verify payload:
    - moves=1, totalDist=0, avgSpeed=0 (single click, no drag)
    - clickTimestamp ≈ dwellMs (click happens at end of dwell)
    """
    click_ts = round(dwell_ms - random.uniform(2, 10), 1)

    return {
        "moves":            1,
        "totalDist":        0,
        "durationMs":       round(random.uniform(60, 120), 1),
        "avgSpeed":         0,
        "clickTimestamp":   click_ts,
        "timeToFirstClick": click_ts,
    }


def _gen_verify_meta(num_stages: int) -> tuple:
    """
    Returns (path, telemetry, fingerprint).
    Verify dwell = time spent solving all stages (~20-70s total).
    """
    base_dwell  = random.uniform(15000, 25000)
    extra_dwell = (num_stages - 1) * random.uniform(8000, 15000)
    dwell_ms    = base_dwell + extra_dwell

    # Verify moves: more samples since user solved multiple stages
    moves    = random.randint(200, 280)
    path     = _gen_path(dwell_ms)
    telemetry = _gen_telemetry(dwell_ms, moves)

    return path, telemetry


def _gen_request_telemetry() -> dict:
    """
    Pre-puzzle telemetry for /request — short dwell (2-5s), fewer moves.
    Matches real example: dwellMs=3086, moves=60, moveDensity=51.43
    """
    dwell_ms = random.uniform(2000, 6000)
    moves    = random.randint(40, 90)
    return _gen_telemetry(dwell_ms, moves)


# ─────────────────────────────────────────────────────────────────────────────
# Network
# ─────────────────────────────────────────────────────────────────────────────

def load_json(path: str, fallback: dict):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return fallback


def send(opener, url: str, payload: dict, headers: dict):
    body = json.dumps(payload, separators=(",", ":")).encode()
    h    = {**headers, "Content-Length": str(len(body))}
    req  = urllib.request.Request(url, data=body, headers=h, method="POST")
    with opener.open(req, timeout=30) as resp:
        raw = resp.read()
        try:
            p = json.loads(raw)
            return resp.status, resp.reason, json.dumps(p, indent=2), p
        except Exception:
            return resp.status, resp.reason, raw.decode("utf-8", errors="replace"), None


def _scrub(obj):
    if isinstance(obj, dict):
        return {k: ("<base64>" if isinstance(v, str) and len(v) > 100 and k == "img"
                    else _scrub(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(i) for i in obj]
    return obj


# ─────────────────────────────────────────────────────────────────────────────
# Instruction parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_instruction(instruction: str):
    instr        = instruction.lower()
    target_type  = next((k for k in SHAPE_KEYWORDS if k in instr), None)
    target_color = next((k for k in COLOR_KEYWORDS  if k in instr), None)
    want_smallest = any(w in instr for w in ("smallest", "tiny", "minimum"))
    want_largest  = any(w in instr for w in ("largest", "biggest", "maximum"))
    if not want_smallest and not want_largest:
        want_largest = True
    return target_type, target_color, want_smallest, want_largest


def _json_area(s: Dict[str, Any]) -> float:
    for k in ("area", "size"):
        v = s.get(k)
        if isinstance(v, (int, float)):
            return float(v)
    w, h = s.get("width"), s.get("height")
    if isinstance(w, (int, float)) and isinstance(h, (int, float)):
        return float(w) * float(h)
    r = s.get("radius")
    if isinstance(r, (int, float)):
        return 3.14159 * r ** 2
    return 0.0


def _is_ambiguous(t: str) -> bool:
    return not t or t in ("unknown", "error", "no_contour") or t.startswith("unknown-")


def _type_matches_strict(detected: str, target: str) -> bool:
    if _is_ambiguous(detected):
        return False
    if target == "circle":
        return "circle" in detected
    if target in detected:
        return True
    try:
        return abs(_POLY_ORDER.index(target) - _POLY_ORDER.index(detected)) <= 1
    except ValueError:
        return False


def _type_confidence(detected: str, target: str) -> float:
    if not target:
        return 1.0
    if _is_ambiguous(detected):
        return 0.0
    if target == "circle" and "circle" in detected:
        return 1.0
    if target != "circle" and target in detected:
        return 1.0
    try:
        if abs(_POLY_ORDER.index(target) - _POLY_ORDER.index(detected)) == 1:
            return 0.7
    except ValueError:
        pass
    return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Stage solver
# ─────────────────────────────────────────────────────────────────────────────

def solve_stage(stage: Dict[str, Any], stage_idx: int) -> str:
    instruction = stage.get("instruction") or ""
    shapes: List[Dict[str, Any]] = stage.get("shapes") or []

    target_type, target_color, want_smallest, _ = _parse_instruction(instruction)
    want_largest = not want_smallest

    print(f"\n  [Stage {stage_idx}] \"{instruction}\"")
    print(f"  target_type={target_type!r}  target_color={target_color!r}  "
          f"shapes={len(shapes)}  want_smallest={want_smallest}")

    if not shapes:
        print("  WARNING: no shapes"); return "0"
    if not visual_verification:
        print("  WARNING: no visual_verification module"); return "0"

    os.makedirs("debug_captchas", exist_ok=True)

    for idx, s in enumerate(shapes):
        b64 = s.get("img")
        if not b64:
            s["visual"] = dict(area=0.0, type="unknown", vertices=0,
                               circularity=0.0, color="unknown", hull_area=0.0)
            continue

        vis = visual_verification.analyze_shape(b64)
        # Fallback: if detection failed, carry over JSON-provided area/type so sorting still works
        if vis.get("area", 0) <= 0 or vis.get("type") in ("unknown", "error", "no_contour"):
            vis["area"]  = _json_area(s)
            vis["type"]  = s.get("type", vis.get("type", "unknown"))
            vis["color"] = s.get("color", vis.get("color", "unknown"))
        s["visual"] = vis

        if os.environ.get("COLLECT_DATASET"):
            visual_verification.save_to_dataset(b64, vis, instruction)

    # Only save images if explicitly requested via env var
    if os.environ.get("DEBUG_SAVE") == "1":
        os.makedirs("debug_captchas", exist_ok=True)
        try:
            import base64 as _b64
            raw      = b64.split(",")[1] if "," in b64 else b64
            decoded  = _b64.b64decode(raw)
            # flat dump for quick debugging
            with open(f"debug_captchas/s{stage_idx}_i{idx}_{vis['type']}.png", "wb") as f:
                f.write(decoded)
            # organized dump per detected shape to make dataset curation easier
            shape_dir = os.path.join("debug_captchas_by_shape", vis.get("type", "unknown"))
            os.makedirs(shape_dir, exist_ok=True)
            fname = f"s{stage_idx}_i{idx}_{vis.get('color','unknown')}.png"
            with open(os.path.join(shape_dir, fname), "wb") as f:
                f.write(decoded)
        except Exception:
            pass

        passes = _type_matches_strict(vis['type'], target_type) if target_type else True
        mark   = "OK" if passes else "NO"
        print(f"    [{idx}] {vis['type']:<12} {vis.get('color','?'):<8} "
              f"area={vis['area']:>7.0f}  hull={vis.get('hull_area',0):>7.0f}  "
              f"v={vis['vertices']}  c={vis.get('circularity',0):.2f}  {mark}")

    # Filter
    if target_type:
        candidates = [s for s in shapes
                      if _type_matches_strict(s.get("visual", {}).get("type", ""), target_type)]
    else:
        candidates = list(shapes)

    if target_color and candidates:
        cc = [s for s in candidates
              if s.get("visual", {}).get("color", "unknown") in ("unknown", target_color)]
        if cc:
            candidates = cc
        else:
            print(f"  [Filter] No color={target_color!r} — dropping color filter")

    if not candidates:
        print(f"  [Filter] No strict match — using all shapes")
        candidates = list(shapes)

    print(f"  [Filter] {len(candidates)}/{len(shapes)} candidates")

    # Filter out invalid shapes (no_contour, error, noise, area=0)
    # This acts as a safety net so we don't pick empty images or dust.
    def is_valid_shape(c):
        vt = c.get("visual", {}).get("type", "")
        va = c.get("visual", {}).get("area", 0)
        vv = c.get("visual", {}).get("vertices", 0)
        if vt in ("no_contour", "error", "unknown-noise"):
            return False
        if va <= 0 and _json_area(c) <= 0:
            return False
        if va < 800 and vv <= 2:
            return False  # speck / dust
        return True

    if target_type:
        filtered = [c for c in candidates if is_valid_shape(c)]
    else:
        # Size-only tasks: prefer valid shapes, but if none, fall back to all candidates.
        filtered = [c for c in candidates if is_valid_shape(c) and c.get("visual", {}).get("type", "") != "unknown"]
        if not filtered:
            filtered = [c for c in candidates if is_valid_shape(c)]

    if filtered:
        candidates = filtered
    else:
        print("  [Filter] All candidates filtered as invalid! Reverting to original set.")

    def _effective_area(s):
        vis = s.get("visual", {})
        # use hull_area > bbox_area > area > json_area
        for k in ("hull_area", "bbox_area", "area"):
            v = vis.get(k)
            if isinstance(v, (int, float)) and v > 0:
                return float(v)
        ja = _json_area(s)
        return float(ja) if ja > 0 else 0.0

    def _conf(s):
        return _type_confidence(s.get("visual", {}).get("type", ""), target_type)

    if target_type:
        # 1) If any exact/very-high confidence matches exist, pick among them by area.
        exact = [c for c in candidates if _conf(c) >= 0.99]
        pool  = exact if exact else candidates
        if exact:
            pool.sort(key=lambda s: _effective_area(s), reverse=not want_smallest)
            chosen = pool[0]
        else:
            # 2) Otherwise use near-best confidence window (0.30) then area.
            max_conf = max(_conf(c) for c in candidates) if candidates else 0
            near_best = [c for c in candidates if _conf(c) >= max_conf - 0.30]
            pool = near_best if near_best else candidates
            pool.sort(key=lambda s: _effective_area(s), reverse=not want_smallest)
            chosen = pool[0]
    else:
        # Size-only tasks: ignore confidence
        candidates.sort(key=lambda s: _effective_area(s), reverse=not want_smallest)
        chosen     = candidates[0]

    chosen_idx = shapes.index(chosen)
    v          = chosen.get("visual", {})

    print(f"  -> Answer index: {chosen_idx}  "
          f"type={v.get('type','?')}  color={v.get('color','?')}  "
          f"area={v.get('area',0):.0f}  "
          f"conf={_type_confidence(v.get('type',''), target_type):.2f}")

    return str(chosen_idx)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def solve_captcha(opener=None, fingerprint=None) -> str:
    """
    Solve a PoW puzzle and return the resulting token on success.
    Returns None if it fails.
    """
    if opener is None:
        import http.cookiejar as _hcj
        cj     = _hcj.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # ── Fingerprint generation/reuse ─────────────────────────────────────────
    if fingerprint is None:
        saved_fp   = load_json("payload_verify.json", {}).get("deviceFingerprint", "")
        fingerprint = saved_fp if saved_fp else _gen_fingerprint()
    
    print(f"[+] deviceFingerprint: {fingerprint}")

    # ── 1. Request ───────────────────────────────────────────────────────────
    req_pl = {
        "telemetry":       _gen_request_telemetry(),
        "deviceFingerprint": fingerprint,
        "forcePuzzle":     False,
    }

    try:
        status, reason, body, parsed = send(opener, REQUEST_URL, req_pl, BASE_HEADERS)
        print(f"REQUEST -> {status} {reason}")
    except urllib.error.HTTPError as e:
        print(f"REQUEST HTTP {e.code}: {e.reason}")
        print(e.read().decode("utf-8", errors="replace")); return None
    except Exception:
        import traceback; traceback.print_exc(); return None

    if os.environ.get("DUMP_REQUEST"):
        print(json.dumps(_scrub(parsed), indent=2) if parsed else body)

    if not parsed or not parsed.get("success"):
        print("Request failed:\n", body); return None

    data      = parsed.get("data", {})
    puzzle_id = data.get("id")
    if not puzzle_id:
        print("ERROR: no id in response"); return None

    print(f"[+] id:    {puzzle_id}")
    print(f"[+] mode:  {data.get('mode')}")

    # ── 2. Collect stages ────────────────────────────────────────────────────
    stages: List[Dict[str, Any]] = data.get("stages") or []
    if not stages:
        puzzle = data.get("puzzle")
        if puzzle:
            stages = [puzzle]
    if not stages:
        print("ERROR: no stages in response"); return None

    print(f"[+] Stages: {len(stages)}")
    for i, st in enumerate(stages):
        print(f"    Stage {i}: \"{st.get('instruction')}\"  "
              f"({len(st.get('shapes') or [])} shapes)")

    # ── 3. Solve ─────────────────────────────────────────────────────────────
    answers: List[str] = []
    for i, stage in enumerate(stages):
        answers.append(solve_stage(stage, i))

    print(f"\n[+] Answers: {answers}")

    # ── 4. Build verify payload — same fingerprint as /request ───────────────
    path, telemetry = _gen_verify_meta(len(stages))

    ver_pl = {
        "id":                puzzle_id,
        "answers":           answers,
        "path":              path,
        "telemetry":         telemetry,
        "deviceFingerprint": fingerprint,   # ← same as /request
    }

    print(f"\n[Telemetry] dwellMs={telemetry['dwellMs']}  "
          f"moves={telemetry['moves']}  "
          f"velocityAvg={telemetry['velocityAvg']:.4f}  "
          f"moveDensity={telemetry['moveDensity']:.4f}")
    print(f"[Path]      clickTimestamp={path['clickTimestamp']}  "
          f"durationMs={path['durationMs']}  "
          f"totalDist={path['totalDist']}")

    wait_ms = float(os.environ.get("WAIT_MS", "1500"))
    if wait_ms > 0:
        print(f"\nWaiting {int(wait_ms)} ms ...")
        time.sleep(wait_ms / 1000.0)

    print(f"\n[PAYLOAD] {json.dumps(ver_pl, separators=(',',':'))}")

    # ── 5. Verify ────────────────────────────────────────────────────────────
    try:
        status, reason, body, pv = send(opener, VERIFY_URL, ver_pl, BASE_HEADERS)
        print(f"\nVERIFY -> {status} {reason}")
        print(body)
        if pv and pv.get("success") is True:
            print("\nOK  CAPTCHA SOLVED!")
            token = pv.get("data", {}).get("token")
            return token
        else:
            print("\nNO  Wrong. Check debug_captchas/ PNGs.")
            token = (pv or {}).get("token") or (pv or {}).get("data", {}).get("token")
            if token:
                print(f"   Token: {token}")
                return token
            return None
    except urllib.error.HTTPError as e:
        print(f"\nVERIFY HTTP {e.code}: {e.reason}")
        print(e.read().decode("utf-8", errors="replace"))
        return None
    except Exception:
        import traceback; traceback.print_exc()
        return None


def main():
    token = solve_captcha()
    if token:
        print(f"\n[SUCCESS] Token: {token}")
    else:
        print("\n[FAILURE] Failed to solve captcha.")


if __name__ == "__main__":
    import sys
    import os
    
    # Tee stdout to file for debugging
    class Tee(object):
        def __init__(self, name, mode):
            self.file = open(name, mode, encoding='utf-8')
            self.stdout = sys.stdout
        def write(self, data):
            # Handle potential bytes
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='replace')
            self.file.write(data)
            self.stdout.write(data)
            self.file.flush()
            self.stdout.flush()
        def flush(self):
            self.file.flush()
            self.stdout.flush()
            
    sys.stdout = Tee("run.log", "w")
    
    # Force unbuffered stdout
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

    main()
