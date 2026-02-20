from flask import Flask, jsonify, request, render_template, make_response, redirect, url_for
import pow_client
import keys_manager
import sys
import io
import contextlib
import time
import os
import random

app = Flask(__name__)

# Security: Set this via environment variable in production
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change-me-immediately")

def get_request_hwid():
    """Derive a simple HWID from request headers and IP."""
    raw = f"{request.remote_addr}|{request.headers.get('User-Agent', 'unknown')}"
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def require_key(f):
    """Decorator to require a valid API key."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.cookies.get('api_key') or request.headers.get('X-API-Key') or request.args.get('key')
        
        if not api_key:
            return jsonify({"success": False, "error": "API key required. Please enter your key in the UI or provide it in headers/cookies/params."}), 401
        
        hwid = request.headers.get('X-HWID') or get_request_hwid()
        is_valid, msg, key_type = keys_manager.validate_key(api_key, hwid)
        
        if not is_valid:
            return jsonify({"success": False, "error": msg}), 403
        
        # Inject key info into request context for use in the route
        request.key_type = key_type
        request.api_key = api_key
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """
    Root endpoint that renders the web interface.
    """
    api_key = request.cookies.get('api_key')
    return render_template('index.html', api_key=api_key)

@app.route('/solve', methods=['GET', 'POST'])
@require_key
def solve():
    """
    Endpoint to solve a captcha. 
    Free users experience a 3-4s delay.
    """
    # Artificial delay for free keys
    if request.key_type == "free":
        delay = random.uniform(3.0, 4.0)
        time.sleep(delay)

    fingerprint = None
    if request.is_json:
        fingerprint = request.json.get('fingerprint')
    if not fingerprint:
        fingerprint = request.args.get('fingerprint')

    start_time = time.perf_counter()
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            token = pow_client.solve_captcha(fingerprint=fingerprint)
    except Exception as e:
        duration = time.perf_counter() - start_time
        return jsonify({
            "success": False,
            "error": str(e),
            "timetaken": f"{duration:.3f}s",
            "tier": request.key_type
        }), 500

    duration = time.perf_counter() - start_time
    
    if token:
        return jsonify({
            "success": True,
            "token": token,
            "timetaken": f"{duration:.3f}s",
            "tier": request.key_type
        })
    else:
        return jsonify({
            "success": False,
            "error": "Failed to solve captcha",
            "timetaken": f"{duration:.3f}s",
            "tier": request.key_type,
            "logs": buf.getvalue()
        }), 400

# --- Admin Routes ---

@app.route('/admin/keys', methods=['GET'])
def list_keys():
    secret = request.headers.get('Admin-Secret')
    if secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    return jsonify(keys_manager.get_all_keys())

@app.route('/admin/keys/create', methods=['POST'])
def create_key_route():
    secret = request.headers.get('Admin-Secret')
    if secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    data = request.json or {}
    key_type = data.get('type', 'free')
    expires_in = data.get('expires_in') # seconds
    
    new_key = keys_manager.create_key(key_type, expires_in)
    return jsonify({"success": True, "key": new_key, "type": key_type})

@app.route('/admin/keys/delete', methods=['DELETE'])
def delete_key_route():
    secret = request.headers.get('Admin-Secret')
    if secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    data = request.json or {}
    key = data.get('key')
    if not key:
        return jsonify({"success": False, "error": "Key required"}), 400
    
    success = keys_manager.delete_key(key)
    return jsonify({"success": success})

@app.route('/validate', methods=['GET'])
def validate():
    """
    Endpoint for the UI to check the status of the current API key.
    """
    api_key = request.cookies.get('api_key') or request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({"success": False, "error": "No key found"}), 401
    
    hwid = request.headers.get('X-HWID') or get_request_hwid()
    is_valid, msg, key_type = keys_manager.validate_key(api_key, hwid)
    
    keys = keys_manager.get_all_keys()
    key_info = keys.get(api_key, {})
    
    return jsonify({
        "success": is_valid,
        "message": msg,
        "type": key_type,
        "hwid_locked": key_info.get("hwid") is not None,
        "uses": key_info.get("uses", 0)
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
