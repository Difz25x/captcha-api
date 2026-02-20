from flask import Flask, jsonify, request
import pow_client
import sys
import io
import contextlib
import time

app = Flask(__name__)

@app.route('/')
def index():
    """
    Root endpoint that lists all available routes and their methods.
    """
    routes = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            routes.append({
                "endpoint": rule.rule,
                "methods": list(rule.methods - {"OPTIONS", "HEAD"}),
                "description": app.view_functions[rule.endpoint].__doc__.strip() if app.view_functions[rule.endpoint].__doc__ else ""
            })
    return jsonify({
        "message": "Welcome to Gateway Captcha API",
        "endpoints": routes
    })

@app.route('/solve', methods=['GET', 'POST'])
def solve():
    """
    Endpoint to solve a captcha and return the token.
    Accepts optional fingerprint in JSON body or query params.
    """
    fingerprint = None
    if request.is_json:
        fingerprint = request.json.get('fingerprint')
    if not fingerprint:
        fingerprint = request.args.get('fingerprint')

    # Start timing
    start_time = time.perf_counter()
    
    # Capture stdout to avoid cluttering the flask log
    # while still allowing us to see what happened on failure
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
            "logs": buf.getvalue()
        }), 500

    duration = time.perf_counter() - start_time
    
    if token:
        return jsonify({
            "success": True,
            "token": token,
            "timetaken": f"{duration:.3f}s"
        })
    else:
        return jsonify({
            "success": False,
            "error": "Failed to solve captcha",
            "timetaken": f"{duration:.3f}s",
            "logs": buf.getvalue()
        }), 400

@app.route('/health', methods=['GET'])
def health():
    """
    Simple health check endpoint.
    """
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    # You can change host/port as needed
    app.run(host='0.0.0.0', port=5000, debug=True)
