from pathlib import Path

p = Path("app/app.py")
s = p.read_text(encoding="utf-8")

if 'def _hosted_status():' not in s:
    raise SystemExit("STOP: hosted status function not found.")
if '@app.route("/api/v1/sensor/events", methods=["POST"])' not in s:
    raise SystemExit("STOP: sensor events route not found.")
if '@app.route("/api/v2/alerts", methods=["GET"])' not in s:
    raise SystemExit("STOP: alerts route not found.")
if 'def _receive_sensor_metrics' in s:
    raise SystemExit("Metrics receiver already exists; no changes made.")

# Insert a small, in-memory snapshot store before hosted status.
anchor = 'def _hosted_status():'
insert = '''# Latest authenticated local-sensor snapshot; deliberately not persisted.
_sensor_metrics_lock = threading.Lock()
_latest_sensor_metrics = None
_latest_sensor_metrics_received_at = 0.0
_SENSOR_METRICS_MAX_AGE_SECONDS = 20

def _hosted_status_with_sensor_metrics():
    result = _hosted_status()
    with _sensor_metrics_lock:
        snapshot = _latest_sensor_metrics
        received_at = _latest_sensor_metrics_received_at

    age = time.time() - received_at if received_at else None
    if snapshot is None or age is None or age > _SENSOR_METRICS_MAX_AGE_SECONDS:
        result["sensor_online"] = False
        result["sensor_metrics_age_seconds"] = None if age is None else round(age, 1)
        return result

    result.update(snapshot)
    result["runtime_role"] = "hosted_web"
    result["capture_available"] = False
    result["local_metrics_available"] = True
    result["sensor_online"] = True
    result["sensor_metrics_age_seconds"] = round(age, 1)
    return result


'''
s = s.replace(anchor, insert + anchor, 1)

# Let the global Basic-auth middleware pass the dedicated bearer-auth route.
old = 'if request.path in {"/healthz", "/readyz", "/api/v1/sensor/events"} or request.path.startswith("/static/"):'
new = 'if request.path in {"/healthz", "/readyz", "/api/v1/sensor/events", "/api/v1/sensor/metrics"} or request.path.startswith("/static/"):'
if old not in s:
    raise SystemExit("STOP: authentication exemption marker not found.")
s = s.replace(old, new, 1)

# Insert the new route immediately before the dashboard alerts route.
anchor = '@app.route("/api/v2/alerts", methods=["GET"])'
route = '''@app.route("/api/v1/sensor/metrics", methods=["POST"])
def _receive_sensor_metrics():
    """Receive a bounded, authenticated live status snapshot from the local sensor."""
    global _latest_sensor_metrics, _latest_sensor_metrics_received_at

    if RUNTIME_ROLE != "hosted_web":
        return jsonify({"error": "Metrics receiver is available only on the hosted service."}), 404

    configured_key = app.config["NETRA_SENSOR_API_KEY"]
    if not configured_key or len(configured_key) < 32:
        return jsonify({"error": "Sensor metrics are not configured."}), 503

    auth_header = request.headers.get("Authorization", "")
    scheme, separator, supplied_key = auth_header.partition(" ")
    if (not separator or scheme.lower() != "bearer"
            or not hmac.compare_digest(supplied_key.encode("utf-8"), configured_key.encode("utf-8"))):
        return jsonify({"error": "Authentication required."}), 401

    if _sensor_rate_limited(request.remote_addr):
        response = jsonify({"error": "Metrics rate limit exceeded."})
        response.headers["Retry-After"] = str(SENSOR_RATE_WINDOW_SECONDS)
        return response, 429

    if request.content_length is not None and request.content_length > 16384:
        return jsonify({"error": "Request body exceeds the configured limit."}), 413
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 415

    try:
        payload = request.get_json()
    except Exception:
        return jsonify({"error": "Malformed JSON request."}), 400

    if not isinstance(payload, dict) or set(payload) != {"status"} or not isinstance(payload["status"], dict):
        return jsonify({"error": "Request must contain only a status object."}), 400

    incoming = payload["status"]
    stats = incoming.get("stats")
    if not isinstance(stats, dict):
        return jsonify({"error": "Status must contain a stats object."}), 400

    numeric_fields = (
        "packets_processed", "ignored_packets", "active_flows", "completed_flows",
        "classified_flows", "simulated_flows", "benign_count", "attack_count",
        "attacks_flagged", "processing_errors", "capture_errors",
    )
    clean_stats = {}
    for name in numeric_fields:
        value = stats.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            return jsonify({"error": "Invalid numeric metric: " + name}), 400
        clean_stats[name] = min(int(value), 2**53 - 1)

    for name in ("last_packet_time", "last_inference_time"):
        value = stats.get(name)
        clean_stats[name] = value[:64] if isinstance(value, str) else None

    threat = stats.get("threat_level")
    clean_stats["threat_level"] = threat[:32] if isinstance(threat, str) else "UNAVAILABLE"

    running = incoming.get("is_running")
    model_available = incoming.get("model_available")
    if type(running) is not bool or type(model_available) is not bool:
        return jsonify({"error": "is_running and model_available must be booleans."}), 400

    mode = incoming.get("mode")
    interface = incoming.get("active_interface")
    snapshot = {
        "is_running": running,
        "stop_requested": incoming.get("stop_requested") is True,
        "mode": mode[:32] if isinstance(mode, str) else "unknown",
        "active_interface": interface[:128] if isinstance(interface, str) else "Local sensor",
        "model_available": model_available,
        "last_run_mode": None,
        "last_run_source": None,
        "last_run_status": "live",
        "error_message": None,
        "stats": clean_stats,
    }

    with _sensor_metrics_lock:
        _latest_sensor_metrics = snapshot
        _latest_sensor_metrics_received_at = time.time()

    return jsonify({"accepted": True}), 200


'''
if anchor not in s:
    raise SystemExit("STOP: alerts route insertion point not found.")
s = s.replace(anchor, route + anchor, 1)

# Make the hosted alerts response use fresh metrics when available.
old = '"status": _hosted_status(),'
if old not in s:
    raise SystemExit('STOP: hosted alerts status field marker not found.')
s = s.replace(old, '"status": _hosted_status_with_sensor_metrics(),', 1)

p.write_text(s, encoding="utf-8")
print("Patched app/app.py successfully.")
