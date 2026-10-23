import os
import sys
import hmac
import ipaddress
import logging
import threading
import time
import uuid
import atexit
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify

# Add project root to sys.path for v2 imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
except ImportError:
    pass

from v2.event_store import (
    EventValidationError, create_delivery_repository, create_event_repository, validate_event,
)

logger = logging.getLogger(__name__)
RUNTIME_ROLE = os.getenv("NETRA_RUNTIME_ROLE", "local_sensor").strip().lower()
if RUNTIME_ROLE not in {"local_sensor", "hosted_web"}:
    raise RuntimeError("NETRA_RUNTIME_ROLE must be 'local_sensor' or 'hosted_web'")

v2_engine = None
event_repository = None
delivery_repository = None
_forwarding_worker = None
_event_forwarder = None
model = None
MODEL_LOADED = False

if RUNTIME_ROLE == "local_sensor":
    # Detector imports load Scapy/model state and start sensor-side components.
    from v2.live_detector import engine as v2_engine
    from v2.attack_simulator import run_attack_simulation
    from v2.event_forwarder import EventForwarder, ForwardingWorker

    event_repository = v2_engine.event_writer.repository
    delivery_repository = v2_engine.critical_email_alerts.notifier.repository
else:
    if os.getenv("NETRA_EVENT_BACKEND", "").strip().lower() != "postgresql":
        raise RuntimeError("hosted_web requires NETRA_EVENT_BACKEND=postgresql; refusing local storage")
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("hosted_web requires DATABASE_URL; refusing local storage")
    from urllib.parse import urlsplit
    try:
        parsed_database_url = urlsplit(database_url)
        valid_database_url = (
            parsed_database_url.scheme in {"postgres", "postgresql"}
            and bool(parsed_database_url.hostname)
            and (parsed_database_url.port is None or 1 <= parsed_database_url.port <= 65535)
        )
    except ValueError:
        valid_database_url = False
    if not valid_database_url:
        raise RuntimeError("hosted_web DATABASE_URL must be a valid PostgreSQL URL")
    try:
        import psycopg  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("hosted_web requires the psycopg PostgreSQL driver") from exc
    event_repository = create_event_repository(backend="postgresql", database_url=database_url)
    if os.getenv("NETRA_DELIVERY_BACKEND", "").strip().lower() != "postgresql":
        raise RuntimeError("hosted_web requires NETRA_DELIVERY_BACKEND=postgresql; refusing local delivery storage")
    delivery_repository = create_delivery_repository(role=RUNTIME_ROLE, database_url=database_url)
MAX_SENSOR_REQUEST_BYTES = 256 * 1024
MAX_SENSOR_BATCH_EVENTS = 100
SENSOR_RATE_LIMIT = 60
SENSOR_RATE_WINDOW_SECONDS = 60
SENSOR_METADATA_FIELDS = {
    "flow_classification": frozenset({"packet_count", "byte_count", "protocol", "confidence_percent"}),
    "alert": frozenset({"packet_count", "byte_count", "protocol", "alert_source"}),
    "capture_error": frozenset({"phase", "error_type"}),
    "processing_error": frozenset({"phase", "error_type"}),
}
HISTORY_WINDOWS = {
    "1h": (timedelta(hours=1), 60),
    "6h": (timedelta(hours=6), 300),
    "24h": (timedelta(hours=24), 900),
    "7d": (timedelta(days=7), 3600),
    "30d": (timedelta(days=30), 3600),
}
HISTORY_ORIGINS = frozenset({"live", "pcap", "simulation", "all"})
_sensor_rate_lock = threading.Lock()
_sensor_rate_windows = {}


def _sensor_rate_limited(client_ip, now=None):
    """Bounded process-local limit; request-size and API-key checks also apply."""
    current = time.monotonic() if now is None else now
    key = client_ip or "unknown"
    with _sensor_rate_lock:
        for address, (window_start, _) in tuple(_sensor_rate_windows.items()):
            if current - window_start >= SENSOR_RATE_WINDOW_SECONDS:
                _sensor_rate_windows.pop(address, None)
        if len(_sensor_rate_windows) >= 2048 and key not in _sensor_rate_windows:
            oldest = min(_sensor_rate_windows, key=lambda address: _sensor_rate_windows[address][0])
            _sensor_rate_windows.pop(oldest, None)
        start, count = _sensor_rate_windows.get(key, (current, 0))
        if current - start >= SENSOR_RATE_WINDOW_SECONDS:
            start, count = current, 0
        if count >= SENSOR_RATE_LIMIT:
            return True
        _sensor_rate_windows[key] = (start, count + 1)
        return False


def _validate_sensor_event(event):
    record = validate_event(event)
    if record["session_id"] is not None:
        try:
            uuid.UUID(record["session_id"])
        except (ValueError, AttributeError) as exc:
            raise EventValidationError("session_id must be a UUID or null") from exc
    metadata = record["metadata"]
    allowed_metadata = SENSOR_METADATA_FIELDS[record["event_type"]]
    if not set(metadata).issubset(allowed_metadata):
        raise EventValidationError("metadata contains unsupported fields")
    for field in ("packet_count", "byte_count"):
        if field in metadata and (type(metadata[field]) is not int or metadata[field] < 0):
            raise EventValidationError(f"{field} must be a non-negative integer")
    if "protocol" in metadata and (
        not isinstance(metadata["protocol"], str) or len(metadata["protocol"]) > 32
    ):
        raise EventValidationError("protocol must be a short string")
    if "confidence_percent" in metadata and (
        isinstance(metadata["confidence_percent"], bool)
        or not isinstance(metadata["confidence_percent"], (int, float))
        or not 0 <= metadata["confidence_percent"] <= 100
    ):
        raise EventValidationError("confidence_percent must be between 0 and 100")
    for field in ("phase", "error_type", "alert_source"):
        if field in metadata and (
            not isinstance(metadata[field], str) or not metadata[field] or len(metadata[field]) > 64
        ):
            raise EventValidationError(f"{field} must be a short non-empty string")
    return record

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_SENSOR_REQUEST_BYTES
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or os.urandom(32)
app.config["DEBUG"] = RUNTIME_ROLE == "local_sensor"
app.config["NETRA_AUTH_USERNAME"] = os.getenv("NETRA_AUTH_USERNAME", "")
app.config["NETRA_AUTH_PASSWORD"] = os.getenv("NETRA_AUTH_PASSWORD", "")
app.config["NETRA_SENSOR_API_KEY"] = os.getenv("NETRA_SENSOR_API_KEY", "")
app.config["NETRA_RUNTIME_ROLE"] = RUNTIME_ROLE
app.config["EVENT_REPOSITORY"] = event_repository
app.config["DELIVERY_REPOSITORY"] = delivery_repository

if RUNTIME_ROLE == "hosted_web" and not (
    app.config["NETRA_AUTH_USERNAME"] and app.config["NETRA_AUTH_PASSWORD"]
):
    raise RuntimeError("hosted_web requires NETRA_AUTH_USERNAME and NETRA_AUTH_PASSWORD")
if RUNTIME_ROLE == "hosted_web" and len(app.config["NETRA_SENSOR_API_KEY"]) < 32:
    raise RuntimeError("hosted_web requires NETRA_SENSOR_API_KEY with at least 32 characters")


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request body exceeds the configured limit."}), 413


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok", "role": RUNTIME_ROLE}), 200


@app.route("/readyz", methods=["GET"])
def readyz():
    """Check repository readiness without returning connection or exception details."""
    if RUNTIME_ROLE == "hosted_web":
        try:
            end = datetime.now(timezone.utc)
            list(_event_repository().iter_events(
                end - timedelta(seconds=1), end, origins=("live",)
            ))
        except Exception as exc:
            logger.warning("hosted event repository readiness check failed (%s)", type(exc).__name__)
            return jsonify({"status": "not_ready", "dependency": "event_store"}), 503
        try:
            app.config["DELIVERY_REPOSITORY"].critical_email_alert_counts()
        except Exception as exc:
            logger.warning("hosted delivery repository readiness check failed (%s)", type(exc).__name__)
            return jsonify({"status": "not_ready", "dependency": "delivery_store"}), 503
    return jsonify({"status": "ready", "role": RUNTIME_ROLE}), 200


def _is_loopback_request():
    try:
        return ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        return False


@app.before_request
def protect_monitoring_routes():
    """Protect all application routes except health and dedicated sensor ingestion."""
    if request.path in {"/healthz", "/readyz", "/api/v1/sensor/events"} or request.path.startswith("/static/"):
        return None

    username = app.config["NETRA_AUTH_USERNAME"]
    password = app.config["NETRA_AUTH_PASSWORD"]
    if not username or not password:
        if _is_loopback_request():
            return None
        return jsonify({"error": "Dashboard credentials must be configured before remote access."}), 503

    auth = request.authorization
    if (auth is None or not hmac.compare_digest(auth.username or "", username)
            or not hmac.compare_digest(auth.password or "", password)):
        response = jsonify({"error": "Authentication required."})
        response.status_code = 401
        response.headers["WWW-Authenticate"] = 'Basic realm="NETRA monitoring", charset="UTF-8"'
        return response
    return None


def _hosted_delivery_status(*, include_failures: bool = False):
    try:
        repository = app.config["DELIVERY_REPOSITORY"]
        counts = repository.critical_email_alert_counts()
        result = {
            "state": "shared_queue", "message": "Shared PostgreSQL outbox; delivery runs in the hosted worker role.",
            "storage_status": "ok", **counts,
        }
        if include_failures:
            result["recent_failures"] = repository.list_critical_email_alerts(state="failed", limit=20)
        result["persistence_error_code"] = None
        return result
    except Exception as exc:
        logger.error("shared email alert status query failed (%s)", type(exc).__name__)
        return {"state": "unavailable", "message": "Shared email alert status is temporarily unavailable.",
                "storage_status": "error", "pending": None, "delivered": None, "failed": None}


def _hosted_status():
    """Status shape compatible with the existing dashboard without fabricated counters."""
    unavailable = None
    return {
        "runtime_role": "hosted_web",
        "capture_available": False,
        "local_metrics_available": False,
        "is_running": False,
        "stop_requested": False,
        "mode": "hosted",
        "active_interface": "Local sensor only",
        "last_run_mode": None,
        "last_run_source": None,
        "last_run_status": "unavailable",
        "error_message": None,
        "model_available": False,
        "alert_processing_status": "not_applicable",
        "email_alerts": _hosted_delivery_status(),
        "stats": {
            "packets_processed": unavailable, "ignored_packets": unavailable,
            "active_flows": unavailable, "completed_flows": unavailable,
            "classified_flows": unavailable, "simulated_flows": unavailable,
            "benign_count": unavailable, "attack_count": unavailable,
            "attacks_flagged": unavailable, "threat_level": "UNAVAILABLE",
            "processing_errors": unavailable, "capture_errors": unavailable,
            "last_packet_time": unavailable, "last_inference_time": unavailable,
            "last_processing_error": unavailable, "last_capture_error": unavailable,
        },
    }


def _event_repository():
    if RUNTIME_ROLE == "local_sensor":
        return v2_engine.event_writer.repository
    return app.config["EVENT_REPOSITORY"]

# ============================================================
# V1 CONFIGURATION (LIGHTGBM PRIMARY)
# ============================================================

MODEL_PATH = os.getenv(
    "MODEL_PATH",
    os.path.join(PROJECT_ROOT, "results", "models", "lightgbm_top20_model.pkl")
)

THRESHOLD = 0.50

FEATURES = [
    "Destination Port",
    "Bwd Packet Length Std",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd Header Length",
    "Average Packet Size",
    "min_seg_size_forward",
    "Flow IAT Mean",
    "Bwd Header Length",
    "PSH Flag Count",
    "Flow IAT Min",
    "Fwd Packet Length Max",
    "Fwd IAT Min",
    "Total Length of Bwd Packets",
    "Max Packet Length",
    "Fwd IAT Total",
    "Packet Length Std",
    "Flow Bytes/s",
    "Bwd Packet Length Mean",
    "Packet Length Variance"
]

# ============================================================
# LOAD V1 MODEL (local sensor and hosted web roles)
# ============================================================

if RUNTIME_ROLE == "local_sensor":
    import pandas as pd
    import joblib
    try:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
            MODEL_LOADED = True
            print("LightGBM V1 model loaded successfully.")
        else:
            from catboost import CatBoostClassifier
            model = CatBoostClassifier()
            model.load_model(os.path.join(PROJECT_ROOT, "results", "models", "leakage_free_top20_model.cbm"))
            THRESHOLD = 0.004
            MODEL_LOADED = True
            print("CatBoost V1 fallback model loaded successfully.")
    except Exception as e:
        MODEL_LOADED = False
        print("ERROR loading V1 model:", type(e).__name__)

elif RUNTIME_ROLE == "hosted_web":
    import pandas as pd
    import joblib
    try:
        from app.hosted_model_loader import download_verified_v1_model
        verified_model_path = download_verified_v1_model()
        model = joblib.load(verified_model_path)
        MODEL_LOADED = True
        print("Hosted V1 LightGBM model loaded successfully.")
    except Exception as e:
        MODEL_LOADED = False
        model = None
        logger.warning("Hosted V1 model unavailable (%s)", type(e).__name__)


# V1 HOME PAGE (STATIC DETECTION)
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():
    if not MODEL_LOADED or model is None:
        return render_template(
            "index.html", features=FEATURES, values={feature: "" for feature in FEATURES},
            prediction=None, probability=None, confidence=None, threshold=THRESHOLD,
            error="V1 model inference is temporarily unavailable.", model_loaded=False,
        ), 503

    prediction = None
    probability = None
    confidence = None
    error = None

    values = {feature: "" for feature in FEATURES}

    if request.method == "POST":
        try:
            for feature in FEATURES:
                values[feature] = request.form.get(feature, "")

            input_values = []
            for feature in FEATURES:
                value = request.form.get(feature)
                if value is None or value.strip() == "":
                    raise ValueError(f"Please enter a value for '{feature}'.")
                input_values.append(float(value))

            X = pd.DataFrame([input_values], columns=FEATURES)
            attack_probability = model.predict_proba(X)[0][1]

            if attack_probability >= THRESHOLD:
                prediction = "ATTACK"
                confidence = attack_probability * 100
            else:
                prediction = "BENIGN"
                confidence = (1 - attack_probability) * 100

            probability = attack_probability * 100

        except Exception as e:
            error = str(e)

    return render_template(
        "index.html",
        features=FEATURES,
        values=values,
        prediction=prediction,
        probability=probability,
        confidence=confidence,
        threshold=THRESHOLD,
        error=error,
        model_loaded=MODEL_LOADED
    )


# ============================================================
# V2 DYNAMIC DASHBOARD & API ENDPOINTS
# ============================================================

@app.route("/v2")
def v2_dashboard():
    return render_template("v2_dashboard.html")


@app.route("/presentation")
def presentation_deck():
    return render_template("presentation.html")


@app.route("/api/v2/status", methods=["GET"])
def get_v2_status():
    response = jsonify(_hosted_status() if RUNTIME_ROLE == "hosted_web" else v2_engine.get_status())
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response



@app.route("/api/v2/alerts", methods=["GET"])
def get_v2_alerts():
    limit = request.args.get("limit", 50, type=int)
    limit = max(1, min(limit, 100))

    if RUNTIME_ROLE == "hosted_web":
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)

        try:
            repository = _event_repository()
            events = list(repository.iter_events(
                start,
                end,
                origins=("live", "pcap", "simulation"),
                event_types=("flow_classification", "alert"),
            ))
            # iter_events is ordered oldest-first; the dashboard needs newest first.
            events = events[-limit:][::-1]

            feed = []
            alerts = []

            for event in events:
                metadata = event.get("metadata") or {}
                label = event.get("classification")
                event_type = event.get("event_type")
                timestamp = event.get("occurred_at_utc", "")
                protocol = metadata.get("protocol", "—")
                packets = metadata.get("packet_count", 0)
                confidence = metadata.get("confidence_percent")

                item = {
                    "id": event.get("event_id"),
                    "timestamp": timestamp,
                    "last_seen": timestamp,
                    "occurrence_count": 1,
                    "label": label,
                    "detection_source": metadata.get("alert_source", "ml"),
                    "traffic_origin": event.get("origin", "unknown"),
                    "src_ip": "—",
                    "src_port": "—",
                    "dst_ip": "—",
                    "dst_port": "—",
                    "protocol": protocol,
                    "packets": packets,
                    "confidence": confidence if confidence is not None else "—",
                    "event_type": event_type,
                }

                if label in {"ATTACK", "BENIGN"}:
                    feed.append(item)

                if event_type == "alert" and label == "ATTACK":
                    alerts.append(item)

            snapshot = {
                "alerts": alerts,
                "feed": feed,
                "status": _hosted_status(),
                "feed_available": True,
                "feed_reason": (
                    "Showing persisted sensor classifications. "
                    "IP addresses, ports, and live packet counters are not stored "
                    "in the hosted event schema."
                ),
            }
        except Exception as exc:
            logger.error("hosted dashboard event query failed (%s)", type(exc).__name__)
            return jsonify({
                "error": "Hosted dashboard event history is temporarily unavailable."
            }), 503
    else:
        snapshot = v2_engine.get_dashboard_snapshot(limit=limit)

    response = jsonify(snapshot)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response



@app.route("/api/v2/email-alerts/status", methods=["GET"])
def get_v2_email_alert_status():
    if RUNTIME_ROLE == "hosted_web":
        data = _hosted_delivery_status(include_failures=True)
        data.update({"sent": data.get("delivered"), "queued": data.get("pending"),
                     "staged_not_persisted": 0, "recent_failures": data.get("recent_failures", [])})
        response = jsonify(data)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response, (503 if data["storage_status"] != "ok" else 200)
    try:
        snapshot = v2_engine.critical_email_alerts.status_snapshot()
        # Deliberately expose aggregate states and sanitized error categories only.
        data = {
            "state": snapshot.get("state", "unavailable"),
            "message": snapshot.get("message", "Email alert status unavailable."),
            "storage_status": snapshot.get("storage_status", "error"),
            "pending": int(snapshot.get("pending", 0)),
            "delivered": int(snapshot.get("delivered", 0)),
            "failed": int(snapshot.get("failed", 0)),
            "storage_error_code": snapshot.get("storage_error_code"),
            "persistence_error_code": snapshot.get("persistence_error_code"),
            "staged_not_persisted": int(snapshot.get("staged_not_persisted", 0)),
            "recent_failures": snapshot.get("recent_failures", [])[:20],
        }
        response = jsonify(data)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response
    except Exception as exc:
        logger.error("email alert status query failed (%s)", type(exc).__name__)
        return jsonify({"error": "Email alert delivery status is temporarily unavailable."}), 503


@app.route("/api/v2/email-alerts/retry", methods=["POST"])
def retry_v2_email_alerts():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"alert_ids"}:
        return jsonify({"error": "Provide alert_ids containing failed alert UUIDs."}), 400
    ids = data.get("alert_ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= 100:
        return jsonify({"error": "Provide between 1 and 100 failed alert UUIDs."}), 400
    try:
        normalized = [str(uuid.UUID(value)) for value in ids if isinstance(value, str)]
        if len(normalized) != len(ids) or len(set(normalized)) != len(normalized):
            raise ValueError("invalid IDs")
        if RUNTIME_ROLE == "hosted_web":
            retried = app.config["DELIVERY_REPOSITORY"].retry_failed_critical_alerts(normalized)
        else:
            retried = v2_engine.critical_email_alerts.notifier.retry_failed(normalized)
    except (ValueError, TypeError):
        return jsonify({"error": "alert_ids must be unique UUIDs."}), 400
    except Exception as exc:
        logger.error("email alert retry request failed (%s)", type(exc).__name__)
        return jsonify({"error": "Email alert retry is temporarily unavailable."}), 503
    response = jsonify({"success": True, "requeued": retried})
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/api/v2/weekly-reports/retry", methods=["POST"])
def retry_v2_weekly_reports():
    if RUNTIME_ROLE != "hosted_web":
        return jsonify({"error": "Shared weekly report retry is available only in the hosted web role."}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"report_ids"}:
        return jsonify({"error": "Provide report_ids containing failed report UUIDs."}), 400
    ids = data.get("report_ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= 100:
        return jsonify({"error": "Provide between 1 and 100 failed report UUIDs."}), 400
    try:
        normalized = [str(uuid.UUID(value)) for value in ids if isinstance(value, str)]
        if len(normalized) != len(ids) or len(set(normalized)) != len(normalized):
            raise ValueError("invalid IDs")
        retried = app.config["DELIVERY_REPOSITORY"].retry_failed_weekly_reports(normalized)
    except (ValueError, TypeError):
        return jsonify({"error": "report_ids must be unique UUIDs."}), 400
    except Exception as exc:
        logger.error("weekly report retry request failed (%s)", type(exc).__name__)
        return jsonify({"error": "Weekly report retry is temporarily unavailable."}), 503
    response = jsonify({"success": True, "requeued": retried})
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


def _history_query():
    if set(request.args) - {"window", "origin"}:
        return None
    if any(len(request.args.getlist(key)) != 1 for key in request.args):
        return None
    window = request.args.get("window", "24h")
    origin = request.args.get("origin", "live")
    if window not in HISTORY_WINDOWS or origin not in HISTORY_ORIGINS:
        return None
    duration, bucket_seconds = HISTORY_WINDOWS[window]
    end = datetime.now(timezone.utc)
    return window, origin, end - duration, end, bucket_seconds, (None if origin == "all" else (origin,))


@app.route("/api/v2/history/trends", methods=["GET"])
def get_v2_history_trends():
    query = _history_query()
    if query is None:
        return jsonify({"error": "Unsupported history window or origin filter."}), 400
    window, origin, start, end, bucket_seconds, origins = query
    try:
        repository = _event_repository()
        buckets = repository.aggregate_events(start, end, bucket_seconds=bucket_seconds, origins=origins)
    except Exception as exc:
        logger.error("history trend query failed (%s)", type(exc).__name__)
        return jsonify({"error": "Historical trend data is temporarily unavailable."}), 503
    response = jsonify({"window": window, "origin_filter": origin, "bucket_seconds": bucket_seconds,
                        "timezone": "UTC", "buckets": buckets})
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/api/v2/history/top-talkers", methods=["GET"])
def get_v2_top_talkers():
    query = _history_query()
    if query is None:
        return jsonify({"error": "Unsupported history window or origin filter."}), 400
    response = jsonify({
        "available": False,
        "window": query[0],
        "origin_filter": request.args.get("origin", "live"),
        "talkers": [],
        "reason": "Stored event history does not include source or destination IP addresses or ports.",
    })
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/api/v2/start", methods=["POST"])
def start_v2_sniffer():
    if RUNTIME_ROLE == "hosted_web":
        return jsonify({"success": False, "message": "Capture and replay controls are available only on the local sensor."}), 403
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "live")  # "live" or "pcap"
    interface = data.get("interface", None)
    pcap_path = data.get("pcap_path", "data/pcap/test_100k.pcap")

    if not isinstance(mode, str) or mode not in {"live", "pcap"}:
        return jsonify({
            "success": False,
            "message": "Unsupported capture mode. Choose 'live' or 'pcap'.",
            "status": v2_engine.get_status(),
        }), 400

    if mode == "pcap":
        # Resolve full path if relative
        if not os.path.isabs(pcap_path):
            pcap_path = os.path.join(PROJECT_ROOT, pcap_path)
        ok, msg = v2_engine.start_pcap_replay(pcap_path)
    else:
        ok, msg = v2_engine.start_live(interface=interface)

    status = v2_engine.get_status()
    response = {"success": ok, "message": msg, "status": status}
    http_status = 503 if not ok and not status.get("model_available", True) else 200
    return jsonify(response), http_status


@app.route("/api/v2/stop", methods=["POST"])
def stop_v2_sniffer():
    if RUNTIME_ROLE == "hosted_web":
        return jsonify({"success": False, "message": "Capture controls are available only on the local sensor."}), 403
    ok, msg = v2_engine.stop()
    return jsonify({"success": ok, "message": msg, "status": v2_engine.get_status()})


@app.route("/api/v2/clear", methods=["POST"])
def clear_v2_alerts():
    if RUNTIME_ROLE == "hosted_web":
        return jsonify({"success": False, "message": "Local alert controls are unavailable in the hosted web role."}), 403
    ok = v2_engine.clear_alerts()
    return jsonify({"success": ok, "message": "Alert history cleared."})


@app.route("/api/v2/simulate-attack", methods=["POST"])
def simulate_attack():
    if RUNTIME_ROLE == "hosted_web":
        return jsonify({"success": False, "message": "Attack simulation is available only on the local sensor."}), 403
    status = v2_engine.get_status()
    if not status.get("model_available", False):
        message = status.get("model_status_message")
        return jsonify({"success": False, "message": message}), 503
    data = request.get_json(silent=True) or {}
    packet_count = data.get("packet_count", 500)
    target_ip = data.get("target_ip", "127.0.0.1")
    target_port = data.get("target_port", 8080)

    ok, msg = run_attack_simulation(
        target_ip=target_ip,
        target_port=target_port,
        packet_count=packet_count
    )

    # Inject attack flow vectors so live alerts immediately flag red attack badges
    v2_engine.inject_simulated_attack(count=5)

    return jsonify({
        "success": True, 
        "message": f"Triggered attack simulation burst ({packet_count} packets) & injected 5 live intrusion attack alerts!"
    })


@app.route("/api/v2/interfaces", methods=["GET"])
def get_interfaces():
    if RUNTIME_ROLE == "hosted_web":
        return jsonify({"available": False, "interfaces": [], "message": "Interfaces are available only on the local sensor."}), 403
    return jsonify({"interfaces": v2_engine.get_interfaces()})


@app.route("/api/v1/sensor/events", methods=["POST"])
def ingest_sensor_events():
    """Accept bounded V1 event batches from a local sensor using its own credential."""
    configured_key = app.config["NETRA_SENSOR_API_KEY"]
    if not configured_key or len(configured_key) < 32:
        return jsonify({"error": "Sensor ingestion is not configured."}), 503

    auth_header = request.headers.get("Authorization", "")
    scheme, separator, supplied_key = auth_header.partition(" ")
    if (not separator or scheme.lower() != "bearer"
            or not hmac.compare_digest(supplied_key.encode("utf-8"), configured_key.encode("utf-8"))):
        return jsonify({"error": "Authentication required."}), 401

    if _sensor_rate_limited(request.remote_addr):
        response = jsonify({"error": "Ingestion rate limit exceeded."})
        response.headers["Retry-After"] = str(SENSOR_RATE_WINDOW_SECONDS)
        return response, 429
    if request.content_length is not None and request.content_length > MAX_SENSOR_REQUEST_BYTES:
        return jsonify({"error": "Request body exceeds the configured limit."}), 413
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 415
    try:
        payload = request.get_json()
    except Exception:
        return jsonify({"error": "Malformed JSON request."}), 400
    if not isinstance(payload, dict) or set(payload) != {"events"}:
        return jsonify({"error": "Request must contain only an events array."}), 400
    events = payload["events"]
    if not isinstance(events, list) or not events:
        return jsonify({"error": "events must be a non-empty array."}), 400
    if len(events) > MAX_SENSOR_BATCH_EVENTS:
        return jsonify({"error": "Event batch exceeds the configured limit."}), 413
    try:
        normalized_events = [_validate_sensor_event(event) for event in events]
        repository = _event_repository()
        inserted = repository.append_many(normalized_events, enqueue_forward=False)
    except (EventValidationError, TypeError, ValueError, RecursionError, OverflowError):
        return jsonify({"error": "Event batch failed schema validation."}), 400
    except Exception as exc:
        logger.error("sensor event batch persistence failed (%s)", type(exc).__name__)
        return jsonify({"error": "Event batch could not be persisted."}), 503

    return jsonify({
        "accepted": len(normalized_events),
        "inserted": inserted,
        "duplicates": len(normalized_events) - inserted,
    }), 200


if RUNTIME_ROLE == "local_sensor":
    # The detector owns capture shutdown and closes its writer/email resources
    # only after the capture thread has terminated.
    try:
        _event_forwarder = EventForwarder.from_environment(event_repository)
        _forwarding_worker = ForwardingWorker(_event_forwarder) if _event_forwarder else None
        if _forwarding_worker is not None:
            _forwarding_worker.start()
            atexit.register(_forwarding_worker.stop)
    except (ValueError, RuntimeError) as exc:
        raise RuntimeError(f"NETRA event forwarding configuration error: {type(exc).__name__}") from None


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    host = "0.0.0.0" if RUNTIME_ROLE == "hosted_web" else os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    app.run(
        host=host,
        port=port,
        debug=RUNTIME_ROLE == "local_sensor"
    )
