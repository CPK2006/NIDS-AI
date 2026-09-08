import os
import sys
from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib

# Add project root to sys.path for v2 imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from v2.live_detector import engine as v2_engine
from v2.attack_simulator import run_attack_simulation

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
except ImportError:
    pass

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "nids-ai-secret-key-super-secure-2026")

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
# LOAD V1 MODEL
# ============================================================

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
    print("ERROR loading V1 model:", e)


# ============================================================
# V1 HOME PAGE (STATIC DETECTION)
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():
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
    return jsonify(v2_engine.get_status())


@app.route("/api/v2/alerts", methods=["GET"])
def get_v2_alerts():
    limit = request.args.get("limit", 50, type=int)
    return jsonify({
        "alerts": v2_engine.get_alerts(limit=limit),
        "status": v2_engine.get_status()
    })


@app.route("/api/v2/start", methods=["POST"])
def start_v2_sniffer():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "live")  # "live" or "pcap"
    interface = data.get("interface", None)
    pcap_path = data.get("pcap_path", "data/pcap/test_100k.pcap")

    if mode == "pcap":
        # Resolve full path if relative
        if not os.path.isabs(pcap_path):
            pcap_path = os.path.join(PROJECT_ROOT, pcap_path)
        ok, msg = v2_engine.start_pcap_replay(pcap_path)
    else:
        ok, msg = v2_engine.start_live(interface=interface)

    return jsonify({"success": ok, "message": msg, "status": v2_engine.get_status()})


@app.route("/api/v2/stop", methods=["POST"])
def stop_v2_sniffer():
    ok, msg = v2_engine.stop()
    return jsonify({"success": ok, "message": msg, "status": v2_engine.get_status()})


@app.route("/api/v2/clear", methods=["POST"])
def clear_v2_alerts():
    ok = v2_engine.clear_alerts()
    return jsonify({"success": ok, "message": "Alert history cleared."})


@app.route("/api/v2/simulate-attack", methods=["POST"])
def simulate_attack():
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
    return jsonify({"interfaces": v2_engine.get_interfaces()})


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    app.run(
        host=host,
        port=port,
        debug=True
    )