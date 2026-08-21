from flask import Flask, render_template, request
from catboost import CatBoostClassifier
import pandas as pd
import os

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "results",
    "models",
    "leakage_free_top20_model.cbm"
)

THRESHOLD = 0.004

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
# LOAD MODEL
# ============================================================

model = CatBoostClassifier()

try:
    model.load_model(MODEL_PATH)
    MODEL_LOADED = True
    print("CatBoost model loaded successfully.")
except Exception as e:
    MODEL_LOADED = False
    print("ERROR loading model:")
    print(e)


# ============================================================
# HOME PAGE
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
            # ------------------------------------------------
            # Read input values
            # ------------------------------------------------

            for feature in FEATURES:
                values[feature] = request.form.get(feature, "")

            # ------------------------------------------------
            # Convert to numeric values
            # ------------------------------------------------

            input_values = []

            for feature in FEATURES:

                value = request.form.get(feature)

                if value is None or value.strip() == "":
                    raise ValueError(
                        f"Please enter a value for '{feature}'."
                    )

                input_values.append(float(value))

            # ------------------------------------------------
            # Create DataFrame
            # ------------------------------------------------

            X = pd.DataFrame(
                [input_values],
                columns=FEATURES
            )

            # ------------------------------------------------
            # Prediction
            # ------------------------------------------------

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
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )