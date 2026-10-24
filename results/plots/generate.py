
import os
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

os.makedirs("results/plots/report_figures", exist_ok=True)

# Replace these with actual arrays from your experiment:
# y_test = actual test labels
# y_pred_lightgbm = LightGBM predictions on the same test records
# y_pred_catboost = CatBoost predictions on the same test records

def save_confusion_matrix(y_test, y_pred, model_name):
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["BENIGN", "ATTACK"]
    )

    fig, ax = plt.subplots(figsize=(6, 5))
    display.plot(ax=ax, values_format=",", colorbar=False)
    ax.set_title(model_name + " — Test Confusion Matrix")
    fig.tight_layout()

    filename = model_name.lower().replace(" ", "_")
    fig.savefig(
        f"results/plots/report_figures/{filename}_confusion_matrix.png",
        dpi=300
    )
    plt.close(fig)

# After loading actual predictions:
# save_confusion_matrix(y_test, y_pred_lightgbm, "LightGBM")
# save_confusion_matrix(y_test, y_pred_catboost, "CatBoost")
