import time
import numpy as np
import joblib
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, ConfusionMatrixDisplay

from step1_capture import packet_buffer
from step2_extract import _extract_features
from step3_preprocess import transform

MODEL_PATH = "model.pkl"

_model: RandomForestClassifier | None = None


# ---------------------------------------------------------------------------
# Cached model loader
# ---------------------------------------------------------------------------
def _load_model() -> RandomForestClassifier:
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


# ---------------------------------------------------------------------------
# Live inference
# ---------------------------------------------------------------------------
def predict(raw_dict: dict) -> str:
    model = _load_model()
    x = transform(raw_dict)
    label = model.predict(x)[0]
    return "ATTACK" if label == 1 else "NORMAL"


def live_monitor(interval: int = 5) -> None:
    print("[monitor] Live inference started.")
    while True:
        time.sleep(interval)
        packets = packet_buffer.drain()
        if not packets:
            continue
        for pkt in packets:
            features = _extract_features(pkt)
            if features is None:
                continue
            result = predict(features)
            if result == "ATTACK":
                print(
                    f"[ALERT] ATTACK detected | "
                    f"src={features['src_ip']}:{features['src_port']}  "
                    f"dst={features['dst_ip']}:{features['dst_port']}  "
                    f"proto={features['proto']}  "
                    f"flags SYN/ACK/RST={features['flag_syn']}/{features['flag_ack']}/{features['flag_rst']}"
                )


# ---------------------------------------------------------------------------
# Training & evaluation
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    X = np.load("X.npy")
    y = np.load("y.npy")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["NORMAL", "ATTACK"]))

    disp = ConfusionMatrixDisplay.from_predictions(
        y_test, y_pred,
        display_labels=["NORMAL", "ATTACK"],
        cmap="Blues"
    )
    disp.ax_.set_title("IDS Confusion Matrix")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    plt.close()
    print("Confusion matrix saved to confusion_matrix.png")

    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
