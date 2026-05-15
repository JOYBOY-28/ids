import time
import threading
import os

import step1_capture
import step2_extract
import step3_preprocess
import step4_model

MIN_FEATURES     = 100
PREPROCESS_EVERY = 5

_done     = threading.Event()
_training_done = threading.Event()


# ---------------------------------------------------------------------------
# Phase 1 threads — data collection
# ---------------------------------------------------------------------------
def _capture_thread():
    while not _done.is_set():
        step1_capture.start_capture()


def _extraction_thread():
    while not _done.is_set():
        step2_extract._extraction_loop()


def _status_thread():
    while not _done.is_set():
        time.sleep(5)
        with step2_extract._lock:
            n = len(step2_extract.feature_list)
        if not _training_done.is_set():
            print(f"[pipeline] features collected: {n}/{MIN_FEATURES}")


def _preprocess_loop():
    while not _done.is_set():
        time.sleep(PREPROCESS_EVERY)

        with step2_extract._lock:
            n = len(step2_extract.feature_list)

        if n < MIN_FEATURES:
            continue

        print(f"[pipeline] {n} samples ready — preprocessing...")
        try:
            X, y, scaler = step3_preprocess.preprocess(step2_extract.feature_list)
            print(f"[pipeline] X={X.shape}  y={y.shape}  "
                  f"normal={(y==0).sum()}  attack={(y==1).sum()}")

            assets = ["X.npy", "y.npy", "scaler.pkl"]
            if all(os.path.exists(a) for a in assets):
                print(f"[pipeline] Assets saved: {assets}")
                _done.set()
                return

        except Exception as e:
            print(f"[pipeline] Preprocess error: {e}")


# ---------------------------------------------------------------------------
# Phase 2 — training (runs in main thread after phase 1 completes)
# ---------------------------------------------------------------------------
def _train():
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    import joblib
    import matplotlib
    matplotlib.use("Agg")   # non-interactive backend, no Tk needed
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay

    print("\n[training] Loading X.npy and y.npy...")
    X = np.load("X.npy")
    y = np.load("y.npy")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print("[training] Fitting RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=100, class_weight="balanced", random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n[training] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["NORMAL", "ATTACK"]))

    disp = ConfusionMatrixDisplay.from_predictions(
        y_test, y_pred, display_labels=["NORMAL", "ATTACK"], cmap="Blues"
    )
    disp.ax_.set_title("IDS Confusion Matrix")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    plt.close()
    print("[training] confusion_matrix.png saved.")

    joblib.dump(model, "model.pkl")
    print("[training] model.pkl saved.")
    _training_done.set()


# ---------------------------------------------------------------------------
# Phase 3 — live monitor (runs after training)
# ---------------------------------------------------------------------------
def _live_monitor_thread():
    print("\n[monitor] Starting live inference. Monitoring traffic...\n")
    step4_model.live_monitor(interval=5)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # ── Phase 1: collect data ──────────────────────────────────────────────
    print("[pipeline] Phase 1: Collecting packets...\n")
    phase1_threads = [
        threading.Thread(target=_capture_thread,    daemon=True, name="capture"),
        threading.Thread(target=_extraction_thread, daemon=True, name="extraction"),
        threading.Thread(target=_preprocess_loop,   daemon=True, name="preprocess"),
        threading.Thread(target=_status_thread,     daemon=True, name="status"),
    ]
    for t in phase1_threads:
        t.start()

    try:
        _done.wait()   # block until X.npy / y.npy / scaler.pkl are saved
    except KeyboardInterrupt:
        print("\n[pipeline] Interrupted during collection.")
        raise SystemExit

    # ── Phase 2: train model ───────────────────────────────────────────────
    print("\n[pipeline] Phase 2: Training model...\n")
    try:
        _train()
    except Exception as e:
        print(f"[pipeline] Training failed: {e}")
        raise SystemExit

    # ── Phase 3: live inference ────────────────────────────────────────────
    print("\n[pipeline] Phase 3: Live monitoring...\n")
    monitor = threading.Thread(
        target=_live_monitor_thread, daemon=True, name="monitor"
    )
    # restart capture + extraction for live traffic
    cap  = threading.Thread(target=_capture_thread,    daemon=True, name="capture2")
    extr = threading.Thread(target=_extraction_thread, daemon=True, name="extraction2")

    for t in [cap, extr, monitor]:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[pipeline] Live monitor stopped.")
