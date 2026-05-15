import time
import threading
import os

import step1_capture
import step2_extract
import step3_preprocess

MIN_FEATURES     = 100  # minimum samples before preprocessing runs
PREPROCESS_EVERY = 5    # seconds between each feature count check

_done = threading.Event()


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
                print(f"[pipeline] All assets saved: {assets}")
                print("[pipeline] Done. Terminating.")
                _done.set()
                return

        except Exception as e:
            print(f"[pipeline] Preprocess error: {e}")


if __name__ == "__main__":
    threads = [
        threading.Thread(target=_capture_thread,    daemon=True, name="capture"),
        threading.Thread(target=_extraction_thread, daemon=True, name="extraction"),
        threading.Thread(target=_preprocess_loop,   daemon=True, name="preprocess"),
        threading.Thread(target=_status_thread,     daemon=True, name="status"),
    ]

    for t in threads:
        t.start()
        print(f"[pipeline] Started thread: {t.name}")

    print(f"[pipeline] Collecting {MIN_FEATURES} packets then terminating...")
    try:
        _done.wait()    # blocks until _done.set() is called by _preprocess_loop
    except KeyboardInterrupt:
        print("\n[pipeline] Interrupted.")
    finally:
        print("[pipeline] Shutdown complete. Run step4_model.py next.")
