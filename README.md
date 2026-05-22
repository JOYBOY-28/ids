# Network Intrusion Detection System (IDS) Pipeline

A real-time network intrusion detection pipeline built with Python, Scapy, and scikit-learn. Captures live traffic, extracts features, trains a Random Forest classifier, and performs live inference — all in a single orchestrated process.

---

## Pipeline Architecture

```
step1_capture.py      →   Captures raw packets via Scapy → packet_buffer
step2_extract.py      →   Drains buffer every 5s → extracts 15 features → feature_list
step3_preprocess.py   →   Builds DataFrame, scales features, labels data → X.npy, y.npy, scaler.pkl
step4_model.py        →   Trains RandomForestClassifier → model.pkl → live inference
run_pipeline.py       →   Orchestrates all 4 stages as threads in one process
```

---

## Project Structure

```
cn/
├── step1_capture.py        # Packet capture using Scapy
├── step2_extract.py        # Feature extraction from raw packets
├── step3_preprocess.py     # Data cleaning, labelling, scaling
├── step4_model.py          # Model training and live inference
├── run_pipeline.py         # Master orchestrator (only script you run)
├── X.npy                   # Feature matrix (generated)
├── y.npy                   # Labels (generated)
├── scaler.pkl              # Fitted StandardScaler (generated)
├── model.pkl               # Trained RandomForest model (generated)
└── confusion_matrix.png    # Evaluation plot (generated)
```

---

## Features Extracted (15 per packet)

| Feature | Description |
|---|---|
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port (0 if N/A) |
| `dst_port` | Destination port (0 if N/A) |
| `ip_ttl` | IP Time-To-Live |
| `ip_flag_df` | Don't Fragment bit (0 or 1) |
| `ip_flag_mf` | More Fragments bit (0 or 1) |
| `payload_len` | Length of IP payload in bytes |
| `delta_t` | Time delta from previous packet (seconds) |
| `proto` | Protocol: TCP=0, UDP=1, ICMP=2, OTHER=3 |
| `flag_syn` | TCP SYN flag (0 or 1) |
| `flag_ack` | TCP ACK flag (0 or 1) |
| `flag_fin` | TCP FIN flag (0 or 1) |
| `flag_rst` | TCP RST flag (0 or 1) |
| `flag_psh` | TCP PSH flag (0 or 1) |

**Scaled features:** `payload_len`, `ip_ttl`, `delta_t` via `StandardScaler`

**Passthrough features:** `flag_syn`, `flag_ack`, `flag_fin`, `flag_rst`, `flag_psh`, `proto`

---

## How to Run

### Requirements

```bash
pip install scapy scikit-learn pandas numpy joblib matplotlib
```

### Single command (runs all 3 phases automatically)

```bash
sudo .myenv/bin/python3 run_pipeline.py
```

> `sudo` is required for raw packet capture via Scapy.

---

## Pipeline Phases

### Phase 1 — Data Collection

Captures live network traffic, extracts features every 5 seconds, and preprocesses once 100 samples are collected. Saves `X.npy`, `y.npy`, and `scaler.pkl` then terminates automatically.

```
[pipeline] Started thread: capture
[pipeline] Started thread: extraction
[pipeline] Started thread: preprocess
[pipeline] Started thread: status
[pipeline] Collecting 100 packets then terminating...
[pipeline] features collected: 23/100
[pipeline] features collected: 67/100
[pipeline] features collected: 134/100
[TCP] 142.251.157.119:443 -> 10.20.188.39:44942 (120 bytes)
[TCP] 142.251.157.119:443 -> 10.20.188.39:44942 (97 bytes)
[TCP] 142.251.157.119:443 -> 10.20.188.39:44942 (105 bytes)
[TCP] 10.20.188.39:44942 -> 142.251.157.119:443 (66 bytes)
[TCP] 10.20.188.39:44942 -> 142.251.157.119:443 (66 bytes)
[OTHER] 10.20.185.106:- -> 224.0.0.22:- (60 bytes)
[OTHER] 10.20.185.106:- -> 224.0.0.22:- (78 bytes)
[TCP] 142.251.157.119:443 -> 10.20.188.39:44952 (147 bytes)
[TCP] 10.20.188.39:44952 -> 142.251.157.119:443 (105 bytes)
[pipeline] 243 samples ready — preprocessing...
[preprocess] Saved X.npy (243, 9) and y.npy (243,)
[pipeline] X=(243, 9)  y=(243,)  normal=84  attack=159
[pipeline] All assets saved: ['X.npy', 'y.npy', 'scaler.pkl']
[pipeline] Done. Terminating.
[pipeline] Shutdown complete. Run step4_model.py next.
```

---

### Phase 2 — Model Training

Loads `X.npy` / `y.npy`, splits 80/20, fits `RandomForestClassifier(n_estimators=100, class_weight='balanced')`, prints classification report, and saves `confusion_matrix.png` and `model.pkl`.

```
[pipeline] Phase 2: Training model...

[training] Loading X.npy and y.npy...
[TCP] 142.251.157.119:443 -> 10.20.188.39:44952 (66 bytes)
[training] Fitting RandomForestClassifier...
[TCP] 142.251.157.119:443 -> 10.20.188.39:44942 (341 bytes)
[TCP] 142.251.157.119:443 -> 10.20.188.39:44942 (1466 bytes)
[TCP] 142.251.157.119:443 -> 10.20.188.39:44942 (2866 bytes)
[TCP] 10.20.188.39:44942 -> 142.251.157.119:443 (66 bytes)
[TCP] 142.250.146.95:443 -> 10.20.188.39:47710 (566 bytes)
[TCP] 142.250.146.95:443 -> 10.20.188.39:47710 (201 bytes)
[TCP] 142.250.146.95:443 -> 10.20.188.39:47710 (66 bytes)

[training] Classification Report:
              precision    recall  f1-score   support

      NORMAL       0.71      0.71      0.71        17
      ATTACK       0.84      0.84      0.84        32

    accuracy                           0.80        49
   macro avg       0.77      0.77      0.77        49
weighted avg       0.80      0.80      0.80        49

[training] confusion_matrix.png saved.
[training] model.pkl saved.
```

---

### Phase 3 — Live Monitoring

Restarts capture and extraction threads, loads `model.pkl`, and runs continuous inference every 5 seconds. Prints alerts for detected attacks with source/destination IP details.

```
[pipeline] Phase 3: Live monitoring...

[monitor] Starting live inference. Monitoring traffic...
[monitor] Live inference started.
[TCP] 10.20.188.39:51952 -> 137.97.164.40:443 (104 bytes)
[TCP] 142.250.146.95:443 -> 10.20.188.39:47710 (66 bytes)
[TCP] 137.97.164.40:443 -> 10.20.188.39:51952 (104 bytes)
[TCP] 10.20.188.39:51952 -> 137.97.164.40:443 (66 bytes)
[UDP] 8.8.4.4:53 -> 10.20.188.39:37289 (169 bytes)
[UDP] 8.8.4.4:53 -> 10.20.188.39:50625 (162 bytes)
[TCP] 10.20.188.39:33840 -> 216.239.32.223:443 (74 bytes)
[TCP] 216.239.32.223:443 -> 10.20.188.39:33840 (74 bytes)
[TCP] 10.20.188.39:55216 -> 142.250.134.190:443 (105 bytes)
[TCP] 142.250.134.190:443 -> 10.20.188.39:55216 (66 bytes)
[ALERT] ATTACK detected | src=10.20.188.39:55216   dst=142.250.134.190:443  proto=0  flags SYN/ACK/RST=0/1/0
[ALERT] ATTACK detected | src=10.20.188.39:55216   dst=142.250.134.190:443  proto=0  flags SYN/ACK/RST=0/1/0
[ALERT] ATTACK detected | src=142.250.134.190:443  dst=10.20.188.39:55216   proto=0  flags SYN/ACK/RST=0/1/0
[ALERT] ATTACK detected | src=10.20.188.39:55216   dst=142.250.134.190:443  proto=0  flags SYN/ACK/RST=0/1/0
[OTHER] 10.20.186.17:- -> 224.0.0.22:- (60 bytes)
[ALERT] ATTACK detected | src=10.20.186.17:0       dst=224.0.0.22:0         proto=3  flags SYN/ACK/RST=0/0/0
[OTHER] 10.20.188.231:- -> 224.0.0.2:- (60 bytes)
[OTHER] 10.20.188.231:- -> 224.0.0.251:- (60 bytes)
[TCP] 10.20.188.39:37194 -> 57.144.81.32:443 (66 bytes)
```

---

## Labelling Logic (Mock)

Since this pipeline uses unsupervised traffic (no ground truth), labels are assigned heuristically:

| Condition | Label |
|---|---|
| `dst_port` in `{22, 23, 3389, 445, 8080}` | ATTACK |
| `flag_syn=1` and `flag_ack=0` | ATTACK |
| `flag_rst=1` | ATTACK |
| `payload_len > 1400` | ATTACK |
| Every 5th packet (fallback) | ATTACK |
| Everything else | NORMAL |

> Replace `_mock_label()` in `step3_preprocess.py` with ground-truth labels for production use.

---

## Inter-process Design

All 4 steps run as **threads in a single process** via `run_pipeline.py`. This avoids the shared-memory problem of running separate Python processes, where imported objects like `packet_buffer` and `feature_list` would not be shared.

```
run_pipeline.py (single process)
 ├── Thread: capture      → step1_capture.start_capture()
 ├── Thread: extraction   → step2_extract._extraction_loop()
 ├── Thread: preprocess   → step3_preprocess.preprocess()
 ├── Thread: status       → prints progress every 5s
 └── Thread: monitor      → step4_model.live_monitor() [Phase 3 only]
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `scapy` | Raw packet capture and parsing |
| `pandas` | DataFrame construction and cleaning |
| `numpy` | Array operations and `.npy` serialisation |
| `scikit-learn` | StandardScaler, RandomForestClassifier, metrics |
| `joblib` | Model and scaler serialisation |
| `matplotlib` | Confusion matrix plot (Agg backend, no display required) |
