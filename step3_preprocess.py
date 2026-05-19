import numpy as np
import pandas as pd
import joblib
from pathlib import Path

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from step2_extract import feature_list

BASE_DIR = Path(__file__).resolve().parent
SCALER_PATH = BASE_DIR / "scaler.pkl"

CONTINUOUS_FEATURES  = ["payload_len", "ip_ttl", "delta_t"]
PASSTHROUGH_FEATURES = ["flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "proto"]
ALL_FEATURES         = CONTINUOUS_FEATURES + PASSTHROUGH_FEATURES

EXPECTED_RAW_FEATURES = 15

# ---------------------------------------------------------------------------
# Labelling config
# ---------------------------------------------------------------------------
ATTACK_DST_PORTS = {22, 23, 3389, 445, 8080, 53, 443, 80}  # expanded port set

def _mock_label(row: pd.Series) -> int:
    if row["dst_port"] in ATTACK_DST_PORTS:
        return 1
    if row["flag_syn"] == 1 and row["flag_ack"] == 0:
        return 1
    if row["flag_rst"] == 1:
        return 1
    if row["payload_len"] > 1400:
        return 1
    # fallback: label ~20% of remaining traffic as attack for class balance
    if int(row.name) % 5 == 0:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Main preprocessing pipeline
# ---------------------------------------------------------------------------
def preprocess(feature_list: list[dict]) -> tuple[np.ndarray, np.ndarray, StandardScaler]:
    df = pd.DataFrame(feature_list)

    assert df.shape[1] == EXPECTED_RAW_FEATURES, (
        f"Expected {EXPECTED_RAW_FEATURES} feature columns, got {df.shape[1]}. "
        f"Columns present: {list(df.columns)}"
    )

    # Clean
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df.reset_index(drop=True, inplace=True)

    # Label
    df["label"] = df.apply(_mock_label, axis=1)

    # Scale continuous features only
    scaler = StandardScaler()
    df[CONTINUOUS_FEATURES] = scaler.fit_transform(df[CONTINUOUS_FEATURES])

    # Export scaler
    joblib.dump(scaler, SCALER_PATH)

    X = df[ALL_FEATURES].to_numpy(dtype=np.float32)
    y = df["label"].to_numpy(dtype=np.int32)

    np.save(BASE_DIR / "X.npy", X)
    np.save(BASE_DIR / "y.npy", y)
    print(f"[preprocess] Saved X.npy {X.shape} and y.npy {y.shape}")

    return X, y, scaler


# ---------------------------------------------------------------------------
# Inference helper
# ---------------------------------------------------------------------------
def transform(raw_dict: dict) -> np.ndarray:
    scaler: StandardScaler = joblib.load(SCALER_PATH)

    # use DataFrame to match feature names scaler was fitted with
    cont   = pd.DataFrame([[raw_dict[f] for f in CONTINUOUS_FEATURES]], columns=CONTINUOUS_FEATURES)
    passth = np.array([[raw_dict[f] for f in PASSTHROUGH_FEATURES]], dtype=np.float32)

    cont_scaled = scaler.transform(cont)
    x = np.concatenate([cont_scaled, passth], axis=1)
    return x

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    X, y, scaler = preprocess(feature_list)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"X_train : {X_train.shape}  y_train : {y_train.shape}")
    print(f"X_test  : {X_test.shape}  y_test  : {y_test.shape}")
    print(f"Label distribution  ->  normal: {(y == 0).sum()}  attack: {(y == 1).sum()}")
    print(f"Scaler saved to '{SCALER_PATH}'")
