"""
train.py
--------
Trains a Random Forest classifier on syscall-statistics features produced
by the C monitoring program (via dataset.jsonl / features.json).

Usage:
    python train.py [path/to/dataset.jsonl]
"""

import json
import sys
import pickle

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# Exact feature order — MUST match predict.py and the C program's fields.
FEATURES = [
    "file",
    "process",
    "network",
    "fork",
    "connect",
    "execve",
    "read",
    "open",
    "close",
    "memory",
    "mprotect",
    "ptrace",
]

RANDOM_STATE = 42
MODEL_PATH = "syscall_model.pkl"


def load_jsonl(path):
    records = []
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                print(f"WARNING: skipping malformed JSON on line {line_no}", file=sys.stderr)
                continue

            if "label" not in obj:
                print(f"WARNING: skipping line {line_no}, missing 'label'", file=sys.stderr)
                continue

            row = []
            ok = True
            for feat in FEATURES:
                if feat not in obj:
                    print(f"WARNING: skipping line {line_no}, missing feature '{feat}'", file=sys.stderr)
                    ok = False
                    break
                row.append(obj[feat])
            if not ok:
                continue

            records.append((row, int(obj["label"])))
    return records


def main():
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "dataset.jsonl"

    records = load_jsonl(dataset_path)
    if not records:
        print("ERROR: no usable records found in dataset.", file=sys.stderr)
        sys.exit(1)

    X = np.array([r[0] for r in records], dtype=float)
    y = np.array([r[1] for r in records], dtype=int)

    print(f"Loaded {len(X)} samples ({(y == 0).sum()} benign, {(y == 1).sum()} malicious)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n=== Accuracy ===")
    print(f"{accuracy_score(y_test, y_pred):.4f}")

    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "MALICIOUS"]))

    print("=== Confusion Matrix ===")
    print("           pred_benign  pred_malicious")
    cm = confusion_matrix(y_test, y_pred)
    for label, row in zip(["true_benign", "true_malicious"], cm):
        print(f"{label:>15} {row[0]:>12} {row[1]:>15}")

    print("\n=== Feature Importance ===")
    importances = clf.feature_importances_
    for feat, imp in sorted(zip(FEATURES, importances), key=lambda x: -x[1]):
        print(f"{feat:10s} {imp:.4f}")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": clf, "features": FEATURES}, f)

    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
