"""
predict.py
----------
Loads syscall_model.pkl and scores JSON-Lines records appended by the C
program to features.json.

By default this scores only the LAST record in features.json (the most
recent execve() the C monitor recorded) — this matches a "live" workflow
where the C program appends one line per run and you want to know right
away whether that run looked malicious.

Use --all to score every record in the file instead (useful for a batch
review of everything collected so far).

Usage:
    python predict.py                      # latest record only
    python predict.py --all                # every record
    python predict.py path/to/other.json   # different file, latest record
    python predict.py path/to/other.json --all
"""

import json
import os
import sys
import pickle

import numpy as np

# Resolve the model relative to THIS script's location, not the caller's
# working directory — predict.py is typically invoked by the C program
# from wherever the C binary runs, which may not be the ml/ folder.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "syscall_model.pkl")

# features.json, on the other hand, is written by the C program into ITS
# own working directory (fopen("features.json", "a")), so this one stays
# relative to the caller's cwd by default.
DEFAULT_FEATURES_PATH = "features.json"

# prediction.txt is the hand-off file back to the C program: one plain
# line ("MALICIOUS" or "BENIGN") that index.c reads with a single
# fgets() call. Written into the caller's cwd, same as features.json,
# so it lands wherever the C program is actually running from.
PREDICTION_OUTPUT_PATH = "prediction.txt"


def load_model(path=MODEL_PATH):
    try:
        with open(path, "rb") as f:
            bundle = pickle.load(f)
    except FileNotFoundError:
        print(f"ERROR: model file '{path}' not found. Run train.py first.", file=sys.stderr)
        sys.exit(1)
    return bundle["model"], bundle["features"]


def load_records(path):
    """Read every valid JSON object from a JSON-Lines file, skipping bad lines."""
    records = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"ERROR: features file '{path}' not found.", file=sys.stderr)
        sys.exit(1)

    for line_no, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            print(f"WARNING: skipping malformed JSON on line {line_no} of {path}", file=sys.stderr)
            continue
        records.append(obj)

    if not records:
        print(f"ERROR: no valid JSON records found in '{path}'.", file=sys.stderr)
        sys.exit(1)

    return records


def score_one(model, features, obj):
    missing = [f for f in features if f not in obj]
    if missing:
        print(f"WARNING: skipping record (missing features {missing}): {obj}", file=sys.stderr)
        return

    row = np.array([[obj[f] for f in features]], dtype=float)

    pred = model.predict(row)[0]
    proba = model.predict_proba(row)[0]
    classes = list(model.classes_)
    confidence = proba[classes.index(pred)] * 100

    label_str = "MALICIOUS" if pred == 1 else "BENIGN"
    program = obj.get("program", "<unknown>")

    print(f"\nProgram: {program}")
    print(f"\nPrediction: {label_str}")
    print(f"Confidence: {confidence:.2f}%")
    print("\nFeatures:")
    for f in features:
        print(f"{f:10s}= {obj[f]}")

    # Hand-off for index.c: two lines it can fgets() straight up —
    # line 1 is the label, line 2 is the confidence as a plain number
    # (no "%" sign, so C can pass it straight to atof()). Overwritten on
    # every run, so it always reflects the most recent prediction.
    try:
        with open(PREDICTION_OUTPUT_PATH, "w") as f:
            f.write(f"{label_str}\n")
            f.write(f"{confidence:.2f}\n")
    except OSError as e:
        print(f"WARNING: could not write '{PREDICTION_OUTPUT_PATH}': {e}", file=sys.stderr)


def main():
    args = sys.argv[1:]
    score_all = "--all" in args
    args = [a for a in args if a != "--all"]
    features_path = args[0] if args else DEFAULT_FEATURES_PATH

    model, features = load_model()
    records = load_records(features_path)

    if score_all:
        for obj in records:
            score_one(model, features, obj)
    else:
        score_one(model, features, records[-1])


if __name__ == "__main__":
    main()