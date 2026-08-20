import json
import joblib
from pathlib import Path

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

FEATURES_PATH = BASE_DIR / "features.json"
MODEL_PATH = BASE_DIR / "ml" / "syscall_model.pkl"
PREDICTION_PATH = BASE_DIR / "prediction.txt"

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
    "chmod",
    "killit"
]


# Load features
with open(FEATURES_PATH, "r") as f:
    data = json.load(f)


# Build feature vector in EXACT training order
X = [[data[feature] for feature in FEATURES]]

print("Feature vector:")
print(X[0])


# Load model
model = joblib.load(MODEL_PATH)


# Predict
prediction = model.predict(X)[0]

if prediction == 1:
    result = "MALICIOUS"
else:
    result = "BENIGN"


# Save prediction for C dashboard
with open(PREDICTION_PATH, "w") as f:
    f.write(result)


print()
print("==============================")
print("ML ANALYSIS")
print("==============================")
print("Prediction:", result)