import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# =========================
# LOAD DATASET
# =========================

df = pd.read_csv("../dataset.csv")

print("Dataset shape:", df.shape)

# =========================
# FEATURES
# =========================

features = [
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

X = df[features]
y = df["label"]

# =========================
# TRAIN / TEST SPLIT
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))

# =========================
# MODEL
# =========================

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

# =========================
# TRAIN
# =========================

print("\nTraining model...")

model.fit(X_train, y_train)

# =========================
# PREDICTION
# =========================

y_pred = model.predict(X_test)

# =========================
# RESULTS
# =========================

accuracy = accuracy_score(y_test, y_pred)

print("\n==============================")
print("MODEL RESULTS")
print("==============================")

print(f"Accuracy: {accuracy:.4f}")

print("\nClassification report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "MALICIOUS"]
    )
)

print("Confusion matrix:")
print(confusion_matrix(y_test, y_pred))

# =========================
# FEATURE IMPORTANCE
# =========================

print("\nFeature importance:")

importance = pd.Series(
    model.feature_importances_,
    index=features
).sort_values(ascending=False)

print(importance)

# =========================
# SAVE MODEL
# =========================

joblib.dump(model, "syscall_model.pkl")

print("\nModel saved:")
print("syscall_model.pkl")
