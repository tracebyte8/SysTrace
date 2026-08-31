#!/bin/bash

set -e

TARGET="$1"

echo "======================================"
echo "        SysTrace Configuration"
echo "======================================"

# -------------------------
# Check target argument
# -------------------------

if [ -z "$TARGET" ]; then
    echo "Usage:"
    echo "  ./config.sh <target>"
    echo
    echo "Example:"
    echo "  ./config.sh ./tests/bin/mal_fileopen"
    exit 1
fi

if [ ! -f "$TARGET" ]; then
    echo "ERROR: Target not found: $TARGET"
    exit 1
fi

# -------------------------
# Check required commands
# -------------------------

echo "[1/5] Checking dependencies..."

command -v gcc >/dev/null || {
    echo "ERROR: gcc is not installed."
    exit 1
}

command -v make >/dev/null || {
    echo "ERROR: make is not installed."
    exit 1
}

command -v python3 >/dev/null || {
    echo "ERROR: python3 is not installed."
    exit 1
}

echo "Dependencies OK."

# -------------------------
# Python virtual environment
# -------------------------

echo "[2/5] Setting up Python environment..."

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "[3/5] Installing Python dependencies..."

python -m pip install --upgrade pip

if [ -f "ml/requirements.txt" ]; then
    pip install -r ml/requirements.txt
else
    pip install numpy scikit-learn joblib
fi

# -------------------------
# Build SysTrace
# -------------------------

echo "[4/5] Building SysTrace..."

make clean
make

# -------------------------
# Run
# -------------------------

echo "[5/5] Starting SysTrace..."

echo
echo "======================================"
echo " Target: $TARGET"
echo "======================================"
echo

./linux_syscall_monitor "$TARGET"
