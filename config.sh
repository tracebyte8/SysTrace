#!/bin/bash

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="$1"
VENV="$ROOT_DIR/.venv"

echo "======================================"
echo "        SysTrace Configuration"
echo "======================================"

if [ -z "$TARGET" ]; then
    echo "Usage:"
    echo "  ./config.sh <target>"
    echo
    echo "Example:"
    echo "  ./config.sh ./tests/bin/mal_fileopen"
    exit 1
fi

if [ ! -f "$ROOT_DIR/$TARGET" ] && [ ! -f "$TARGET" ]; then
    echo "ERROR: Target not found: $TARGET"
    exit 1
fi

if [[ "$TARGET" != /* ]]; then
    TARGET="$ROOT_DIR/$TARGET"
fi

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

echo "[2/5] Setting up Python environment..."

if [ ! -x "$VENV/bin/python3" ]; then
    rm -rf "$VENV"
    python3 -m venv "$VENV"
fi

echo "[3/5] Installing Python dependencies..."

"$VENV/bin/python3" -m pip install --upgrade pip

if [ -f "$ROOT_DIR/ml/requirements.txt" ]; then
    "$VENV/bin/python3" -m pip install -r "$ROOT_DIR/ml/requirements.txt"
else
    "$VENV/bin/python3" -m pip install numpy scikit-learn joblib
fi

"$VENV/bin/python3" -c "import numpy, sklearn, joblib; print('Python ML dependencies OK')"

echo "[4/5] Building SysTrace..."

cd "$ROOT_DIR"

make clean
make

echo "[5/5] Starting SysTrace..."

echo
echo "======================================"
echo " Target: $TARGET"
echo " Python: $VENV/bin/python3"
echo "======================================"
echo

# Make python3 resolve to the virtual environment.
export PATH="$VENV/bin:$PATH"

./linux_syscall_monitor "$TARGET"
if [ -f "$ROOT_DIR/security_report.html" ]; then
    xdg-open "$ROOT_DIR/security_report.html" >/dev/null 2>&1 &
fi