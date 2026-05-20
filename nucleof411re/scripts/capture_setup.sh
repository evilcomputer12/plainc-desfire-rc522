#!/usr/bin/env bash
# Capture serial log while running df setup. Close other serial clients first (screen, etc.).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.venv-serial"
PORT="${1:-/dev/cu.usbmodem1443203}"

if ! python3 -c "import serial" 2>/dev/null; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q pyserial
  PY="$VENV/bin/python"
else
  PY=python3
fi

exec "$PY" "$ROOT/scripts/capture_setup.py" "$PORT" -o "$ROOT/scripts/last_setup.log"
