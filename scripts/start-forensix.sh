#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
ADB_PATH="${FORENSIX_ADB_PATH:-$(command -v adb || true)}"
API_PORT="${FORENSIX_API_PORT:-8765}"
WEB_PORT="${FORENSIX_WEB_PORT:-5173}"
LOG_DIR="$ROOT/data/logs"

[[ -x "$PYTHON" ]] || { echo "Python environment missing: $PYTHON" >&2; exit 1; }
command -v pnpm >/dev/null || { echo "pnpm is not installed." >&2; exit 1; }
[[ -n "$ADB_PATH" && -x "$ADB_PATH" ]] || { echo "ADB is missing; set FORENSIX_ADB_PATH." >&2; exit 1; }
"$ADB_PATH" version | grep -q "Android Debug Bridge version" || { echo "ADB version check failed." >&2; exit 1; }

mkdir -p "$LOG_DIR"
export FORENSIX_ADB_MODE=system
export FORENSIX_ADB_PATH="$ADB_PATH"

if ! curl --silent --fail "http://127.0.0.1:$API_PORT/health/live" >/dev/null 2>&1; then
  nohup "$PYTHON" -m uvicorn forensix_api.main:app --host 127.0.0.1 --port "$API_PORT" >"$LOG_DIR/api.out.log" 2>"$LOG_DIR/api.err.log" &
  echo $! >"$LOG_DIR/api.pid"
fi
if ! curl --silent --fail "http://127.0.0.1:$WEB_PORT" >/dev/null 2>&1; then
  nohup pnpm --dir "$ROOT/apps/web" dev --host 127.0.0.1 --port "$WEB_PORT" >"$LOG_DIR/web.out.log" 2>"$LOG_DIR/web.err.log" &
  echo $! >"$LOG_DIR/web.pid"
fi

for _ in $(seq 1 40); do
  if curl --silent --fail "http://127.0.0.1:$API_PORT/health/live" >/dev/null && curl --silent --fail "http://127.0.0.1:$WEB_PORT" >/dev/null; then
    echo "ForensiX ready at http://127.0.0.1:$WEB_PORT/devices"
    echo "Logs: $LOG_DIR"
    exit 0
  fi
  sleep 0.5
done
echo "ForensiX failed to start; inspect $LOG_DIR." >&2
exit 1
