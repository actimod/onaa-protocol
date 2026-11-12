#!/usr/bin/env bash
# Run the ONAA direct-trade demo end to end on ephemeral localhost ports.
# SAMPLE seller, MOCK escrow, no real funds, no external network calls
# (pip install aside). Optional: REGISTRY_URL=https://... to search a real
# registry instead of the local stub (read-only).
#
#   examples/direct-trade-demo/scripts/run_demo.sh            # create .venv, install, run
#   SKIP_INSTALL=1 examples/direct-trade-demo/scripts/run_demo.sh
#   RUN_TESTS=1 examples/direct-trade-demo/scripts/run_demo.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
VENV="${VENV:-$HERE/.venv}"

if [[ "${SKIP_INSTALL:-0}" != "1" ]]; then
  if [[ ! -x "$VENV/bin/python" ]]; then
    "$PY" -m venv "$VENV"
  fi
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check -e "$HERE[dev]"
fi
RUN_PY="$VENV/bin/python"
[[ -x "$RUN_PY" ]] || RUN_PY="$PY"

if [[ "${RUN_TESTS:-0}" == "1" ]]; then
  (cd "$HERE" && "$RUN_PY" -m pytest -q)
fi

# Loopback is allowed ONLY for this demo run; non-demo mode requires public https endpoints.
export ONAA_DEMO_ALLOW_LOCALHOST=1
exec "$RUN_PY" -m onaa_demo.demo
