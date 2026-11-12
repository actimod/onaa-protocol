#!/usr/bin/env bash
# Run the ONAA direct-trade demo (ONAA Protocol v0.1) end to end on ephemeral localhost ports.
# SAMPLE buyer/seller, MOCK escrow, no real funds, no external network calls
# (pip install aside). Ephemeral in-memory signing keys only.
# Optional: REGISTRY_URL=https://... to search a real registry instead of the local stub (read-only).
#
#   examples/direct-trade-demo/scripts/run_demo.sh            # create .venv, install, run
#   SKIP_INSTALL=1 examples/direct-trade-demo/scripts/run_demo.sh
#   RUN_TESTS=1 examples/direct-trade-demo/scripts/run_demo.sh
#   RUN_CONFORMANCE=1 examples/direct-trade-demo/scripts/run_demo.sh   # also run the live conformance suite
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTOCOL_PKG="$(cd "$HERE/../../packages/onaa-protocol" && pwd)"
PY="${PYTHON:-python3}"
VENV="${VENV:-$HERE/.venv}"

if [[ "${SKIP_INSTALL:-0}" != "1" ]]; then
  if [[ ! -x "$VENV/bin/python" ]]; then
    "$PY" -m venv "$VENV"
  fi
  # Local package first: onaa-protocol is unpublished and intentionally not a declared dependency.
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check -e "$PROTOCOL_PKG"
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check -e "$HERE[dev]"
fi
RUN_PY="$VENV/bin/python"
[[ -x "$RUN_PY" ]] || RUN_PY="$PY"

if [[ "${RUN_TESTS:-0}" == "1" ]]; then
  (cd "$HERE" && "$RUN_PY" -m pytest -q)
fi

"$RUN_PY" -c "import onaa_protocol" 2>/dev/null || {
  echo "onaa_protocol not installed: pip install -e $PROTOCOL_PKG" >&2; exit 2; }

# Loopback is allowed ONLY for this demo run; non-demo mode requires public https endpoints.
export ONAA_DEMO_ALLOW_LOCALHOST=1
if [[ "${RUN_CONFORMANCE:-0}" == "1" ]]; then
  (cd "$HERE" && "$RUN_PY" -m pytest -q tests/test_conformance_live.py)
fi
exec "$RUN_PY" -m onaa_demo.demo
