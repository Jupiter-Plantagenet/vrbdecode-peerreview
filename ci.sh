#!/usr/bin/env bash
set -euo pipefail
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

# In the peer-review export repo, paper sources must not be present.
if [[ -f "EXPORT_METADATA.txt" ]]; then
  if [[ -d "paper" ]]; then
    echo "ERROR: peer-review repo must not contain ./paper/" >&2
    exit 1
  fi
fi

run_pytests() {
  local py="$1"
  if "$py" -c "import pytest" >/dev/null 2>&1; then
    "$py" -m pytest -q
    return 0
  fi
  echo "WARN: pytest not installed; skipping Python tests. Install with: python3 -m pip install -r requirements-dev.txt" >&2
  return 0
}

if command -v python3 >/dev/null 2>&1; then
  run_pytests python3
elif command -v python >/dev/null 2>&1; then
  run_pytests python
fi
cargo test -p vrbdecode-core -p vrbdecode-zk --quiet

if [[ "${VRBDECODE_CI_SLOW:-0}" == "1" ]]; then
  cargo test -p vrbdecode-zk --test groth16_smoke -- --ignored
  cargo test -p vrbdecode-zk --test r1cs_vectors -- --ignored
fi
