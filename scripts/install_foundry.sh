#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
fi

if ! command -v foundryup >/dev/null 2>&1; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "missing curl (required to install Foundry)" >&2
    exit 1
  fi
  curl -L https://foundry.paradigm.xyz | bash
  export PATH="$HOME/.foundry/bin:$PATH"
fi

foundryup

echo "Foundry installed:"
"$HOME/.foundry/bin/anvil" --version
"$HOME/.foundry/bin/forge" --version
"$HOME/.foundry/bin/cast" --version
