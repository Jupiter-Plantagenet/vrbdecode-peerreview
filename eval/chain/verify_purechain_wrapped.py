#!/usr/bin/env python3
"""
Verify a wrapped VRBDecode proof on the Purechain testnet (remote RPC).

Purechain is described as gas-price-free, so by default we send with:
- --gas-price 0
- --priority-gas-price 0

Secrets:
- Do NOT hardcode or commit private keys.
- Provide the key via env var PURECHAIN_PRIVATE_KEY or CLI --private-key.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List


DEFAULT_RPC_URL = "http://3.34.161.207:8548"
PURECHAIN_CHAIN_ID = 900520900520


def _workspace_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _run(cmd: List[str], cwd: Path) -> int:
    p = subprocess.run(cmd, cwd=str(cwd))
    return int(p.returncode)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-dir", required=True)
    ap.add_argument("--rpc-url", default=os.environ.get("PURECHAIN_RPC_URL", DEFAULT_RPC_URL))
    ap.add_argument("--private-key", default=os.environ.get("PURECHAIN_PRIVATE_KEY", "").strip() or None)
    ap.add_argument("--private-key-file", default=os.environ.get("PURECHAIN_PRIVATE_KEY_FILE", "").strip() or None)
    ap.add_argument("--gas-limit", type=int, default=5_000_000)
    ap.add_argument("--gas-price", default="0")
    ap.add_argument("--priority-gas-price", default="0")
    ap.add_argument("--legacy", action="store_true")
    args = ap.parse_args()

    if not args.private_key and not args.private_key_file:
        raise SystemExit("missing Purechain private key (set PURECHAIN_PRIVATE_KEY or pass --private-key)")

    root = _workspace_root()
    verifier = root / "eval" / "chain" / "verify_anvil.py"
    if not verifier.exists():
        raise SystemExit(f"missing verifier script: {verifier}")

    env = dict(os.environ)
    if env.get("FOUNDRY_BIN", "").strip() == "":
        env["FOUNDRY_BIN"] = str(Path.home() / ".foundry" / "bin")

    cmd = [
        sys.executable,
        str(verifier),
        "--artifact-dir",
        args.artifact_dir,
        "--rpc-url",
        args.rpc_url,
        "--no-start-anvil",
        "--expected-chain-id",
        str(PURECHAIN_CHAIN_ID),
        "--evm-version",
        "paris",
        *(["--private-key", args.private_key] if args.private_key else ["--private-key-file", args.private_key_file]),
        "--chain-subdir",
        "chain_purechain",
        "--gas-limit",
        str(args.gas_limit),
        "--gas-price",
        str(args.gas_price),
        "--priority-gas-price",
        str(args.priority_gas_price),
    ]
    # Purechain reports no EIP-1559 support; use legacy tx mode.
    cmd.append("--legacy")

    p = subprocess.run(cmd, cwd=str(root), env=env)
    return int(p.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
