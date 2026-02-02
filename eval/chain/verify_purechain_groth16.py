#!/usr/bin/env python3
"""
Verify a baseline Groth16 proof on the Purechain testnet (remote RPC).

Inputs:
- --verifier-sol: Solidity verifier (Groth16Verifier)
- --calldata-bin: calldata bytes

Secrets:
- Provide PURECHAIN_PRIVATE_KEY via env var or --private-key.
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


def _run(cmd: List[str], cwd: Path, env: dict) -> int:
    p = subprocess.run(cmd, cwd=str(cwd), env=env)
    return int(p.returncode)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verifier-sol", required=True)
    ap.add_argument("--calldata-bin", required=True)
    ap.add_argument("--out-dir", default=None)
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
    verifier = root / "eval" / "chain" / "verify_groth16_anvil.py"
    if not verifier.exists():
        raise SystemExit(f"missing verifier script: {verifier}")

    env = dict(os.environ)
    if env.get("FOUNDRY_BIN", "").strip() == "":
        env["FOUNDRY_BIN"] = str(Path.home() / ".foundry" / "bin")

    cmd = [
        sys.executable,
        str(verifier),
        "--verifier-sol",
        args.verifier_sol,
        "--calldata-bin",
        args.calldata_bin,
        "--rpc-url",
        args.rpc_url,
        "--no-start-anvil",
        "--expected-chain-id",
        str(PURECHAIN_CHAIN_ID),
        "--evm-version",
        "paris",
        *(["--private-key", args.private_key] if args.private_key else ["--private-key-file", args.private_key_file]),
        "--gas-limit",
        str(args.gas_limit),
        "--gas-price",
        str(args.gas_price),
        "--priority-gas-price",
        str(args.priority_gas_price),
    ]
    if args.out_dir:
        cmd += ["--out-dir", args.out_dir]
    # Purechain reports no EIP-1559 support; use legacy tx mode.
    cmd.append("--legacy")

    return _run(cmd, cwd=root, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
