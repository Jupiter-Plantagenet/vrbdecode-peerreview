#!/usr/bin/env python3
"""
Probe EVM gas costs for BN254 precompiles on a local Anvil node.

This is a diagnostics script to explain suspiciously-low Groth16 verifier gas.
It deploys a tiny contract that calls:
- precompile 0x07 (ECMUL)
- precompile 0x06 (ECADD)
and reports gas deltas measured via gasleft() around the staticcall loops.

Outputs (in --out-dir):
- deploy.json
- probe_call.json          (decoded gas deltas)
- probe_call_raw.json      (raw cast output)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


ANVIL_DEFAULT_MNEMONIC = "test test test test test test test test test test test junk"
DEFAULT_FOUNDRY_BIN = Path.home() / ".foundry" / "bin"
_TX_RE = re.compile(r"0x[a-fA-F0-9]{64}")


def _run(cmd: list[str], cwd: Path) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"command failed (rc={p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p.stdout.strip()


def _tool_path(name: str) -> str:
    p = shutil.which(name)
    if p:
        return p
    env_bin = os.environ.get("FOUNDRY_BIN", "").strip()
    if env_bin:
        cand = Path(env_bin) / name
        if cand.exists():
            return str(cand)
    cand = DEFAULT_FOUNDRY_BIN / name
    if cand.exists():
        return str(cand)
    raise SystemExit(f"missing required tool: {name} (install Foundry)")


def _start_anvil(rpc_url: str, anvil_bin: str, mnemonic: str) -> subprocess.Popen:
    host = "127.0.0.1"
    port = "8545"
    if rpc_url.startswith("http://") or rpc_url.startswith("https://"):
        rest = rpc_url.split("://", 1)[1]
        if ":" in rest:
            host, port = rest.split(":", 1)
    return subprocess.Popen(
        [anvil_bin, "--host", host, "--port", port, "--silent", "--mnemonic", mnemonic],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for_rpc(rpc_url: str, timeout_s: float = 5.0) -> None:
    cast_bin = _tool_path("cast")
    start = time.time()
    while True:
        try:
            _run([cast_bin, "rpc", "--rpc-url", rpc_url, "web3_clientVersion"], cwd=Path.cwd())
            return
        except Exception:
            if time.time() - start > timeout_s:
                raise RuntimeError(f"anvil RPC did not become ready within {timeout_s}s ({rpc_url})")
            time.sleep(0.15)


def _eth_accounts(rpc_url: str) -> list[str]:
    cast_bin = _tool_path("cast")
    out = _run([cast_bin, "rpc", "--rpc-url", rpc_url, "eth_accounts"], cwd=Path.cwd())
    accounts = json.loads(out)
    if isinstance(accounts, list):
        return [str(a) for a in accounts]
    raise RuntimeError(f"failed to parse eth_accounts response:\n{out}")


def _parse_forge_create_output(out: str) -> Tuple[str, str]:
    addr = ""
    tx = ""
    for line in out.splitlines():
        if not addr and "Deployed to:" in line:
            cand = line.split("Deployed to:", 1)[1].strip().split()[0]
            if re.fullmatch(r"0x[a-fA-F0-9]{40}", cand):
                addr = cand
        if not tx and "Transaction hash:" in line:
            cand = line.split("Transaction hash:", 1)[1].strip().split()[0]
            if re.fullmatch(r"0x[a-fA-F0-9]{64}", cand):
                tx = cand
    if not addr or not tx:
        raise RuntimeError(f"failed to parse forge create output:\n{out}")
    return addr, tx


def _parse_cast_call_u256s(out: str, n_words: int) -> list[int]:
    s = out.strip()
    if s.startswith("0x"):
        b = bytes.fromhex(s[2:])
        if len(b) < 32 * n_words:
            raise ValueError(f"expected >= {n_words} words, got {len(b)} bytes")
        res: list[int] = []
        for i in range(n_words):
            word = b[i * 32 : (i + 1) * 32]
            res.append(int.from_bytes(word, "big"))
        return res

    # When an output signature is provided, cast may pretty-print one value per line:
    #   12345 [1.235e4]
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(lines) < n_words:
        raise ValueError(f"unexpected cast call output (need {n_words} lines): {out}")
    res = []
    for ln in lines[:n_words]:
        head = ln.split()[0]
        res.append(int(head, 10))
    return res


PROBE_SOL = r"""
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract PrecompileGasProbe {
    // BN254 G1 generator.
    uint256 constant GX = 1;
    uint256 constant GY = 2;

    function probe(uint256 n) external view returns (uint256 ecmul_gas, uint256 ecadd_gas) {
        ecmul_gas = _probeEcmul(n);
        ecadd_gas = _probeEcadd(n);
    }

    function _probeEcmul(uint256 n) internal view returns (uint256 spent) {
        uint256 g0 = gasleft();
        bytes memory input = new bytes(96);
        assembly {
            mstore(add(input, 32), GX)
            mstore(add(input, 64), GY)
            mstore(add(input, 96), 2)
        }
        for (uint256 i = 0; i < n; i++) {
            bool ok;
            bytes memory out = new bytes(64);
            assembly {
                ok := staticcall(gas(), 7, add(input, 32), 96, add(out, 32), 64)
            }
            require(ok, "ecmul failed");
        }
        uint256 g1 = gasleft();
        spent = g0 - g1;
    }

    function _probeEcadd(uint256 n) internal view returns (uint256 spent) {
        uint256 g0 = gasleft();
        bytes memory input = new bytes(128);
        assembly {
            mstore(add(input, 32), GX)
            mstore(add(input, 64), GY)
            mstore(add(input, 96), GX)
            mstore(add(input, 128), GY)
        }
        for (uint256 i = 0; i < n; i++) {
            bool ok;
            bytes memory out = new bytes(64);
            assembly {
                ok := staticcall(gas(), 6, add(input, 32), 128, add(out, 32), 64)
            }
            require(ok, "ecadd failed");
        }
        uint256 g1 = gasleft();
        spent = g0 - g1;
    }
}
"""


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8545")
    ap.add_argument("--mnemonic", default=ANVIL_DEFAULT_MNEMONIC)
    ap.add_argument("--no-start-anvil", action="store_true")
    ap.add_argument("--n", type=int, default=10, help="Loop count for each precompile call")
    args = ap.parse_args()

    anvil_bin = _tool_path("anvil")
    forge_bin = _tool_path("forge")
    cast_bin = _tool_path("cast")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    anvil_proc: Optional[subprocess.Popen] = None
    if not args.no_start_anvil:
        anvil_proc = _start_anvil(args.rpc_url, anvil_bin, args.mnemonic)

    try:
        _wait_for_rpc(args.rpc_url)
        accounts = _eth_accounts(args.rpc_url)
        if not accounts:
            raise RuntimeError("no accounts returned by eth_accounts")
        from_addr = accounts[0]

        with tempfile.TemporaryDirectory(prefix="vrbdecode_precompile_probe_") as td:
            tmp = Path(td)
            (tmp / "src").mkdir(parents=True, exist_ok=True)
            (tmp / "foundry.toml").write_text(
                "[profile.default]\n"
                "src = 'src'\n"
                "out = 'out'\n"
                "libs = ['lib']\n",
                encoding="utf-8",
            )
            (tmp / "src" / "PrecompileGasProbe.sol").write_text(PROBE_SOL, encoding="utf-8")

            out = _run(
                [
                    forge_bin,
                    "create",
                    "--rpc-url",
                    args.rpc_url,
                    "--broadcast",
                    "--unlocked",
                    "--from",
                    from_addr,
                    "src/PrecompileGasProbe.sol:PrecompileGasProbe",
                ],
                cwd=tmp,
            )
            addr, tx = _parse_forge_create_output(out)
            _write_json(
                out_dir / "deploy.json",
                {"rpc_url": args.rpc_url, "deployed_to": addr, "deploy_tx": tx, "from": from_addr, "forge_create_output": out},
            )

            # probe(uint256) returns (uint256,uint256)
            call_out = _run(
                [
                    cast_bin,
                    "call",
                    "--rpc-url",
                    args.rpc_url,
                    addr,
                    "probe(uint256)(uint256,uint256)",
                    str(args.n),
                ],
                cwd=Path.cwd(),
            )
            _write_json(out_dir / "probe_call_raw.json", {"cast_call_output": call_out})
            ecmul_gas, ecadd_gas = _parse_cast_call_u256s(call_out, 2)
            _write_json(out_dir / "probe_call.json", {"n": args.n, "ecmul_gas": ecmul_gas, "ecadd_gas": ecadd_gas})

    finally:
        if anvil_proc is not None:
            anvil_proc.terminate()
            try:
                anvil_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                anvil_proc.kill()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
