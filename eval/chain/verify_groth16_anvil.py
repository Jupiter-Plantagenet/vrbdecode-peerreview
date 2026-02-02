#!/usr/bin/env python3
"""
Verify a Groth16 proof on a local Anvil chain (Foundry).

Inputs:
- --verifier-sol: Solidity verifier (contract name: Groth16Verifier)
- --calldata-bin: ABI calldata bytes for calling `verifyProof(...)`

This script:
1) optionally starts `anvil`,
2) deploys the verifier contract with `forge create --broadcast` (unlocked or private-key),
3) calls the verifier using `cast call` and `cast send`,
4) runs a negative-control tamper check (by default),
5) writes deploy + call receipts into --out-dir (defaults to the verifier's directory).

Note: we set an explicit gas limit by default because some tool/node combinations can
badly underestimate gas for BN254 precompile-heavy calls, leading to a "status=1" tx that
returns `false` (and therefore a misleadingly-low `gasUsed`).
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
_ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")
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

def _rpc_json(rpc_url: str, method: str, *params: str) -> Any:
    cast_bin = _tool_path("cast")
    out = _run([cast_bin, "rpc", "--rpc-url", rpc_url, method, *params], cwd=Path.cwd())
    try:
        return json.loads(out)
    except Exception:
        return out


def _chain_id_int(rpc_url: str) -> int:
    v = _rpc_json(rpc_url, "eth_chainId")
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    if isinstance(v, int):
        return v
    raise RuntimeError(f"unexpected eth_chainId response: {v!r}")

def _chain_feature_info(rpc_url: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        info["rpc_modules"] = _rpc_json(rpc_url, "rpc_modules")
    except Exception as e:
        info["rpc_modules_error"] = str(e)

    try:
        blk = _rpc_json(rpc_url, "eth_getBlockByNumber", "latest", "false")
        if isinstance(blk, dict):
            info["latest_block_keys"] = sorted(list(blk.keys()))
            info["has_base_fee_per_gas"] = "baseFeePerGas" in blk
            info["has_withdrawals"] = "withdrawals" in blk or "withdrawalsRoot" in blk
            info["has_blob_fields"] = any(k in blk for k in ("blobGasUsed", "excessBlobGas"))
            info["block_difficulty"] = blk.get("difficulty")
            info["block_total_difficulty"] = blk.get("totalDifficulty")
        else:
            info["latest_block_raw"] = blk
    except Exception as e:
        info["latest_block_error"] = str(e)

    try:
        info["eth_maxPriorityFeePerGas"] = _rpc_json(rpc_url, "eth_maxPriorityFeePerGas")
    except Exception as e:
        info["eth_maxPriorityFeePerGas_error"] = str(e)
    try:
        info["eth_feeHistory"] = _rpc_json(rpc_url, "eth_feeHistory", "0x1", "latest", "[]")
    except Exception as e:
        info["eth_feeHistory_error"] = str(e)

    return info


def _eth_accounts(rpc_url: str) -> list[str]:
    cast_bin = _tool_path("cast")
    out = _run([cast_bin, "rpc", "--rpc-url", rpc_url, "eth_accounts"], cwd=Path.cwd())
    try:
        accounts = json.loads(out)
        if isinstance(accounts, list):
            return [str(a) for a in accounts]
    except Exception:
        pass
    raise RuntimeError(f"failed to parse eth_accounts response:\n{out}")

def _eth_get_transaction_by_hash(rpc_url: str, tx: str) -> Dict[str, Any]:
    cast_bin = _tool_path("cast")
    out = _run([cast_bin, "rpc", "--rpc-url", rpc_url, "eth_getTransactionByHash", tx], cwd=Path.cwd())
    try:
        return json.loads(out)
    except Exception as e:
        raise RuntimeError(f"failed to parse eth_getTransactionByHash output:\n{out}") from e


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


def _parse_cast_kv_output(out: str) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if ":" in s:
            k, v = s.split(":", 1)
            res[k.strip()] = v.strip()
            continue
        parts = s.split()
        if len(parts) >= 2:
            res[parts[0].strip()] = parts[1].strip()
    return res


def _parse_cast_send_tx_hash(out: str) -> str:
    for line in out.splitlines():
        l = line.lower().strip()
        if l.startswith("transaction:") or l.startswith("transactionhash") or "transaction hash" in l:
            m = _TX_RE.search(line)
            if m:
                return m.group(0)
    m = _TX_RE.search(out)
    if m:
        return m.group(0)
    toks = [t for t in out.split() if t.startswith("0x") and len(t) > 10]
    return toks[-1] if toks else ""

def _receipt_json_with_retries(rpc_url: str, tx: str, *, retries: int = 10, sleep_s: float = 0.2) -> Dict[str, Any]:
    cast_bin = _tool_path("cast")
    last_err: Optional[Exception] = None
    for _ in range(retries):
        try:
            receipt_json = _run(
                [cast_bin, "receipt", "--json", "--rpc-url", rpc_url, "--rpc-timeout", "180", tx],
                cwd=Path.cwd(),
            )
            return json.loads(receipt_json)
        except Exception as e:
            last_err = e
            time.sleep(sleep_s)
    raise RuntimeError(f"failed to fetch receipt via cast after {retries} retries: {tx}\nlast error: {last_err}")


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _deploy(
    tmp: Path,
    rpc_url: str,
    forge_bin: str,
    *,
    private_key: Optional[str],
    from_addr: Optional[str],
    gas_price: Optional[str],
    priority_gas_price: Optional[str],
    legacy: bool,
) -> Tuple[str, str, str]:
    out = _run(
        (
            [
                forge_bin,
                "create",
                "--rpc-url",
                rpc_url,
                "--broadcast",
            ]
            + (["--gas-price", gas_price] if gas_price else [])
            + (["--priority-gas-price", priority_gas_price] if priority_gas_price else [])
            + (["--legacy"] if legacy else [])
            + (["--private-key", private_key] if private_key else ["--unlocked", "--from", (from_addr or "")])
            + ["src/Groth16Verifier.sol:Groth16Verifier"]
        ),
        cwd=tmp,
    )
    addr, tx = _parse_forge_create_output(out)
    return addr, tx, out


def _call_calldata(rpc_url: str, to: str, calldata_hex: str, *, gas_limit: Optional[int] = None) -> Dict[str, Any]:
    cast_bin = _tool_path("cast")
    cmd = [cast_bin, "call", "--rpc-url", rpc_url]
    if gas_limit is not None:
        cmd += ["--gas-limit", str(gas_limit)]
    cmd += [to, calldata_hex]
    out = _run(cmd, cwd=Path.cwd())
    ok = False
    try:
        s = out.strip()
        if s.startswith("0x"):
            b = bytes.fromhex(s[2:])
            if len(b) >= 32:
                ok = int.from_bytes(b[-32:], "big") == 1
    except Exception:
        ok = False
    return {"cast_call_output": out, "ok": ok}

def _tamper_calldata(calldata_hex: str) -> str:
    """
    Flip one byte in calldata while keeping the 4-byte selector intact.
    This should cause Groth16 verification to fail (return false).
    """
    s = calldata_hex.strip()
    if s.startswith("0x"):
        s = s[2:]
    b = bytearray.fromhex(s)
    if len(b) <= 4:
        raise ValueError("calldata too short to tamper")
    idx = len(b) - 1
    if idx < 4:
        idx = 4
    b[idx] ^= 0x01
    return "0x" + bytes(b).hex()


def _send_calldata(
    rpc_url: str,
    to: str,
    calldata_hex: str,
    *,
    private_key: Optional[str],
    from_addr: Optional[str],
    gas_limit: Optional[int] = None,
    gas_price: Optional[str] = None,
    priority_gas_price: Optional[str] = None,
    legacy: bool = False,
) -> Dict[str, Any]:
    cast_bin = _tool_path("cast")
    cmd = [cast_bin, "send", "--rpc-url", rpc_url]
    if gas_price:
        cmd += ["--gas-price", gas_price]
    if priority_gas_price:
        cmd += ["--priority-gas-price", priority_gas_price]
    if legacy:
        cmd += ["--legacy"]
    if private_key:
        cmd += ["--private-key", private_key]
    else:
        if not from_addr:
            raise RuntimeError("missing --from address for unlocked send")
        cmd += ["--unlocked", "--from", from_addr]
    cmd += ["--rpc-timeout", "180"]
    if gas_limit is not None:
        cmd += ["--gas-limit", str(gas_limit)]
    cmd += [to, calldata_hex]
    out = _run(cmd, cwd=Path.cwd())
    tx = _parse_cast_send_tx_hash(out)
    if not tx:
        raise RuntimeError(f"failed to parse tx hash from cast send:\n{out}")
    kv = _parse_cast_kv_output(out)
    if kv.get("transactionHash"):
        tx = kv["transactionHash"]

    receipt = _receipt_json_with_retries(rpc_url, tx)
    receipt["cast_send_output"] = out
    receipt["tx_hash"] = tx
    return receipt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verifier-sol", required=True)
    ap.add_argument("--calldata-bin", required=True)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8545")
    ap.add_argument("--mnemonic", default=ANVIL_DEFAULT_MNEMONIC)
    ap.add_argument("--no-start-anvil", action="store_true")
    ap.add_argument(
        "--expected-chain-id",
        type=int,
        default=None,
        help="If set, abort unless eth_chainId matches this value",
    )
    ap.add_argument(
        "--evm-version",
        default="paris",
        help="Solidity compiler EVM version for Foundry (use 'paris' to avoid PUSH0 on pre-Shanghai chains)",
    )
    ap.add_argument(
        "--solc-version",
        default=None,
        help="Optional Solidity compiler version for Foundry (e.g. 0.8.19). If unset, Foundry auto-detects.",
    )
    ap.add_argument(
        "--gas-limit",
        type=int,
        default=5_000_000,
        help="Gas limit to use for eth_call + tx (workaround for bad gas estimation on some nodes)",
    )
    ap.add_argument("--gas-price", default=None)
    ap.add_argument("--priority-gas-price", default=None)
    ap.add_argument("--legacy", action="store_true")
    ap.add_argument("--private-key", default=None, help="Use a funded private key (hex) instead of unlocked accounts")
    ap.add_argument(
        "--private-key-file",
        default=None,
        help="Read private key (hex) from a file path (safer than passing via CLI/history)",
    )
    ap.add_argument("--from", dest="from_addr", default=None, help="From address for --unlocked (defaults to eth_accounts[0])")
    ap.add_argument(
        "--no-tamper-check",
        action="store_true",
        help="Skip negative control (tamper calldata and require verify=false)",
    )
    args = ap.parse_args()

    anvil_bin = _tool_path("anvil")
    forge_bin = _tool_path("forge")
    _tool_path("cast")

    verifier = Path(args.verifier_sol).resolve()
    calldata_bin = Path(args.calldata_bin).resolve()
    if not verifier.exists() or not calldata_bin.exists():
        raise SystemExit("missing --verifier-sol or --calldata-bin")

    out_dir = Path(args.out_dir).resolve() if args.out_dir else verifier.parent.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    anvil_proc: Optional[subprocess.Popen] = None
    if not args.no_start_anvil:
        anvil_proc = _start_anvil(args.rpc_url, anvil_bin, args.mnemonic)

    try:
        _wait_for_rpc(args.rpc_url)
        chain_id = _chain_id_int(args.rpc_url)
        if args.expected_chain_id is not None and chain_id != args.expected_chain_id:
            raise RuntimeError(f"unexpected chainId={chain_id} (expected {args.expected_chain_id})")
        _write_json(
            out_dir / "chain_info.json",
            {
                "rpc_url": args.rpc_url,
                "chain_id": chain_id,
                "client_version": _rpc_json(args.rpc_url, "web3_clientVersion"),
                "features": _chain_feature_info(args.rpc_url),
            },
        )
        private_key = (args.private_key or "").strip() or None
        if not private_key and args.private_key_file:
            private_key = Path(args.private_key_file).expanduser().read_text(encoding="utf-8").strip() or None
        from_addr = (args.from_addr or "").strip() or None
        if not private_key and not from_addr:
            accounts = _eth_accounts(args.rpc_url)
            if not accounts:
                raise RuntimeError("no accounts returned by eth_accounts")
            from_addr = accounts[0]

        with tempfile.TemporaryDirectory(prefix="vrbdecode_groth16_foundry_") as td:
            tmp = Path(td)
            (tmp / "src").mkdir(parents=True, exist_ok=True)
            cfg = (
                "[profile.default]\n"
                "src = 'src'\n"
                "out = 'out'\n"
                "libs = ['lib']\n"
                f"evm_version = '{args.evm_version}'\n"
            )
            if (args.solc_version or "").strip():
                cfg += f"solc_version = '{args.solc_version.strip()}'\n"
            (tmp / "foundry.toml").write_text(cfg, encoding="utf-8")
            (tmp / "src" / "Groth16Verifier.sol").write_text(verifier.read_text(encoding="utf-8"), encoding="utf-8")

            addr, deploy_tx, forge_out = _deploy(
                tmp,
                args.rpc_url,
                forge_bin,
                private_key=private_key,
                from_addr=from_addr,
                gas_price=(args.gas_price or "").strip() or None,
                priority_gas_price=(args.priority_gas_price or "").strip() or None,
                legacy=bool(args.legacy),
            )
            _write_json(
                out_dir / "deploy.json",
                {"rpc_url": args.rpc_url, "deployed_to": addr, "deploy_tx": deploy_tx, "from": from_addr, "forge_create_output": forge_out},
            )

            calldata_hex = "0x" + calldata_bin.read_bytes().hex()
            call_res = _call_calldata(args.rpc_url, addr, calldata_hex, gas_limit=args.gas_limit)
            _write_json(out_dir / "verify_call_result.json", call_res)
            if not call_res.get("ok", False):
                raise RuntimeError("eth_call returned false (Groth16 proof did not verify)")

            if not args.no_tamper_check:
                tampered = _tamper_calldata(calldata_hex)
                tamper_res = _call_calldata(args.rpc_url, addr, tampered, gas_limit=args.gas_limit)
                _write_json(out_dir / "tamper_call_result.json", tamper_res)
                if tamper_res.get("ok", False):
                    raise RuntimeError("tamper check failed (tampered calldata still verified=true)")

            receipt = _send_calldata(
                args.rpc_url,
                addr,
                calldata_hex,
                private_key=private_key,
                from_addr=from_addr,
                gas_limit=args.gas_limit,
                gas_price=(args.gas_price or "").strip() or None,
                priority_gas_price=(args.priority_gas_price or "").strip() or None,
                legacy=bool(args.legacy),
            )
            _write_json(out_dir / "verify_call.json", receipt)
            tx_hash = receipt.get("transactionHash") or receipt.get("tx_hash")
            if isinstance(tx_hash, str) and tx_hash.startswith("0x") and len(tx_hash) == 66:
                tx_doc = _eth_get_transaction_by_hash(args.rpc_url, tx_hash)
                _write_json(out_dir / "verify_tx.json", tx_doc)
            status = receipt.get("status")
            if status not in (1, "1", "0x1", True, "1 (success)"):
                raise RuntimeError(f"on-chain transaction failed (status={status})")
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
