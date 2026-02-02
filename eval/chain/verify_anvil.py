#!/usr/bin/env python3
"""
Verify a VRBDecode wrapped proof on an EVM JSON-RPC endpoint (Foundry).

Inputs:
- An artifact directory produced by `cargo run -p vrbdecode-zk --bin pipeline ...` containing:
  - wrapped/verifier.sol
  - wrapped/calldata.bin

This script:
1) optionally starts `anvil`,
2) deploys the verifier contract with `forge create` (unlocked or private-key),
3) calls the verifier using `cast send` with calldata bytes,
4) writes deploy + call receipts into the artifact directory under `<chain-subdir>/`.

For remote chains, pass `--no-start-anvil` and set `--rpc-url`.
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


def _run(cmd: list[str], cwd: Path, env: Optional[Dict[str, str]] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"command failed (rc={p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p.stdout.strip()


def _tool_path(name: str) -> str:
    """
    Resolve a Foundry tool executable.

    Search order:
    1) PATH
    2) $FOUNDRY_BIN/<name>
    3) ~/.foundry/bin/<name>
    """
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
        # naive parse: http://host:port
        rest = rpc_url.split("://", 1)[1]
        if ":" in rest:
            host, port = rest.split(":", 1)

    p = subprocess.Popen(
        [anvil_bin, "--host", host, "--port", port, "--silent", "--mnemonic", mnemonic],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return p


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


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
        # Some cast rpc methods return a raw JSON scalar (e.g., "0x1"); json.loads handles that.
        # If it's not JSON, keep as string.
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
    # modules (useful for consensus hints like clique)
    try:
        info["rpc_modules"] = _rpc_json(rpc_url, "rpc_modules")
    except Exception as e:
        info["rpc_modules_error"] = str(e)

    # latest block fields -> infer hardfork-era features
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

    # EIP-1559-related RPCs existence (not sufficient to prove tx-type support)
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
            # cast often prints "key <spaces> value (extra...)".
            res[parts[0].strip()] = parts[1].strip()
    return res


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


def _deploy(
    tmp: Path,
    rpc_url: str,
    *,
    forge_bin: str,
    private_key: Optional[str],
    from_addr: Optional[str],
    gas_price: Optional[str],
    priority_gas_price: Optional[str],
    legacy: bool,
) -> Tuple[str, str, str]:
    cmd = [forge_bin, "create", "--rpc-url", rpc_url, "--broadcast"]
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
            raise RuntimeError("missing --from address for unlocked deploy")
        cmd += ["--unlocked", "--from", from_addr]
    cmd.append("src/NovaDecider.sol:NovaDecider")

    out = _run(cmd, cwd=tmp)
    addr, tx = _parse_forge_create_output(out)
    return addr, tx, out


def _send_calldata(
    rpc_url: str,
    *,
    private_key: Optional[str],
    from_addr: Optional[str],
    to: str,
    calldata_hex: str,
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
    cmd += ["--rpc-timeout", "180", "--timeout", "180"]
    if gas_limit is not None:
        cmd += ["--gas-limit", str(gas_limit)]
    cmd += [to, calldata_hex]
    out = _run(cmd, cwd=Path.cwd())
    # `cast send` prints a receipt-like output; we also fetch the receipt as JSON.
    # Use `cast receipt --json <txhash>` to get stable fields.
    tx = _parse_cast_send_tx_hash(out)
    if not tx:
        raise RuntimeError(f"failed to parse tx hash from cast send:\n{out}")

    receipt = _receipt_json_with_retries(rpc_url, tx)
    receipt["cast_send_output"] = out
    receipt["tx_hash"] = tx
    return receipt


def _call_calldata(rpc_url: str, to: str, calldata_hex: str, *, gas_limit: Optional[int] = None) -> Dict[str, Any]:
    cast_bin = _tool_path("cast")
    cmd = [cast_bin, "call", "--rpc-url", rpc_url]
    if gas_limit is not None:
        cmd += ["--gas-limit", str(gas_limit)]
    cmd += [to, calldata_hex]
    out = _run(cmd, cwd=Path.cwd())
    # Expected ABI encoding for `bool` is 32 bytes where last bit is 1.
    ok = False
    try:
        s = out.strip()
        if s.startswith("0x"):
            b = bytes.fromhex(s[2:])
            if len(b) >= 32:
                word = b[-32:]
                ok = int.from_bytes(word, "big") == 1
    except Exception:
        ok = False
    return {"cast_call_output": out, "ok": ok}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-dir", required=True)
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8545")
    ap.add_argument(
        "--chain-subdir",
        default="chain",
        help="Subdirectory under the artifact dir to write receipts (e.g. chain_purechain)",
    )
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
        help="Gas limit to use for eth_call + tx (makes receipts comparable across tools)",
    )
    ap.add_argument(
        "--gas-price",
        default=None,
        help="Gas price (legacy) or max fee per gas (EIP-1559); pass 0 for gas-price-free testnets",
    )
    ap.add_argument(
        "--priority-gas-price",
        default=None,
        help="Priority fee per gas for EIP-1559; pass 0 for gas-price-free testnets",
    )
    ap.add_argument("--legacy", action="store_true", help="Send legacy (non-EIP-1559) transactions")
    ap.add_argument(
        "--private-key",
        default=None,
        help="Use a funded private key (hex) instead of Anvil unlocked accounts",
    )
    ap.add_argument(
        "--private-key-file",
        default=None,
        help="Read private key (hex) from a file path (safer than passing via CLI/history)",
    )
    ap.add_argument(
        "--from",
        dest="from_addr",
        default=None,
        help="From address to use with --unlocked (defaults to eth_accounts[0])",
    )
    ap.add_argument(
        "--mnemonic",
        default=ANVIL_DEFAULT_MNEMONIC,
        help="Mnemonic used when starting Anvil (ignored with --no-start-anvil)",
    )
    ap.add_argument("--no-start-anvil", action="store_true", help="Use an already-running node at --rpc-url")
    args = ap.parse_args()

    anvil_bin = _tool_path("anvil")
    forge_bin = _tool_path("forge")
    _tool_path("cast")

    artifact_dir = Path(args.artifact_dir).resolve()
    verifier = artifact_dir / "wrapped" / "verifier.sol"
    calldata_bin = artifact_dir / "wrapped" / "calldata.bin"
    if not verifier.exists() or not calldata_bin.exists():
        raise SystemExit("artifact dir missing wrapped/verifier.sol or wrapped/calldata.bin")

    chain_dir = artifact_dir / args.chain_subdir
    chain_dir.mkdir(parents=True, exist_ok=True)

    anvil_proc: Optional[subprocess.Popen] = None
    if not args.no_start_anvil:
        anvil_proc = _start_anvil(args.rpc_url, anvil_bin, args.mnemonic)

    try:
        _wait_for_rpc(args.rpc_url)
        chain_id = _chain_id_int(args.rpc_url)
        if args.expected_chain_id is not None and chain_id != args.expected_chain_id:
            raise RuntimeError(f"unexpected chainId={chain_id} (expected {args.expected_chain_id})")
        _write_json(
            chain_dir / "chain_info.json",
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
                raise RuntimeError("no accounts returned by eth_accounts; provide --private-key or --from")
            from_addr = accounts[0]

        with tempfile.TemporaryDirectory(prefix="vrbdecode_foundry_") as td:
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
            # Sonobe template expects contract name `NovaDecider`
            (tmp / "src" / "NovaDecider.sol").write_text(verifier.read_text(encoding="utf-8"), encoding="utf-8")

            addr, deploy_tx, forge_create_output = _deploy(
                tmp,
                args.rpc_url,
                forge_bin=forge_bin,
                private_key=private_key,
                from_addr=from_addr,
                gas_price=(args.gas_price or "").strip() or None,
                priority_gas_price=(args.priority_gas_price or "").strip() or None,
                legacy=bool(args.legacy),
            )
            _write_json(
                chain_dir / "deploy.json",
                {
                    "rpc_url": args.rpc_url,
                    "deployed_to": addr,
                    "deploy_tx": deploy_tx,
                    "tx_mode": "private_key" if private_key else "unlocked",
                    "from": from_addr,
                    "forge_create_output": forge_create_output,
                },
            )

            calldata_hex = "0x" + calldata_bin.read_bytes().hex()
            call_res = _call_calldata(args.rpc_url, addr, calldata_hex, gas_limit=args.gas_limit)
            _write_json(chain_dir / "verify_call_result.json", call_res)
            if not call_res.get("ok", False):
                raise RuntimeError("on-chain eth_call returned false (proof did not verify)")
            receipt = _send_calldata(
                args.rpc_url,
                private_key=private_key,
                from_addr=from_addr,
                to=addr,
                calldata_hex=calldata_hex,
                gas_limit=args.gas_limit,
                gas_price=(args.gas_price or "").strip() or None,
                priority_gas_price=(args.priority_gas_price or "").strip() or None,
                legacy=bool(args.legacy),
            )
            _write_json(chain_dir / "verify_call.json", receipt)
            tx_hash = receipt.get("transactionHash") or receipt.get("tx_hash")
            if isinstance(tx_hash, str) and tx_hash.startswith("0x") and len(tx_hash) == 66:
                tx_doc = _eth_get_transaction_by_hash(args.rpc_url, tx_hash)
                _write_json(chain_dir / "verify_tx.json", tx_doc)
            status = receipt.get("status")
            if status not in (1, "1", "0x1", True):
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
