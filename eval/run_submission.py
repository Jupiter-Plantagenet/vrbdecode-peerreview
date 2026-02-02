#!/usr/bin/env python3
"""
Submission runner: generate a wrapped proof, optionally verify on Anvil, and run baselines.

This is intended to produce a single run directory under `eval/artifacts/<run_id>/` with:
- pipeline outputs (Nova folding + Groth16 wrap)
- optional local EVM verification receipts
- baseline Groth16 batch-FCircuit measurements
- a consolidated `summary.json` for easy table/plot generation
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional


def _run(cmd: list[str], cwd: Path, env: Optional[Dict[str, str]] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        sys.stderr.write(f"\n[run_submission] command failed (rc={p.returncode}): {' '.join(cmd)}\n")
        if p.stdout:
            sys.stderr.write("[run_submission] --- stdout ---\n")
            sys.stderr.write(p.stdout + "\n")
        if p.stderr:
            sys.stderr.write("[run_submission] --- stderr ---\n")
            sys.stderr.write(p.stderr + "\n")
        raise SystemExit(p.returncode)
    return p.stdout.strip()


def _parse_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return int(s, 16)
            except Exception:
                return None
        # handle "1 (success)" style
        head = s.split()[0]
        try:
            return int(head)
        except Exception:
            return None
    return None


def _workspace_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _target_release(root: Path) -> Path:
    return root / "target" / "release"


def _ensure_built(root: Path, bins: list[str]) -> None:
    cmd = ["cargo", "build", "--release", "-p", "vrbdecode-zk"]
    for b in bins:
        cmd += ["--bin", b]
    _run(cmd, cwd=root)


def _pipeline_run(root: Path, *, k: int, n: int, run_id: str, verify_anvil: bool, env: Optional[Dict[str, str]] = None) -> Path:
    exe = _target_release(root) / "pipeline"
    cmd = [
        str(exe),
        "--k",
        str(k),
        "--n",
        str(n),
        "--run-id",
        run_id,
        "--force",
    ]
    if verify_anvil:
        cmd.append("--verify-anvil")
    out = _run(cmd, cwd=root, env=env)
    out_dir = Path(out.splitlines()[-1]).expanduser().resolve()
    if not out_dir.exists():
        raise SystemExit(f"[run_submission] pipeline did not produce an output dir: {out_dir}")
    return out_dir


def _baseline_run(root: Path, *, k: int, b: int, run_id: str) -> None:
    exe = _target_release(root) / "baseline_groth16_batch_fcircuit"
    _run([str(exe), "--k", str(k), "--b", str(b), "--run-id", run_id], cwd=root)

def _baseline_verify_anvil(root: Path, *, verifier_sol: Path, calldata_bin: Path, out_dir: Path, env: Dict[str, str]) -> None:
    script = root / "eval" / "chain" / "verify_groth16_anvil.py"
    if not script.exists():
        raise SystemExit(f"[run_submission] missing verifier script: {script}")
    _run(
        [
            sys.executable,
            str(script),
            "--verifier-sol",
            str(verifier_sol),
            "--calldata-bin",
            str(calldata_bin),
            "--out-dir",
            str(out_dir),
        ],
        cwd=root,
        env=env,
    )

def _verify_purechain_wrapped(root: Path, *, artifact_dir: Path, env: Dict[str, str]) -> None:
    script = root / "eval" / "chain" / "verify_purechain_wrapped.py"
    if not script.exists():
        raise SystemExit(f"[run_submission] missing Purechain wrapper: {script}")
    _run([sys.executable, str(script), "--artifact-dir", str(artifact_dir)], cwd=root, env=env)


def _verify_purechain_baseline(
    root: Path, *, verifier_sol: Path, calldata_bin: Path, out_dir: Path, env: Dict[str, str]
) -> None:
    script = root / "eval" / "chain" / "verify_purechain_groth16.py"
    if not script.exists():
        raise SystemExit(f"[run_submission] missing Purechain baseline wrapper: {script}")
    _run(
        [
            sys.executable,
            str(script),
            "--verifier-sol",
            str(verifier_sol),
            "--calldata-bin",
            str(calldata_bin),
            "--out-dir",
            str(out_dir),
        ],
        cwd=root,
        env=env,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True, help="Run ID under eval/artifacts/")
    ap.add_argument("--k", type=int, default=16, choices=[16, 32, 64])
    ap.add_argument("--n", type=int, default=2)
    ap.add_argument("--verify-anvil", action="store_true", help="Run local EVM verification (requires Foundry)")
    ap.add_argument(
        "--verify-baselines-anvil",
        action="store_true",
        help="Verify baseline Groth16 proofs on a local Anvil chain (requires Foundry)",
    )
    ap.add_argument(
        "--verify-purechain",
        action="store_true",
        help="Verify wrapped + baseline proofs on Purechain (requires PURECHAIN_PRIVATE_KEY_FILE env var)",
    )
    ap.add_argument(
        "--baseline-b",
        type=int,
        action="append",
        default=[],
        help="Baseline batch sizes to run (repeatable, e.g. --baseline-b 1 --baseline-b 8)",
    )
    args = ap.parse_args()

    root = _workspace_root()
    bins = ["pipeline", "baseline_groth16_batch_fcircuit"]
    _ensure_built(root, bins)

    env = dict(os.environ)
    if env.get("FOUNDRY_BIN", "").strip() == "":
        env["FOUNDRY_BIN"] = str(Path.home() / ".foundry" / "bin")

    if args.verify_purechain and (env.get("PURECHAIN_PRIVATE_KEY_FILE", "").strip() == ""):
        raise SystemExit("[run_submission] missing PURECHAIN_PRIVATE_KEY_FILE for --verify-purechain")

    out_dir = _pipeline_run(root, k=args.k, n=args.n, run_id=args.run_id, verify_anvil=args.verify_anvil, env=env)

    if args.verify_purechain:
        _verify_purechain_wrapped(root, artifact_dir=out_dir, env=env)

    baseline_bs = args.baseline_b or [1, 8, 16]
    for b in baseline_bs:
        if b <= 0:
            raise SystemExit("--baseline-b must be positive")
        _baseline_run(root, k=args.k, b=b, run_id=args.run_id)
        if args.verify_baselines_anvil:
            verifier_sol = out_dir / "baselines" / f"baseline_groth16_batch_fcircuit_k{args.k}_b{b}_verifier.sol"
            calldata_bin = out_dir / "baselines" / f"baseline_groth16_batch_fcircuit_k{args.k}_b{b}_calldata.bin"
            if not verifier_sol.exists() or not calldata_bin.exists():
                raise SystemExit(f"[run_submission] missing baseline verifier or calldata for k={args.k} b={b}")
            chain_out = out_dir / "baselines" / f"chain_k{args.k}_b{b}"
            _baseline_verify_anvil(root, verifier_sol=verifier_sol, calldata_bin=calldata_bin, out_dir=chain_out, env=env)
        if args.verify_purechain:
            verifier_sol = out_dir / "baselines" / f"baseline_groth16_batch_fcircuit_k{args.k}_b{b}_verifier.sol"
            calldata_bin = out_dir / "baselines" / f"baseline_groth16_batch_fcircuit_k{args.k}_b{b}_calldata.bin"
            if not verifier_sol.exists() or not calldata_bin.exists():
                raise SystemExit(f"[run_submission] missing baseline verifier or calldata for k={args.k} b={b}")
            chain_out = out_dir / "baselines" / f"chain_purechain_k{args.k}_b{b}"
            _verify_purechain_baseline(
                root, verifier_sol=verifier_sol, calldata_bin=calldata_bin, out_dir=chain_out, env=env
            )

    summary: Dict[str, Any] = {"run_id": args.run_id, "k": args.k, "n": args.n}

    def _file_size(path: Path) -> Optional[int]:
        try:
            return int(path.stat().st_size)
        except OSError:
            return None

    meta_path = out_dir / "meta.json"
    if meta_path.exists():
        summary["meta"] = json.loads(meta_path.read_text(encoding="utf-8"))

    wrapped_metrics_path = out_dir / "wrapped" / "wrapped_metrics.json"
    if wrapped_metrics_path.exists():
        summary["wrapped_metrics"] = json.loads(wrapped_metrics_path.read_text(encoding="utf-8"))

    summary["artifact_sizes_bytes"] = {
        "nova_ivc_proof_bin": _file_size(out_dir / "nova" / "ivc_proof.bin"),
        "wrapped_proof_bin": _file_size(out_dir / "wrapped" / "proof.bin"),
        "wrapped_calldata_bin": _file_size(out_dir / "wrapped" / "calldata.bin"),
        "wrapped_verifier_sol": _file_size(out_dir / "wrapped" / "verifier.sol"),
    }

    chain_dir = out_dir / "chain"
    deploy_path = chain_dir / "deploy.json"
    if deploy_path.exists():
        summary["chain_deploy"] = json.loads(deploy_path.read_text(encoding="utf-8"))

    verify_path = chain_dir / "verify_call.json"
    if verify_path.exists():
        verify = json.loads(verify_path.read_text(encoding="utf-8"))
        summary["chain_verify"] = verify
        summary["chain_verify_gas_used"] = _parse_int(verify.get("gasUsed"))
        summary["chain_verify_status"] = _parse_int(verify.get("status"))

    purechain_dir = out_dir / "chain_purechain"
    purechain_verify_path = purechain_dir / "verify_call.json"
    if purechain_verify_path.exists():
        verify = json.loads(purechain_verify_path.read_text(encoding="utf-8"))
        summary["purechain_verify"] = verify
        summary["purechain_verify_gas_used"] = _parse_int(verify.get("gasUsed"))
        summary["purechain_verify_status"] = _parse_int(verify.get("status"))
    purechain_chain_info = purechain_dir / "chain_info.json"
    if purechain_chain_info.exists():
        summary["purechain_info"] = json.loads(purechain_chain_info.read_text(encoding="utf-8"))

    baselines_dir = out_dir / "baselines"
    if baselines_dir.exists():
        baseline_docs: list[dict[str, Any]] = []
        for p in sorted(baselines_dir.glob("baseline_groth16_batch_fcircuit_*.json")):
            doc = json.loads(p.read_text(encoding="utf-8"))
            if args.verify_baselines_anvil and isinstance(doc, dict):
                k = int(doc.get("k", args.k))
                b = int(doc.get("batch_steps", 0))
                chain_verify_path = baselines_dir / f"chain_k{k}_b{b}" / "verify_call.json"
                if chain_verify_path.exists():
                    verify = json.loads(chain_verify_path.read_text(encoding="utf-8"))
                    doc["chain_verify"] = verify
                    doc["chain_verify_gas_used"] = _parse_int(verify.get("gasUsed"))
                    doc["chain_verify_status"] = _parse_int(verify.get("status"))
            if args.verify_purechain and isinstance(doc, dict):
                k = int(doc.get("k", args.k))
                b = int(doc.get("batch_steps", 0))
                chain_verify_path = baselines_dir / f"chain_purechain_k{k}_b{b}" / "verify_call.json"
                if chain_verify_path.exists():
                    verify = json.loads(chain_verify_path.read_text(encoding="utf-8"))
                    doc["purechain_verify"] = verify
                    doc["purechain_verify_gas_used"] = _parse_int(verify.get("gasUsed"))
                    doc["purechain_verify_status"] = _parse_int(verify.get("status"))
            baseline_docs.append(doc)
        summary["baselines"] = baseline_docs

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
