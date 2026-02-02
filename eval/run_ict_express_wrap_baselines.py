#!/usr/bin/env python3
"""
ICT Express submission-side metrics: wrapped SNARK + local EVM verify + baselines.

This script is designed to complement `eval/run_ict_express.py` (which focuses on step/folding
microbenchmarks with repetitions). Here we run:
- `eval/run_submission.py` for each K (default 16,32,64) at a small N (default 2),
  producing a wrapped proof and (optionally) verifying it on Anvil for gas metrics.
- Baselines are executed by `eval/run_submission.py` via `baseline_groth16_batch_fcircuit`.

Outputs (under `eval/`, typically ignored by git):
- `eval/ict_express_wrap_baselines.json`
- `eval/ict_express_wrap.csv`
- `eval/ict_express_baselines.csv`
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


WRAP_CSV_FIELDS = [
    "run_id",
    "k",
    "n",
    "nova_preprocess_time_s",
    "nova_fold_time_s",
    "decider_circuit_constraints",
    "groth16_preprocess_time_s",
    "wrap_time_s",
    "verify_time_s",
    "calldata_bytes",
    "wrapped_proof_size_bytes",
    "nova_ivc_proof_size_bytes",
    "verifier_sol_bytes",
    "evm_gas_used",
    "evm_status",
    "purechain_gas_used",
    "purechain_status",
]

BASELINE_CSV_FIELDS = [
    "run_id",
    "k",
    "batch_steps",
    "setup_time_s",
    "prove_time_s",
    "verify_time_s",
    "proof_size_bytes",
    "public_inputs_len",
    "evm_gas_used",
    "evm_status",
    "purechain_gas_used",
    "purechain_status",
]


def _workspace_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _run(cmd: List[str], cwd: Path, env: Optional[Dict[str, str]] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        sys.stderr.write(f"\n[run_wrap_baselines] command failed (rc={p.returncode}): {' '.join(cmd)}\n")
        if p.stdout:
            sys.stderr.write("[run_wrap_baselines] --- stdout ---\n")
            sys.stderr.write(p.stdout + "\n")
        if p.stderr:
            sys.stderr.write("[run_wrap_baselines] --- stderr ---\n")
            sys.stderr.write(p.stderr + "\n")
        raise SystemExit(p.returncode)
    return p.stdout.strip()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        delete=False,
        dir=str(path.parent),
        prefix=path.name + ".tmp.",
    ) as f:
        tmp_path = Path(f.name)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp_path), str(path))


def _atomic_write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        delete=False,
        dir=str(path.parent),
        prefix=path.name + ".tmp.",
    ) as f:
        tmp_path = Path(f.name)
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp_path), str(path))


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
        head = s.split()[0]
        try:
            return int(head)
        except Exception:
            return None
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ks", default="16,32,64")
    ap.add_argument("--n-wrap", type=int, default=2)
    ap.add_argument("--verify-anvil", action="store_true")
    ap.add_argument(
        "--verify-baselines-anvil",
        action="store_true",
        help="Also verify baseline Groth16 proofs on Anvil (records baseline gas used)",
    )
    ap.add_argument(
        "--verify-purechain",
        action="store_true",
        help="Verify wrapped + baselines on Purechain (requires PURECHAIN_PRIVATE_KEY_FILE env var)",
    )
    ap.add_argument(
        "--reuse-existing",
        action="store_true",
        help="Do not re-run proof generation; load existing eval/artifacts/<run_id>/summary.json instead.",
    )
    ap.add_argument("--run-prefix", default="ict_wrap")
    ap.add_argument("--baseline-b", default="1,8,16", help="Comma-separated batch sizes")
    args = ap.parse_args()
    if args.verify_anvil and not args.verify_baselines_anvil:
        args.verify_baselines_anvil = True

    ks = [int(x.strip()) for x in args.ks.split(",") if x.strip()]
    bs = [int(x.strip()) for x in args.baseline_b.split(",") if x.strip()]
    if not ks:
        raise SystemExit("--ks must not be empty")
    if args.n_wrap < 2:
        raise SystemExit("--n-wrap must be >= 2 (CycleFold decider requirement)")
    if any(b <= 0 for b in bs):
        raise SystemExit("--baseline-b must be positive")

    root = _workspace_root()
    runner = root / "eval" / "run_submission.py"
    if not runner.exists():
        raise SystemExit(f"missing runner: {runner}")

    env = dict(os.environ)
    if env.get("FOUNDRY_BIN", "").strip() == "":
        env["FOUNDRY_BIN"] = str(Path.home() / ".foundry" / "bin")
    if (not args.reuse_existing) and args.verify_purechain and env.get("PURECHAIN_PRIVATE_KEY_FILE", "").strip() == "":
        raise SystemExit("missing PURECHAIN_PRIVATE_KEY_FILE for --verify-purechain")

    summaries: List[Dict[str, Any]] = []
    wrap_rows: List[Dict[str, Any]] = []
    baseline_rows: List[Dict[str, Any]] = []

    for k in ks:
        run_id = f"{args.run_prefix}_k{k}_n{args.n_wrap}"
        if args.reuse_existing:
            out_dir = (root / "eval" / "artifacts" / run_id).resolve()
        else:
            cmd = [sys.executable, str(runner), "--run-id", run_id, "--k", str(k), "--n", str(args.n_wrap)]
            if args.verify_anvil:
                cmd.append("--verify-anvil")
            if args.verify_baselines_anvil:
                cmd.append("--verify-baselines-anvil")
            if args.verify_purechain:
                cmd.append("--verify-purechain")
            for b in bs:
                cmd += ["--baseline-b", str(b)]
            out_dir_s = _run(cmd, cwd=root, env=env).splitlines()[-1].strip()
            out_dir = Path(out_dir_s).resolve()

        summary_path = out_dir / "summary.json"
        if not summary_path.exists():
            if args.reuse_existing:
                raise SystemExit(
                    f"missing summary.json at: {summary_path}\n"
                    f"Run without --reuse-existing to generate artifacts for run_id={run_id}."
                )
            raise SystemExit(f"missing summary.json at: {summary_path}")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summaries.append(summary)

        wm = summary.get("wrapped_metrics") or {}
        sizes = (summary.get("artifact_sizes_bytes") or {}) if isinstance(summary, dict) else {}
        chain_verify = summary.get("chain_verify") or {}
        purechain_verify = summary.get("purechain_verify") or {}
        if args.verify_purechain and not purechain_verify:
            raise SystemExit(
                f"Purechain verification missing for run_id={run_id}. "
                f"Run without --reuse-existing and with --verify-purechain."
            )

        wrap_rows.append(
            {
                "run_id": run_id,
                "k": k,
                "n": args.n_wrap,
                "nova_preprocess_time_s": wm.get("nova_preprocess_time_s"),
                "nova_fold_time_s": wm.get("nova_fold_time_s"),
                "decider_circuit_constraints": wm.get("decider_circuit_constraints"),
                "groth16_preprocess_time_s": wm.get("groth16_preprocess_time_s"),
                "wrap_time_s": wm.get("wrap_time_s"),
                "verify_time_s": wm.get("verify_time_s"),
                "calldata_bytes": wm.get("calldata_bytes"),
                "wrapped_proof_size_bytes": sizes.get("wrapped_proof_bin"),
                "nova_ivc_proof_size_bytes": sizes.get("nova_ivc_proof_bin"),
                "verifier_sol_bytes": sizes.get("wrapped_verifier_sol"),
                "evm_gas_used": _parse_int(chain_verify.get("gasUsed")),
                "evm_status": _parse_int(chain_verify.get("status")),
                "purechain_gas_used": _parse_int(purechain_verify.get("gasUsed")),
                "purechain_status": _parse_int(purechain_verify.get("status")),
            }
        )

        for bdoc in summary.get("baselines") or []:
            if not isinstance(bdoc, dict):
                continue
            chain_verify = bdoc.get("chain_verify") or {}
            purechain_verify = bdoc.get("purechain_verify") or {}
            baseline_rows.append(
                {
                    "run_id": run_id,
                    "k": bdoc.get("k", k),
                    "batch_steps": bdoc.get("batch_steps"),
                    "setup_time_s": bdoc.get("setup_time_s"),
                    "prove_time_s": bdoc.get("prove_time_s"),
                    "verify_time_s": bdoc.get("verify_time_s"),
                    "proof_size_bytes": bdoc.get("proof_size_bytes"),
                    "public_inputs_len": bdoc.get("public_inputs_len"),
                    "evm_gas_used": _parse_int(chain_verify.get("gasUsed") if isinstance(chain_verify, dict) else None)
                    or _parse_int(bdoc.get("chain_verify_gas_used")),
                    "evm_status": _parse_int(chain_verify.get("status") if isinstance(chain_verify, dict) else None)
                    or _parse_int(bdoc.get("chain_verify_status")),
                    "purechain_gas_used": _parse_int(purechain_verify.get("gasUsed") if isinstance(purechain_verify, dict) else None)
                    or _parse_int(bdoc.get("purechain_verify_gas_used")),
                    "purechain_status": _parse_int(purechain_verify.get("status") if isinstance(purechain_verify, dict) else None)
                    or _parse_int(bdoc.get("purechain_verify_status")),
                }
            )

    out_doc = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ks": ks,
        "n_wrap": args.n_wrap,
        "verify_anvil": bool(args.verify_anvil),
        "baseline_b": bs,
        "summaries": summaries,
    }

    eval_dir = root / "eval"
    json_path = eval_dir / "ict_express_wrap_baselines.json"
    wrap_csv = eval_dir / "ict_express_wrap.csv"
    baseline_csv = eval_dir / "ict_express_baselines.csv"

    _atomic_write_text(json_path, json.dumps(out_doc, indent=2))
    _atomic_write_csv(wrap_csv, wrap_rows, WRAP_CSV_FIELDS)
    _atomic_write_csv(baseline_csv, baseline_rows, BASELINE_CSV_FIELDS)

    print(str(json_path))
    print(str(wrap_csv))
    print(str(baseline_csv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
