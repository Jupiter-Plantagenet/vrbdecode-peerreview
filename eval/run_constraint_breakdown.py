#!/usr/bin/env python3
"""
Generate a constraint breakdown JSON/CSV for StepFCircuit.

Outputs:
- eval/artifacts/<run_id>/constraints/constraint_breakdown.json  (from the Rust binary)
- eval/constraint_breakdown.csv                                 (flattened rows)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List


def _workspace_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _run(cmd: List[str], cwd: Path, env: Dict[str, str] | None = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        sys.stderr.write(f"\n[run_constraint_breakdown] command failed (rc={p.returncode}): {' '.join(cmd)}\n")
        if p.stdout:
            sys.stderr.write("[run_constraint_breakdown] --- stdout ---\n")
            sys.stderr.write(p.stdout + "\n")
        if p.stderr:
            sys.stderr.write("[run_constraint_breakdown] --- stderr ---\n")
            sys.stderr.write(p.stderr + "\n")
        raise SystemExit(p.returncode)
    return p.stdout.strip()


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default="constraint_breakdown")
    ap.add_argument("--max-tokens", type=int, default=2)
    ap.add_argument("--steps", default="0,1")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    root = _workspace_root()
    if not args.no_build:
        _run(["cargo", "build", "--release", "-p", "vrbdecode-zk", "--bin", "constraint_breakdown"], cwd=root)

    exe = root / "target" / "release" / "constraint_breakdown"
    steps = ",".join([s.strip() for s in args.steps.split(",") if s.strip()]) or "0,1"
    out_path_s = _run(
        [
            str(exe),
            "--run-id",
            args.run_id,
            "--max-tokens",
            str(args.max_tokens),
            "--steps",
            steps,
        ],
        cwd=root,
    ).splitlines()[-1]

    out_path = Path(out_path_s).resolve()
    doc = json.loads(out_path.read_text(encoding="utf-8"))

    rows: List[Dict[str, Any]] = []
    for case in doc.get("cases") or []:
        if not isinstance(case, dict):
            continue
        k = case.get("k")
        step_idx = case.get("step_idx")
        constraints = case.get("constraints")
        for b in case.get("breakdown") or []:
            if not isinstance(b, dict):
                continue
            rows.append(
                {
                    "k": k,
                    "step_idx": step_idx,
                    "constraints_total": constraints,
                    "label": b.get("label"),
                    "constraints_delta": b.get("constraints_delta"),
                    "constraints_total_at_label": b.get("constraints_total"),
                }
            )

    csv_path = root / "eval" / "constraint_breakdown.csv"
    _atomic_write_csv(
        csv_path,
        rows,
        ["k", "step_idx", "constraints_total", "label", "constraints_delta", "constraints_total_at_label"],
    )

    print(str(out_path))
    print(str(csv_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

