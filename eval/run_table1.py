import csv
import json
import tempfile
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid
from typing import List, Dict, Tuple, Optional


def run(cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    p = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p.returncode != 0:
        sys.stderr.write(f"\n[run_table1] command failed (rc={p.returncode}): {' '.join(cmd)}\n")
        if (p.stdout or "").strip():
            sys.stderr.write("[run_table1] --- stdout ---\n")
            sys.stderr.write(p.stdout)
            if not p.stdout.endswith("\n"):
                sys.stderr.write("\n")
        if (p.stderr or "").strip():
            sys.stderr.write("[run_table1] --- stderr ---\n")
            sys.stderr.write(p.stderr)
            if not p.stderr.endswith("\n"):
                sys.stderr.write("\n")
        raise SystemExit(p.returncode)
    if (p.stderr or "").strip():
        sys.stderr.write(p.stderr)
        if not p.stderr.endswith("\n"):
            sys.stderr.write("\n")
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


def load_ict_express(eval_dir: Path) -> Tuple[List[Dict], Dict]:
    p = eval_dir / "ict_express.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    step_rows = (doc.get("bench_step") or {}).get("rows") or []
    nova_rows = (doc.get("bench_nova") or {}).get("rows") or []
    nova_out = {
        "preprocess_time_s": None,
        "results": nova_rows,
    }
    return step_rows, nova_out


def run_table1_with_retries(root: Path, nova_steps: Optional[str], max_attempts: int = 5) -> Tuple[List[Dict], Dict]:
    base_env = dict(os.environ)
    base_env["CARGO_INCREMENTAL"] = "0"
    base_env["CARGO_BUILD_JOBS"] = "1"

    base_target = root / "target_eval_release"

    last_err: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        env = dict(base_env)
        env["CARGO_TARGET_DIR"] = str(base_target / f"run_{attempt}_{uuid.uuid4().hex}")
        try:
            bench_step_out = run(
                ["cargo", "run", "--release", "-p", "vrbdecode-zk", "--bin", "bench_step", "--", "--json"],
                cwd=root,
                env=env,
            )
            step_rows = json.loads(bench_step_out)

            nova_cmd = [
                "cargo",
                "run",
                "--release",
                "-p",
                "vrbdecode-zk",
                "--bin",
                "bench_nova",
                "--",
                "--json",
                "--progress",
            ]
            if nova_steps is not None:
                nova_cmd.extend(["--steps", nova_steps])

            bench_nova_out = run(nova_cmd, cwd=root, env=env)
            nova_out = json.loads(bench_nova_out)
            return step_rows, nova_out
        except BaseException as e:
            last_err = e
            sys.stderr.write(f"\n[run_table1] attempt {attempt}/{max_attempts} failed; retrying...\n")
            time.sleep(2)

    raise last_err if last_err is not None else SystemExit(1)


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
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
    root = Path(__file__).resolve().parent.parent

    nova_steps = os.environ.get("VRBDECODE_BENCH_NOVA_STEPS")
    if nova_steps is not None:
        nova_steps = nova_steps.strip() or None

    eval_dir = root / "eval"
    use_ict = os.environ.get("VRBDECODE_TABLE1_FROM_ICT", "1").strip() != "0"
    force_run = os.environ.get("VRBDECODE_TABLE1_FORCE_RUN", "0").strip() == "1"

    ict_path = eval_dir / "ict_express.json"
    if use_ict and (not force_run) and ict_path.exists():
        step_rows, nova_out = load_ict_express(eval_dir)
    else:
        step_rows, nova_out = run_table1_with_retries(root, nova_steps)

    out = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "bench_step": {"rows": step_rows},
        "bench_nova": nova_out,
    }

    json_path = eval_dir / "table1.json"
    _atomic_write_text(json_path, json.dumps(out, indent=2))

    step_csv = eval_dir / "table1_step.csv"
    write_csv(
        step_csv,
        step_rows,
        [
            "k",
            "step_circuit_constraints",
            "step_circuit_gen_time_s",
            "step_circuit_gen_time_s_std",
            "step_fcircuit_constraints",
            "step_fcircuit_gen_time_s",
            "step_fcircuit_gen_time_s_std",
            "reps",
        ],
    )

    nova_csv = eval_dir / "table1_nova.csv"
    write_csv(
        nova_csv,
        nova_out.get("results", []),
        [
            "k",
            "n_steps",
            "avg_step_time_s",
            "avg_step_time_s_std",
            "total_fold_time_s",
            "total_fold_time_s_std",
            "proof_size_bytes",
            "proof_size_bytes_std",
            "verify_time_s",
            "verify_time_s_std",
            "peak_rss_kb",
            "peak_rss_kb_std",
            "preprocess_time_s",
            "preprocess_time_s_std",
            "reps",
        ],
    )

    print(str(json_path))
    print(str(step_csv))
    print(str(nova_csv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
