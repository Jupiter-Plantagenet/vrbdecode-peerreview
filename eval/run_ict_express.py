import argparse
import csv
import json
import os
import platform
import subprocess
import statistics
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


STEP_CSV_FIELDS = [
    "k",
    "step_circuit_constraints",
    "step_circuit_gen_time_s",
    "step_circuit_gen_time_s_std",
    "step_fcircuit_constraints",
    "step_fcircuit_gen_time_s",
    "step_fcircuit_gen_time_s_std",
    "reps",
]


NOVA_CSV_FIELDS = [
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
]


def _parse_int_list(s: str) -> List[int]:
    return [int(x.strip()) for x in s.split(",") if x.strip()]


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


def _atomic_write_csv(path: Path, rows: List[Dict], fieldnames: List[str]) -> None:
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


def _ensure_vectors(root: Path) -> None:
    vec_dir = root / "vectors"
    golden = vec_dir / "golden.jsonl"
    random = vec_dir / "random.jsonl"
    if golden.exists() and random.exists():
        return
    script = root / "ref" / "python" / "generate_vectors.py"
    if not script.exists():
        raise SystemExit(f"vector generator not found: {script}")
    env = dict(os.environ)
    run(
        [
            sys.executable,
            str(script),
            "--out-dir",
            str(vec_dir),
            "--golden",
            "50",
            "--random",
            "1000",
            "--seed",
            "1",
        ],
        cwd=root,
        env=env,
    )


def _load_existing(path: Path) -> Tuple[List[Dict], List[Dict]]:
    if not path.exists():
        return [], []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [], []
    step_raw = ((doc.get("bench_step") or {}).get("raw_rows") or []) if isinstance(doc, dict) else []
    nova_raw = ((doc.get("bench_nova") or {}).get("raw_rows") or []) if isinstance(doc, dict) else []
    if not isinstance(step_raw, list):
        step_raw = []
    if not isinstance(nova_raw, list):
        nova_raw = []
    return step_raw, nova_raw


def _bin_path(target_dir: Path, name: str) -> Path:
    suffix = ".exe" if sys.platform.startswith("win") else ""
    return target_dir / "release" / f"{name}{suffix}"


def _mean(xs: List[float]) -> Optional[float]:
    if not xs:
        return None
    return float(sum(xs)) / float(len(xs))


def _stdev(xs: List[float]) -> Optional[float]:
    if len(xs) < 2:
        return None
    return float(statistics.stdev(xs))


def _aggregate(rows: List[Dict], key_fields: List[str], metric_fields: List[str], int_metrics: List[str]) -> List[Dict]:
    grouped: Dict[Tuple, List[Dict]] = {}
    for r in rows:
        key = tuple(r.get(k) for k in key_fields)
        grouped.setdefault(key, []).append(r)

    out: List[Dict] = []
    for key, rs in grouped.items():
        agg: Dict = {}
        for i, kf in enumerate(key_fields):
            agg[kf] = key[i]
        agg["reps"] = len(rs)

        for mf in metric_fields:
            vals: List[float] = []
            for r in rs:
                v = r.get(mf)
                if isinstance(v, (int, float)):
                    vals.append(float(v))
            mu = _mean(vals)
            sd = _stdev(vals)
            if mu is None:
                agg[mf] = None
                agg[f"{mf}_std"] = None
                continue
            if mf in int_metrics:
                agg[mf] = int(round(mu))
            else:
                agg[mf] = mu
            agg[f"{mf}_std"] = sd

        out.append(agg)

    out.sort(key=lambda r: tuple(r.get(k) for k in key_fields))
    return out


def run(cmd: List[str], cwd: Path, env: Dict[str, str]) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        sys.stderr.write(f"\n[run_ict_express] command failed (rc={p.returncode}): {' '.join(cmd)}\n")
        if (p.stdout or "").strip():
            sys.stderr.write("[run_ict_express] --- stdout ---\n")
            sys.stderr.write(p.stdout)
            if not p.stdout.endswith("\n"):
                sys.stderr.write("\n")
        if (p.stderr or "").strip():
            sys.stderr.write("[run_ict_express] --- stderr ---\n")
            sys.stderr.write(p.stderr)
            if not p.stderr.endswith("\n"):
                sys.stderr.write("\n")
        raise SystemExit(p.returncode)
    if (p.stderr or "").strip():
        sys.stderr.write(p.stderr)
        if not p.stderr.endswith("\n"):
            sys.stderr.write("\n")
    return p.stdout.strip()


def write_csv(path: Path, rows: List[Dict], fieldnames: List[str]) -> None:
    _atomic_write_csv(path, rows, fieldnames)


def run_with_retries(
    root: Path,
    ks: List[int],
    ns: List[int],
    reps: int,
    nova_reps: Optional[List[int]],
    prove_sorting: bool,
    out_prefix: str,
    max_attempts: int = 3,
    fixed_target_dir: Optional[str] = None,
) -> Tuple[List[Dict], List[Dict], List[Dict], List[Dict]]:
    eval_dir = root / "eval"
    partial_path = eval_dir / f"{out_prefix}_partial.json"
    final_path = eval_dir / f"{out_prefix}.json"
    step_csv = eval_dir / f"{out_prefix}_step.csv"
    nova_csv = eval_dir / f"{out_prefix}_nova.csv"

    base_env = dict(os.environ)
    base_env["CARGO_INCREMENTAL"] = "0"
    base_env["CARGO_BUILD_JOBS"] = "1"
    base_env["RAYON_NUM_THREADS"] = "1"
    base_env["VRBDECODE_BENCH_PROGRESS"] = base_env.get("VRBDECODE_BENCH_PROGRESS", "1")

    step_raw_rows, nova_raw_rows = _load_existing(partial_path)
    if not step_raw_rows and not nova_raw_rows:
        step_raw_rows, nova_raw_rows = _load_existing(final_path)

    base_target = root / "target_eval_release"

    last_err: Optional[BaseException] = None
    for attempt in range(1, max_attempts + 1):
        env = dict(base_env)
        if fixed_target_dir:
            env["CARGO_TARGET_DIR"] = str(base_target / fixed_target_dir)
        else:
            env["CARGO_TARGET_DIR"] = str(base_target / f"ict_{attempt}_{uuid.uuid4().hex}")
        env["VRBDECODE_PROVE_SORTING"] = "1" if prove_sorting else "0"
        try:
            _ensure_vectors(root)

            run(
                [
                    "cargo",
                    "build",
                    "--release",
                    "-p",
                    "vrbdecode-zk",
                    "--bin",
                    "bench_step",
                    "--bin",
                    "bench_nova",
                ],
                cwd=root,
                env=env,
            )

            target_dir = Path(env["CARGO_TARGET_DIR"])
            bench_step_bin = _bin_path(target_dir, "bench_step")
            bench_nova_bin = _bin_path(target_dir, "bench_nova")

            rep_to_ks: Dict[int, set] = {}
            for r in step_raw_rows:
                try:
                    rep = int(r.get("rep"))
                    k = int(r.get("k"))
                except (TypeError, ValueError):
                    continue
                rep_to_ks.setdefault(rep, set()).add(k)
            done_step_reps = {rep for rep, ks_seen in rep_to_ks.items() if set(ks).issubset(ks_seen)}

            pair_to_ns: Dict[Tuple[int, int], set] = {}
            for r in nova_raw_rows:
                try:
                    k = int(r.get("k"))
                    rep = int(r.get("rep"))
                    n_steps = int(r.get("n_steps"))
                except (TypeError, ValueError):
                    continue
                pair_to_ns.setdefault((k, rep), set()).add(n_steps)
            done_nova_pairs = {pair for pair, ns_seen in pair_to_ns.items() if set(ns).issubset(ns_seen)}

            for rep in range(reps):
                if rep in done_step_reps:
                    continue
                bench_step_out = run(
                    [str(bench_step_bin), "--json"] + (["--prove-sorting"] if prove_sorting else []),
                    cwd=root,
                    env=env,
                )
                rows = json.loads(bench_step_out)
                for r in rows:
                    row = dict(r)
                    row["rep"] = rep
                    step_raw_rows.append(row)

                step_rows = _aggregate(
                    step_raw_rows,
                    key_fields=["k"],
                    metric_fields=[
                        "step_circuit_constraints",
                        "step_circuit_gen_time_s",
                        "step_fcircuit_constraints",
                        "step_fcircuit_gen_time_s",
                    ],
                    int_metrics=["step_circuit_constraints", "step_fcircuit_constraints"],
                )
                nova_rows = _aggregate(
                    nova_raw_rows,
                    key_fields=["k", "n_steps"],
                    metric_fields=[
                        "avg_step_time_s",
                        "total_fold_time_s",
                        "proof_size_bytes",
                        "verify_time_s",
                        "peak_rss_kb",
                        "preprocess_time_s",
                    ],
                    int_metrics=["proof_size_bytes", "peak_rss_kb"],
                )
                out = {
                    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                    "ks": ks,
                    "ns": ns,
                    "reps": reps,
                    "host": {
                        "platform": platform.platform(),
                        "python": sys.version.split()[0],
                    },
                    "bench_step": {"rows": step_rows, "raw_rows": step_raw_rows},
                    "bench_nova": {"rows": nova_rows, "raw_rows": nova_raw_rows},
                }
                _atomic_write_text(partial_path, json.dumps(out, indent=2))
                write_csv(step_csv, step_rows, STEP_CSV_FIELDS)
                write_csv(nova_csv, nova_rows, NOVA_CSV_FIELDS)

            steps_arg = ",".join(str(x) for x in ns)
            for k in ks:
                for rep in range(reps):
                    if nova_reps is not None and rep not in set(nova_reps):
                        continue
                    if (k, rep) in done_nova_pairs:
                        continue
                    nova_out_s = run(
                        [
                            str(bench_nova_bin),
                            "--json",
                            "--progress",
                        ]
                        + (["--prove-sorting"] if prove_sorting else [])
                        + [
                            "--k",
                            str(k),
                            "--steps",
                            steps_arg,
                        ],
                        cwd=root,
                        env=env,
                    )
                    nova_out = json.loads(nova_out_s)
                    for r in nova_out.get("results", []):
                        row = dict(r)
                        row["k"] = k
                        row["rep"] = rep
                        row["attempt"] = attempt
                        row["preprocess_time_s"] = nova_out.get("preprocess_time_s")
                        nova_raw_rows.append(row)

                    step_rows = _aggregate(
                        step_raw_rows,
                        key_fields=["k"],
                        metric_fields=[
                            "step_circuit_constraints",
                            "step_circuit_gen_time_s",
                            "step_fcircuit_constraints",
                            "step_fcircuit_gen_time_s",
                        ],
                        int_metrics=["step_circuit_constraints", "step_fcircuit_constraints"],
                    )
                    nova_rows = _aggregate(
                        nova_raw_rows,
                        key_fields=["k", "n_steps"],
                        metric_fields=[
                            "avg_step_time_s",
                            "total_fold_time_s",
                            "proof_size_bytes",
                            "verify_time_s",
                            "peak_rss_kb",
                            "preprocess_time_s",
                        ],
                        int_metrics=["proof_size_bytes", "peak_rss_kb"],
                    )
                    out = {
                        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                        "ks": ks,
                        "ns": ns,
                        "reps": reps,
                        "prove_sorting": prove_sorting,
                        "candidate_order_mode": "prove_sorting" if prove_sorting else "assume_canonical_sorted",
                        "host": {
                            "platform": platform.platform(),
                            "python": sys.version.split()[0],
                        },
                        "bench_step": {"rows": step_rows, "raw_rows": step_raw_rows},
                        "bench_nova": {"rows": nova_rows, "raw_rows": nova_raw_rows},
                    }
                    _atomic_write_text(partial_path, json.dumps(out, indent=2))
                    write_csv(step_csv, step_rows, STEP_CSV_FIELDS)
                    write_csv(nova_csv, nova_rows, NOVA_CSV_FIELDS)

            step_rows = _aggregate(
                step_raw_rows,
                key_fields=["k"],
                metric_fields=[
                    "step_circuit_constraints",
                    "step_circuit_gen_time_s",
                    "step_fcircuit_constraints",
                    "step_fcircuit_gen_time_s",
                ],
                int_metrics=["step_circuit_constraints", "step_fcircuit_constraints"],
            )
            nova_rows = _aggregate(
                nova_raw_rows,
                key_fields=["k", "n_steps"],
                metric_fields=[
                    "avg_step_time_s",
                    "total_fold_time_s",
                    "proof_size_bytes",
                    "verify_time_s",
                    "peak_rss_kb",
                    "preprocess_time_s",
                ],
                int_metrics=["proof_size_bytes", "peak_rss_kb"],
            )
            return step_rows, nova_rows, step_raw_rows, nova_raw_rows
        except BaseException as e:
            last_err = e
            sys.stderr.write(f"\n[run_ict_express] attempt {attempt}/{max_attempts} failed; retrying...\n")
            time.sleep(2)

    raise last_err if last_err is not None else SystemExit(1)

def _is_complete(step_raw_rows: List[Dict], nova_raw_rows: List[Dict], ks: List[int], ns: List[int], reps: int) -> Tuple[bool, Dict[str, object]]:
    ks_set = set(int(k) for k in ks)
    ns_set = set(int(n) for n in ns)

    rep_to_ks: Dict[int, set] = {}
    for r in step_raw_rows:
        try:
            rep = int(r.get("rep"))
            k = int(r.get("k"))
        except (TypeError, ValueError):
            continue
        rep_to_ks.setdefault(rep, set()).add(k)
    missing_step_reps = [rep for rep in range(reps) if not ks_set.issubset(rep_to_ks.get(rep, set()))]

    pair_to_ns: Dict[Tuple[int, int], set] = {}
    for r in nova_raw_rows:
        try:
            k = int(r.get("k"))
            rep = int(r.get("rep"))
            n_steps = int(r.get("n_steps"))
        except (TypeError, ValueError):
            continue
        pair_to_ns.setdefault((k, rep), set()).add(n_steps)
    missing_nova: List[Tuple[int, int, List[int]]] = []
    for k in sorted(ks_set):
        for rep in range(reps):
            seen = pair_to_ns.get((k, rep), set())
            miss = sorted(ns_set - seen)
            if miss:
                missing_nova.append((k, rep, miss))

    complete = (len(missing_step_reps) == 0) and (len(missing_nova) == 0)
    return complete, {"missing_step_reps": missing_step_reps, "missing_nova": missing_nova}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ks", default="16,32,64")
    ap.add_argument("--ns", default="32,64,128,256")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument(
        "--mode",
        default="assume_sorted",
        choices=["assume_sorted", "prove_sorting", "both"],
        help="Candidate order mode: assume_sorted (optimized), prove_sorting (baseline), or both.",
    )
    ap.add_argument(
        "--nova-reps",
        default="",
        help="Optional comma-separated subset of rep indices to run for Nova (e.g. '1,2'). Useful for splitting long runs.",
    )
    ap.add_argument(
        "--fixed-target-dir",
        default="",
        help="Optional fixed subdir under target_eval_release/ to reuse builds across invocations (reduces rebuild time).",
    )
    args = ap.parse_args()

    ks = _parse_int_list(args.ks)
    ns = _parse_int_list(args.ns)
    nova_reps = _parse_int_list(args.nova_reps) if (args.nova_reps or "").strip() else None

    root = Path(__file__).resolve().parent.parent

    def _prefix_for(prove_sorting: bool) -> str:
        # Keep legacy filenames for the optimized default mode.
        return "ict_express" if not prove_sorting else "ict_express_prove_sorting"

    if args.no_resume:
        eval_dir = root / "eval"
        prefixes = []
        if args.mode == "both":
            prefixes = [_prefix_for(False), _prefix_for(True)]
        elif args.mode == "prove_sorting":
            prefixes = [_prefix_for(True)]
        else:
            prefixes = [_prefix_for(False)]
        for prefix in prefixes:
            for suffix in ["_partial.json", ".json", "_step.csv", "_nova.csv"]:
                p = eval_dir / f"{prefix}{suffix}"
                try:
                    if p.exists():
                        p.unlink()
                except OSError:
                    pass

    def _run_one(prove_sorting: bool) -> int:
        out_prefix = _prefix_for(prove_sorting)
        step_rows, nova_rows, step_raw_rows, nova_raw_rows = run_with_retries(
            root,
            ks=ks,
            ns=ns,
            reps=args.reps,
            nova_reps=nova_reps,
            prove_sorting=prove_sorting,
            out_prefix=out_prefix,
            max_attempts=args.attempts,
            fixed_target_dir=(args.fixed_target_dir or "").strip() or None,
        )

        complete, missing = _is_complete(step_raw_rows, nova_raw_rows, ks, ns, args.reps)
        eval_dir = root / "eval"
        partial_path = eval_dir / f"{out_prefix}_partial.json"
        if not complete:
            # Ensure partial is up-to-date and do not emit final json (would be incomplete).
            out_partial = {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "ks": ks,
                "ns": ns,
                "reps": args.reps,
                "prove_sorting": prove_sorting,
                "candidate_order_mode": "prove_sorting" if prove_sorting else "assume_canonical_sorted",
                "host": {"platform": platform.platform(), "python": sys.version.split()[0]},
                "missing": missing,
                "bench_step": {"rows": step_rows, "raw_rows": step_raw_rows},
                "bench_nova": {"rows": nova_rows, "raw_rows": nova_raw_rows},
            }
            _atomic_write_text(partial_path, json.dumps(out_partial, indent=2))
            write_csv(eval_dir / f"{out_prefix}_step.csv", step_rows, STEP_CSV_FIELDS)
            write_csv(eval_dir / f"{out_prefix}_nova.csv", nova_rows, NOVA_CSV_FIELDS)
            sys.stderr.write(f"[run_ict_express] incomplete; wrote {partial_path}\n")
            sys.stderr.write(f"[run_ict_express] missing: {missing}\n")
            print(str(partial_path))
            return 2

        out = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "ks": ks,
            "ns": ns,
            "reps": args.reps,
            "prove_sorting": prove_sorting,
            "candidate_order_mode": "prove_sorting" if prove_sorting else "assume_canonical_sorted",
            "host": {"platform": platform.platform(), "python": sys.version.split()[0]},
            "bench_step": {"rows": step_rows, "raw_rows": step_raw_rows},
            "bench_nova": {"rows": nova_rows, "raw_rows": nova_raw_rows},
        }

        json_path = eval_dir / f"{out_prefix}.json"
        _atomic_write_text(json_path, json.dumps(out, indent=2))

        step_csv = eval_dir / f"{out_prefix}_step.csv"
        write_csv(step_csv, step_rows, STEP_CSV_FIELDS)

        nova_csv = eval_dir / f"{out_prefix}_nova.csv"
        write_csv(nova_csv, nova_rows, NOVA_CSV_FIELDS)

        print(str(json_path))
        print(str(step_csv))
        print(str(nova_csv))
        return 0

    if args.mode == "both":
        rc1 = _run_one(False)
        rc2 = _run_one(True)
        return 0 if (rc1 == 0 and rc2 == 0) else 2
    if args.mode == "prove_sorting":
        return _run_one(True)
    return _run_one(False)


if __name__ == "__main__":
    raise SystemExit(main())
