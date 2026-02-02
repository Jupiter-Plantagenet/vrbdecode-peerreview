import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class StepRow:
    k: int
    step_circuit_constraints: int
    step_circuit_gen_time_s: Optional[float]
    step_fcircuit_constraints: int
    step_fcircuit_gen_time_s: Optional[float]


@dataclass(frozen=True)
class NovaRow:
    k: int
    n_steps: int
    avg_step_time_s: Optional[float]
    total_fold_time_s: Optional[float]
    verify_time_s: Optional[float]
    proof_size_bytes: Optional[int]
    peak_rss_kb: Optional[int]
    preprocess_time_s: Optional[float]


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(float(s))
    except ValueError:
        return None


def _to_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise SystemExit(f"missing input: {path}")
    with path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        return list(r)


def load_step(path: Path) -> List[StepRow]:
    rows = _read_csv_rows(path)
    out: List[StepRow] = []
    for r in rows:
        k = _to_int(r.get("k"))
        scc = _to_int(r.get("step_circuit_constraints"))
        sct = _to_float(r.get("step_circuit_gen_time_s"))
        sfc = _to_int(r.get("step_fcircuit_constraints"))
        sft = _to_float(r.get("step_fcircuit_gen_time_s"))
        if k is None or scc is None or sfc is None:
            continue
        out.append(
            StepRow(
                k=k,
                step_circuit_constraints=scc,
                step_circuit_gen_time_s=sct,
                step_fcircuit_constraints=sfc,
                step_fcircuit_gen_time_s=sft,
            )
        )
    out.sort(key=lambda x: x.k)
    return out


def load_nova(path: Path) -> List[NovaRow]:
    rows = _read_csv_rows(path)
    out: List[NovaRow] = []
    for r in rows:
        k = _to_int(r.get("k"))
        n_steps = _to_int(r.get("n_steps"))
        if k is None or n_steps is None:
            continue
        out.append(
            NovaRow(
                k=k,
                n_steps=n_steps,
                avg_step_time_s=_to_float(r.get("avg_step_time_s")),
                total_fold_time_s=_to_float(r.get("total_fold_time_s")),
                verify_time_s=_to_float(r.get("verify_time_s")),
                proof_size_bytes=_to_int(r.get("proof_size_bytes")),
                peak_rss_kb=_to_int(r.get("peak_rss_kb")),
                preprocess_time_s=_to_float(r.get("preprocess_time_s")),
            )
        )
    out.sort(key=lambda x: (x.k, x.n_steps))
    return out


def _group_by_k_nova(rows: List[NovaRow]) -> Dict[int, List[NovaRow]]:
    out: Dict[int, List[NovaRow]] = {}
    for r in rows:
        out.setdefault(r.k, []).append(r)
    for k in list(out.keys()):
        out[k].sort(key=lambda x: x.n_steps)
    return out


def _ensure_matplotlib() -> Tuple[Any, Any]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return matplotlib, plt
    except ImportError as e:
        raise SystemExit(
            "matplotlib is required for plotting. Install with: pip install -r eval/requirements_plot.txt"
        ) from e


def _save(fig: Any, out_base: Path) -> None:
    out_base.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(out_base.with_suffix(".pdf")), bbox_inches="tight")
    fig.savefig(str(out_base.with_suffix(".png")), dpi=200, bbox_inches="tight")


def plot_constraints_vs_k(step_rows: List[StepRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()

    ks = [r.k for r in step_rows]
    step_constraints = [r.step_circuit_constraints for r in step_rows]
    stepf_constraints = [r.step_fcircuit_constraints for r in step_rows]

    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ax.plot(ks, step_constraints, marker="o", label="StepCircuit")
    ax.plot(ks, stepf_constraints, marker="o", label="StepFCircuit")
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Constraints")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")

    _save(fig, out_dir / "constraints_vs_k")
    plt.close(fig)


def plot_gen_time_vs_k(step_rows: List[StepRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()

    ks = [r.k for r in step_rows]
    step_times = [r.step_circuit_gen_time_s for r in step_rows]
    stepf_times = [r.step_fcircuit_gen_time_s for r in step_rows]

    if all(v is None for v in step_times) and all(v is None for v in stepf_times):
        return

    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    if any(v is not None for v in step_times):
        ax.plot(ks, [v if v is not None else float("nan") for v in step_times], marker="o", label="StepCircuit")
    if any(v is not None for v in stepf_times):
        ax.plot(
            ks,
            [v if v is not None else float("nan") for v in stepf_times],
            marker="o",
            label="StepFCircuit",
        )
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Circuit generation time (s)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")

    _save(fig, out_dir / "gen_time_vs_k")
    plt.close(fig)


def plot_nova_times_vs_n(nova_rows: List[NovaRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()

    by_k = _group_by_k_nova(nova_rows)
    fig, ax = plt.subplots(figsize=(5.2, 3.2))

    plotted = False
    for k, rows in sorted(by_k.items()):
        ns = [r.n_steps for r in rows]
        ys = [r.avg_step_time_s for r in rows]
        if not any(v is not None for v in ys):
            continue
        plotted = True
        ax.plot(ns, [v if v is not None else float("nan") for v in ys], marker="o", label=f"K={k}")

    if not plotted:
        plt.close(fig)
        return

    ax.set_xlabel("N (number of decoding steps)")
    ax.set_ylabel("Avg proving time per step (s)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")

    _save(fig, out_dir / "nova_avg_step_time_vs_n")
    plt.close(fig)


def plot_nova_memory_vs_n(nova_rows: List[NovaRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()

    by_k = _group_by_k_nova(nova_rows)
    fig, ax = plt.subplots(figsize=(5.2, 3.2))

    plotted = False
    for k, rows in sorted(by_k.items()):
        ns = [r.n_steps for r in rows]
        ys = [r.peak_rss_kb for r in rows]
        if not any(v is not None for v in ys):
            continue
        plotted = True
        ax.plot(ns, [v if v is not None else float("nan") for v in ys], marker="o", label=f"K={k}")

    if not plotted:
        plt.close(fig)
        return

    ax.set_xlabel("N (number of decoding steps)")
    ax.set_ylabel("Peak RSS (KiB)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")

    _save(fig, out_dir / "nova_peak_rss_vs_n")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--step-csv", default="eval/ict_express_step.csv")
    ap.add_argument("--nova-csv", default="eval/ict_express_nova.csv")
    ap.add_argument("--out-dir", default="eval/plots")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    step_csv = (root / args.step_csv).resolve()
    nova_csv = (root / args.nova_csv).resolve()
    out_dir = (root / args.out_dir).resolve()

    step_rows = load_step(step_csv)
    nova_rows = load_nova(nova_csv)

    if not step_rows and not nova_rows:
        sys.stderr.write("no data rows found; nothing to plot\n")
        return 2

    if step_rows:
        plot_constraints_vs_k(step_rows, out_dir)
        plot_gen_time_vs_k(step_rows, out_dir)

    if nova_rows:
        plot_nova_times_vs_n(nova_rows, out_dir)
        plot_nova_memory_vs_n(nova_rows, out_dir)

    print(str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
