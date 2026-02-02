import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        # handle "1 (success)"
        head = s.split()[0]
        if head.startswith(("0x", "0X")):
            return int(head, 16)
        return int(float(head))
    except Exception:
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


def _read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise SystemExit(f"missing input: {path}")
    with path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        return list(r)


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


@dataclass(frozen=True)
class WrapRow:
    k: int
    wrap_time_s: Optional[float]
    calldata_bytes: Optional[int]
    gas_used: Optional[int]
    purechain_gas_used: Optional[int]


@dataclass(frozen=True)
class BaselineRow:
    k: int
    batch_steps: int
    setup_time_s: Optional[float]
    prove_time_s: Optional[float]
    gas_used: Optional[int]
    purechain_gas_used: Optional[int]


def load_wrap(path: Path) -> List[WrapRow]:
    rows = _read_csv(path)
    out: List[WrapRow] = []
    for r in rows:
        k = _to_int(r.get("k"))
        if k is None:
            continue
        out.append(
            WrapRow(
                k=k,
                wrap_time_s=_to_float(r.get("wrap_time_s")),
                calldata_bytes=_to_int(r.get("calldata_bytes")),
                gas_used=_to_int(r.get("evm_gas_used")),
                purechain_gas_used=_to_int(r.get("purechain_gas_used")),
            )
        )
    out.sort(key=lambda x: x.k)
    return out


def load_baselines(path: Path) -> List[BaselineRow]:
    rows = _read_csv(path)
    out: List[BaselineRow] = []
    for r in rows:
        k = _to_int(r.get("k"))
        b = _to_int(r.get("batch_steps"))
        if k is None or b is None:
            continue
        out.append(
            BaselineRow(
                k=k,
                batch_steps=b,
                setup_time_s=_to_float(r.get("setup_time_s")),
                prove_time_s=_to_float(r.get("prove_time_s")),
                gas_used=_to_int(r.get("evm_gas_used")),
                purechain_gas_used=_to_int(r.get("purechain_gas_used")),
            )
        )
    out.sort(key=lambda x: (x.batch_steps, x.k))
    return out


def plot_wrap_time_vs_k(rows: List[WrapRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ks = [r.k for r in rows]
    ys = [r.wrap_time_s for r in rows]
    if not any(v is not None for v in ys):
        plt.close(fig)
        return
    ax.plot(ks, [v if v is not None else float("nan") for v in ys], marker="o")
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Wrap prove time (s)")
    ax.grid(True, alpha=0.3)
    _save(fig, out_dir / "wrap_time_vs_k")
    plt.close(fig)


def plot_evm_gas_vs_k(rows: List[WrapRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ks = [r.k for r in rows]
    ys = [r.gas_used for r in rows]
    if not any(v is not None for v in ys):
        plt.close(fig)
        return
    ax.bar([str(k) for k in ks], [v if v is not None else 0 for v in ys])
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("EVM verify gas (Anvil)")
    ax.grid(True, axis="y", alpha=0.3)
    _save(fig, out_dir / "evm_gas_vs_k")
    plt.close(fig)

def plot_purechain_gas_vs_k(rows: List[WrapRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ks = [r.k for r in rows]
    ys = [r.purechain_gas_used for r in rows]
    if not any(v is not None for v in ys):
        plt.close(fig)
        return
    ax.bar([str(k) for k in ks], [v if v is not None else 0 for v in ys])
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Purechain verify gas")
    ax.grid(True, axis="y", alpha=0.3)
    _save(fig, out_dir / "purechain_gas_vs_k")
    plt.close(fig)


def plot_baseline_prove_vs_k(rows: List[BaselineRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    plotted = False
    for b in sorted({r.batch_steps for r in rows}):
        rs = [r for r in rows if r.batch_steps == b]
        ks = [r.k for r in rs]
        ys = [r.prove_time_s for r in rs]
        if not any(v is not None for v in ys):
            continue
        plotted = True
        ax.plot(ks, [v if v is not None else float("nan") for v in ys], marker="o", label=f"B={b}")
    if not plotted:
        plt.close(fig)
        return
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Baseline Groth16 prove time (s)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")
    _save(fig, out_dir / "baseline_prove_time_vs_k")
    plt.close(fig)

def plot_baseline_evm_gas_vs_k(rows: List[BaselineRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    plotted = False
    for b in sorted({r.batch_steps for r in rows}):
        rs = [r for r in rows if r.batch_steps == b]
        ks = [r.k for r in rs]
        ys = [r.gas_used for r in rs]
        if not any(v is not None for v in ys):
            continue
        plotted = True
        ax.plot(ks, [v if v is not None else float("nan") for v in ys], marker="o", label=f"B={b}")
    if not plotted:
        plt.close(fig)
        return
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Baseline EVM verify gas (Anvil)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")
    _save(fig, out_dir / "baseline_evm_gas_vs_k")
    plt.close(fig)

def plot_baseline_purechain_gas_vs_k(rows: List[BaselineRow], out_dir: Path) -> None:
    _, plt = _ensure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    plotted = False
    for b in sorted({r.batch_steps for r in rows}):
        rs = [r for r in rows if r.batch_steps == b]
        ks = [r.k for r in rs]
        ys = [r.purechain_gas_used for r in rs]
        if not any(v is not None for v in ys):
            continue
        plotted = True
        ax.plot(ks, [v if v is not None else float("nan") for v in ys], marker="o", label=f"B={b}")
    if not plotted:
        plt.close(fig)
        return
    ax.set_xlabel("K (candidate set size)")
    ax.set_ylabel("Baseline Purechain verify gas")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")
    _save(fig, out_dir / "baseline_purechain_gas_vs_k")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wrap-csv", default="eval/ict_express_wrap.csv")
    ap.add_argument("--baseline-csv", default="eval/ict_express_baselines.csv")
    ap.add_argument("--out-dir", default="eval/plots")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    wrap_csv = (root / args.wrap_csv).resolve()
    baseline_csv = (root / args.baseline_csv).resolve()
    out_dir = (root / args.out_dir).resolve()

    wrap_rows = load_wrap(wrap_csv)
    baseline_rows = load_baselines(baseline_csv)

    if not wrap_rows and not baseline_rows:
        sys.stderr.write("no data rows found; nothing to plot\n")
        return 2

    if wrap_rows:
        plot_wrap_time_vs_k(wrap_rows, out_dir)
        plot_evm_gas_vs_k(wrap_rows, out_dir)
        plot_purechain_gas_vs_k(wrap_rows, out_dir)

    if baseline_rows:
        plot_baseline_prove_vs_k(baseline_rows, out_dir)
        plot_baseline_evm_gas_vs_k(baseline_rows, out_dir)
        plot_baseline_purechain_gas_vs_k(baseline_rows, out_dir)

    print(str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
