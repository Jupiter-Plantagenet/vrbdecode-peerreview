import argparse
import csv
import json
import math
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
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
    except Exception:
        return None


def _read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise SystemExit(f"missing input: {path}")
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


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


@dataclass(frozen=True)
class NovaAgg:
    k: int
    n_steps: int
    total_fold_time_s: float
    proof_size_bytes: int


@dataclass(frozen=True)
class WrapAgg:
    k: int
    wrap_time_s: float
    calldata_bytes: int
    evm_gas_used: Optional[int]


@dataclass(frozen=True)
class BaselineAgg:
    k: int
    batch_steps: int
    prove_time_s: float
    setup_time_s: float


def load_nova_agg(path: Path, *, n: int) -> Dict[int, NovaAgg]:
    out: Dict[int, NovaAgg] = {}
    for r in _read_csv(path):
        k = _to_int(r.get("k"))
        n_steps = _to_int(r.get("n_steps"))
        if k is None or n_steps is None or n_steps != n:
            continue
        fold = _to_float(r.get("total_fold_time_s"))
        size = _to_int(r.get("proof_size_bytes"))
        if fold is None or size is None:
            continue
        out[k] = NovaAgg(k=k, n_steps=n_steps, total_fold_time_s=float(fold), proof_size_bytes=int(size))
    return out


def load_wrap_agg(path: Path) -> Dict[int, WrapAgg]:
    out: Dict[int, WrapAgg] = {}
    for r in _read_csv(path):
        k = _to_int(r.get("k"))
        if k is None:
            continue
        wrap = _to_float(r.get("wrap_time_s"))
        calldata = _to_int(r.get("calldata_bytes"))
        gas = _to_int(r.get("evm_gas_used"))
        if wrap is None or calldata is None:
            continue
        out[k] = WrapAgg(k=k, wrap_time_s=float(wrap), calldata_bytes=int(calldata), evm_gas_used=gas)
    return out


def load_baselines(path: Path) -> List[BaselineAgg]:
    out: List[BaselineAgg] = []
    for r in _read_csv(path):
        k = _to_int(r.get("k"))
        b = _to_int(r.get("batch_steps"))
        if k is None or b is None:
            continue
        prove = _to_float(r.get("prove_time_s"))
        setup = _to_float(r.get("setup_time_s"))
        if prove is None or setup is None:
            continue
        out.append(BaselineAgg(k=k, batch_steps=b, prove_time_s=float(prove), setup_time_s=float(setup)))
    out.sort(key=lambda x: (x.k, x.batch_steps))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=256, help="Target N for the comparison (from ict_express_nova.csv)")
    ap.add_argument("--nova-csv", default="eval/ict_express_nova.csv")
    ap.add_argument("--wrap-csv", default="eval/ict_express_wrap.csv")
    ap.add_argument("--baseline-csv", default="eval/ict_express_baselines.csv")
    ap.add_argument("--out-json", default="eval/comparison_table.json")
    ap.add_argument("--out-csv", default="eval/comparison_table.csv")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    nova_csv = (root / args.nova_csv).resolve()
    wrap_csv = (root / args.wrap_csv).resolve()
    baseline_csv = (root / args.baseline_csv).resolve()

    nova = load_nova_agg(nova_csv, n=args.n)
    wrap = load_wrap_agg(wrap_csv)
    baselines = load_baselines(baseline_csv)

    ks = sorted(set(nova.keys()) & set(wrap.keys()))
    if not ks:
        raise SystemExit("no overlapping Ks across nova and wrap inputs")

    rows: List[Dict[str, Any]] = []
    for k in ks:
        nrow = nova[k]
        wrow = wrap[k]
        rows.append(
            {
                "k": k,
                "n": args.n,
                "scheme": "fold+wrap",
                "batch_steps": None,
                "setup_time_s": None,
                "prove_time_s_total": nrow.total_fold_time_s + wrow.wrap_time_s,
                "prove_time_s_fold": nrow.total_fold_time_s,
                "prove_time_s_wrap": wrow.wrap_time_s,
                "proof_or_state_size_bytes": nrow.proof_size_bytes,
                "calldata_bytes": wrow.calldata_bytes,
                "evm_gas_used": wrow.evm_gas_used,
            }
        )

        for b in [1, 8, 16]:
            bmatch = next((x for x in baselines if x.k == k and x.batch_steps == b), None)
            if bmatch is None:
                continue
            batches = int(math.ceil(args.n / float(b)))
            rows.append(
                {
                    "k": k,
                    "n": args.n,
                    "scheme": "groth16_batch_fcircuit",
                    "batch_steps": b,
                    "setup_time_s": bmatch.setup_time_s,
                    "prove_time_s_total": bmatch.prove_time_s * batches,
                    "prove_time_s_fold": None,
                    "prove_time_s_wrap": None,
                    "proof_or_state_size_bytes": None,
                    "calldata_bytes": None,
                    "evm_gas_used": None,
                }
            )

    fieldnames = [
        "k",
        "n",
        "scheme",
        "batch_steps",
        "setup_time_s",
        "prove_time_s_total",
        "prove_time_s_fold",
        "prove_time_s_wrap",
        "proof_or_state_size_bytes",
        "calldata_bytes",
        "evm_gas_used",
    ]
    rows.sort(key=lambda r: (r["k"], str(r["scheme"]), r.get("batch_steps") or 0))

    out_doc = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "n": args.n,
        "rows": rows,
    }
    _atomic_write_text((root / args.out_json).resolve(), json.dumps(out_doc, indent=2))
    _atomic_write_csv((root / args.out_csv).resolve(), rows, fieldnames)
    print(str((root / args.out_json).resolve()))
    print(str((root / args.out_csv).resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

