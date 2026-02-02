from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Tuple


ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PATH = ROOT / "repro" / "expected_constants.json"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _index_step(rows: list[dict]) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for r in rows:
        try:
            k = int(r["k"])
        except Exception:
            continue
        out[k] = r
    return out


def _index_nova(rows: list[dict]) -> dict[Tuple[int, int], dict]:
    out: dict[Tuple[int, int], dict] = {}
    for r in rows:
        try:
            k = int(r["k"])
            n = int(r["n_steps"])
        except Exception:
            continue
        out[(k, n)] = r
    return out


def _cmp(label: str, got: Any, exp: Any) -> str | None:
    if got == exp:
        return None
    return f"{label}: got={got!r} expected={exp!r}"


def _check_ict(prefix: str, exp: Dict[str, Any], failures: list[str], warnings: list[str]) -> None:
    path = ROOT / "eval" / f"{prefix}.json"
    if not path.exists():
        # Optional: some reviewers may only reproduce the optimized default mode.
        return
    doc = _load_json(path)
    step_rows = ((doc.get("bench_step") or {}).get("rows") or [])
    nova_rows = ((doc.get("bench_nova") or {}).get("rows") or [])
    step = _index_step(step_rows)
    nova = _index_nova(nova_rows)

    for k, exp_step in (exp.get("step_by_k") or {}).items():
        k_i = int(k)
        got_row = step.get(k_i)
        if not got_row:
            warnings.append(f"{prefix}: missing step row for k={k_i} (skipped)")
            continue
        for field in ["step_circuit_constraints", "step_fcircuit_constraints"]:
            m = _cmp(f"{prefix}:k={k_i}:{field}", got_row.get(field), exp_step.get(field))
            if m:
                failures.append(m)

    for key, exp_nova in (exp.get("nova_by_k_n") or {}).items():
        k_i = int(key.split(",")[0])
        n_i = int(key.split(",")[1])
        got_row = nova.get((k_i, n_i))
        if not got_row:
            warnings.append(f"{prefix}: missing nova row for k={k_i} n={n_i} (skipped)")
            continue
        for field in ["proof_size_bytes"]:
            m = _cmp(f"{prefix}:k={k_i}:n={n_i}:{field}", got_row.get(field), exp_nova.get(field))
            if m:
                failures.append(m)


def _check_wrap(exp: Dict[str, Any], failures: list[str], warnings: list[str]) -> None:
    path = ROOT / "eval" / "ict_express_wrap_baselines.json"
    if not path.exists():
        # Optional: EVM/wrap experiments are not required to reproduce Tables 1–2.
        return
    doc = _load_json(path)
    summaries = doc.get("summaries") or []
    by_k = {int(s.get("k")): s for s in summaries if isinstance(s, dict) and s.get("k") is not None}
    for k, exp_k in (exp.get("wrap_by_k") or {}).items():
        k_i = int(k)
        s = by_k.get(k_i)
        if not s:
            warnings.append(f"wrap: missing summary for k={k_i} (skipped)")
            continue
        wm = s.get("wrapped_metrics") or {}
        sizes = s.get("artifact_sizes_bytes") or {}
        for field, got in [
            ("calldata_bytes", wm.get("calldata_bytes")),
            ("wrapped_proof_bin", sizes.get("wrapped_proof_bin")),
        ]:
            m = _cmp(f"wrap:k={k_i}:{field}", got, exp_k.get(field))
            if m:
                failures.append(m)


def main() -> int:
    if not EXPECTED_PATH.exists():
        raise SystemExit(f"missing expected constants file: {EXPECTED_PATH}")
    expected = _load_json(EXPECTED_PATH)

    failures: list[str] = []
    warnings: list[str] = []
    _check_ict("ict_express", expected.get("assume_sorted") or {}, failures, warnings)
    _check_ict("ict_express_prove_sorting", expected.get("prove_sorting") or {}, failures, warnings)
    _check_wrap(expected, failures, warnings)

    if failures:
        sys.stderr.write("Reproducibility invariant check FAILED:\n")
        for f in failures:
            sys.stderr.write(f"- {f}\n")
        for w in warnings:
            sys.stderr.write(f"- WARN: {w}\n")
        return 2
    if warnings:
        sys.stderr.write("Reproducibility invariant check PASSED with warnings:\n")
        for w in warnings:
            sys.stderr.write(f"- WARN: {w}\n")
        return 0
    print("Reproducibility invariant check PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
