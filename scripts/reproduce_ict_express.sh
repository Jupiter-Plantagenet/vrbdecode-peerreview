#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./scripts/reproduce_ict_express.sh [--quick|--full] [--with-ablation] [--with-figures] [--wrap] [--verify-anvil]

Modes:
  --quick          Ks={16,32,64}, Ns={32,64}, reps=1 (fast sanity run)
  --full           Ks={16,32,64}, Ns={32,64,128,256}, reps=3 (paper-grade; slow)

Options:
  --with-ablation  Also run prove-sorting baseline (for Table 2 ablation)
  --with-figures   Generate plots under eval/plots (requires matplotlib)
  --wrap           Run wrapped proof + baselines runner (N=2)
  --verify-anvil   When used with --wrap, verify on local Anvil (requires Foundry)

EOF
}

MODE="quick"
WITH_ABLATION=0
WITH_FIGURES=0
DO_WRAP=0
VERIFY_ANVIL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) MODE="quick"; shift ;;
    --full) MODE="full"; shift ;;
    --with-ablation) WITH_ABLATION=1; shift ;;
    --with-figures) WITH_FIGURES=1; shift ;;
    --wrap) DO_WRAP=1; shift ;;
    --verify-anvil) VERIFY_ANVIL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

cd "$ROOT"

KS="16,32,64"
NS="32,64"
REPS="1"
ATTEMPTS="1"
FIXED_TARGET_DIR="reviewer_quick"
if [[ "$MODE" == "full" ]]; then
  NS="32,64,128,256"
  REPS="3"
  ATTEMPTS="3"
  FIXED_TARGET_DIR="reviewer_full"
fi

echo "[reproduce] mode=$MODE ks=$KS ns=$NS reps=$REPS"
python3 eval/run_ict_express.py --ks "$KS" --ns "$NS" --reps "$REPS" --attempts "$ATTEMPTS" --fixed-target-dir "$FIXED_TARGET_DIR"

if [[ "$WITH_ABLATION" == "1" ]]; then
  echo "[reproduce] running ablation baseline (prove-sorting)"
  python3 eval/run_ict_express.py --mode prove_sorting --ks "$KS" --ns "$NS" --reps "$REPS" --attempts "$ATTEMPTS" --fixed-target-dir "${FIXED_TARGET_DIR}_prove_sorting"
fi

if [[ "$WITH_FIGURES" == "1" ]]; then
  if ! python3 -c "import matplotlib" >/dev/null 2>&1; then
    echo "[reproduce] matplotlib is required for --with-figures" >&2
    echo "[reproduce] install: python3 -m pip install 'matplotlib>=3.8'" >&2
    exit 2
  fi

  echo "[reproduce] generating plots (requires matplotlib)"
  python3 eval/plot_ict_express.py --step-csv eval/ict_express_step.csv --nova-csv eval/ict_express_nova.csv --out-dir eval/plots
fi

if [[ "$DO_WRAP" == "1" ]]; then
  echo "[reproduce] running wrapped proof + baselines (N=2)"
  WRAP_ARGS=(python3 eval/run_ict_express_wrap_baselines.py --ks "$KS" --n-wrap 2 --run-prefix ict_wrap_reviewer --reuse-existing)
  # If artifacts are missing, rerun without --reuse-existing.
  if ! "${WRAP_ARGS[@]}" >/dev/null 2>&1; then
    WRAP_ARGS=(python3 eval/run_ict_express_wrap_baselines.py --ks "$KS" --n-wrap 2 --run-prefix ict_wrap_reviewer)
    if [[ "$VERIFY_ANVIL" == "1" ]]; then
      WRAP_ARGS+=(--verify-anvil)
    fi
    "${WRAP_ARGS[@]}"
  else
    # Reuse existing succeeded; optionally still verify-anvil is not meaningful without regeneration.
    python3 eval/run_ict_express_wrap_baselines.py --ks "$KS" --n-wrap 2 --run-prefix ict_wrap_reviewer --reuse-existing
  fi
fi

echo "[reproduce] done"
