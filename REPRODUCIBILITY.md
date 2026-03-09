# Reproducibility (Peer Review)

This repo contains:
- a normative decoding/receipt specification (`spec/`)
- a Rust reference + circuit implementation (`vrbdecode-core/`, `vrbdecode-zk/`)
- evaluation runners that reproduce the Journal submission results (`eval/`, `scripts/`)

The evaluation is CPU-intensive; this guide provides both a quick sanity run and a paper-grade (long) run.

## 1) Environment

Supported: Linux/macOS (Windows via WSL recommended).

Required:
- Rust toolchain via `rustup` (locked by `rust-toolchain.toml`)
- Python 3.10+ (stdlib-only for runners; plotting needs matplotlib)

If you want to generate figures:
- `python3 -m pip install 'matplotlib>=3.8'`

Optional:
- Foundry (`anvil/forge/cast`) if you want to reproduce on-chain verification experiments.

## 2) Quick sanity check (minutes)

From repo root:

- `./ci.sh`

This runs:
- Python reference + vector tests
- Rust unit tests

## 3) Reproduce Journal Submission results (one command)

### 3.1 Quick run (reduced Ks/Ns, 1 repetition)

- `./scripts/reproduce_ict_express.sh --quick --with-figures`

Outputs:
- `eval/ict_express.json`, `eval/ict_express_step.csv`, `eval/ict_express_nova.csv`
- `eval/plots/` (PDF/PNG plots)

### 3.2 Paper-grade run (Ks={16,32,64}, Ns={32,64,128,256}, 3 reps)

- `./scripts/reproduce_ict_express.sh --full --with-ablation --with-figures`

Notes:
- This can take hours depending on CPU.
- It is resumable: re-run the same command; `eval/run_ict_express.py` will resume from `eval/*_partial.json`.

## 4) Optional: reproduce wrapped proof + local EVM verification

This requires Foundry (Anvil). The minimal wrapped run uses `N=2` by design.

- `./scripts/reproduce_ict_express.sh --wrap --verify-anvil`

## 5) Consistency check (recommended for reviewers)

After running either quick/full:

- `python3 scripts/check_repro_invariants.py`

This checks “should match exactly” fields (constraint counts, proof sizes, calldata bytes) and ignores timing fields.
