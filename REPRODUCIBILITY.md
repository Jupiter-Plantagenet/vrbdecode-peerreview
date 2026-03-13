# Reproducibility

Before running the artifact, reviewers should read `REVIEWER_NOTE.md`. This branch includes a correction that aligns `StepFCircuit` with the manuscript semantics.

This repository is organized so that a reviewer can do one of three things:

- inspect the locked specifications in `spec/`
- run a quick correctness and sanity pass
- reproduce the benchmark and artifact-generation workflows used for the submission

The heavier evaluation runs are CPU-intensive, so the commands below are ordered from fastest to slowest.

## 1. Environment

Recommended platforms:

- Linux
- macOS
- Windows via WSL

Required tools:

- Rust via `rustup` using the version pinned in `rust-toolchain.toml`
- Python 3.10+

Optional tools:

- `matplotlib` for figure generation
- Foundry (`anvil`, `forge`, `cast`) for local EVM verification

To install plotting support:

- `python3 -m pip install 'matplotlib>=3.8'`

## 2. Quick sanity check

From the repository root, run:

- `./ci.sh`

This is the fastest reviewer-oriented check. It runs the Python reference tests when `pytest` is present and then runs the Rust test suites for `vrbdecode-core` and `vrbdecode-zk`.

## 3. Reproduce the benchmark runs

### 3.1 Quick reviewer run

Use the reduced configuration first:

- `./scripts/reproduce_ict_express.sh --quick --with-figures`

This produces the main benchmark JSON and CSV files and, if `matplotlib` is installed, writes plots under `eval/plots/`.

### 3.2 Paper-grade run

For the full submission-style run:

- `./scripts/reproduce_ict_express.sh --full --with-ablation --with-figures`

This evaluates `K in {16,32,64}` and `N in {32,64,128,256}` with three repetitions. It can take hours depending on hardware.

The run is resumable. Re-running the same command will continue from the partial outputs under `eval/`.

## 4. Wrapped proof and local EVM verification

If you want to reproduce the wrapped-proof path and verify it on a local Anvil node:

- `./scripts/reproduce_ict_express.sh --wrap --verify-anvil`

This uses a minimal wrapped setting with `N=2`, which is intentional for the decider workflow.

## 5. Optional remote verification

Purechain support is included for reviewers who want remote verification receipts in addition to local Anvil runs.

For paper-grade wrapped-proof verification on both Anvil and Purechain:

- `python3 eval/run_ict_express_wrap_baselines.py --verify-anvil --verify-purechain`

This expects `PURECHAIN_PRIVATE_KEY_FILE` to be set in the environment.

## 6. Consistency checks

After a quick run or a full reproduction run, you can validate the deterministic artifact fields with:

- `python3 scripts/check_repro_invariants.py`

This script checks fields that should match exactly, such as constraint counts, proof sizes, and calldata size, while intentionally ignoring timing fields.
