# Testing (VRBDecode v3)

This repo has **two tiers** of checks:

## Tier 1: Fast correctness (default)

Runs quickly and does **not** require Foundry/Anvil/solc.

- `cargo test -p vrbdecode-zk`

What this covers
- `vrbdecode-zk/tests/r1cs_vectors.rs` checks the step R1CS (`StepCircuit`) on golden vectors and includes tamper/negative tests.
- `vrbdecode-zk/src/cache.rs` has a small serialization roundtrip test for cached artifacts.

## Tier 2: Acceptance (slow, includes folding/wrapping)

These are marked `#[ignore]` because they can take minutes to hours depending on hardware.

- Prefer running these in release mode:
  - `cargo test -p vrbdecode-zk --release -- --ignored`
  - (Debug builds can turn Groth16 setup into multi-hour runs.)

What this covers
- Nova folding correctness + tamper detection via verification failure (`vrbdecode-zk/tests/sonobe_nova_step_ivc.rs`).
- Pipeline artifact generation (`vrbdecode-zk/tests/pipeline_smoke.rs`).
- Groth16 “step circuit” smoke (still `#[ignore]`) (`vrbdecode-zk/tests/groth16_smoke.rs`).
- DeciderEth (Groth16-wrapped Nova) wrap + calldata + Solidity template generation (`vrbdecode-zk/tests/decider_eth_wrap_acceptance.rs`).
  - This one is additionally gated: set `VRBDECODE_RUN_WRAP_TESTS=1` (it can take a long time on first run).
  - For a cheaper pre-check that the Decider circuit is satisfiable (no Groth16 setup), run:
    - `cargo run -p vrbdecode-zk --release --bin pipeline -- --k 16 --n 2 --decider-sanity-only`

## Tier 3: Full E2E on a local EVM (required for submission runs)

Requires Foundry tools: `anvil`, `forge`, `cast`.
- Install (if needed): `bash scripts/install_foundry.sh`

- Prefer running this in release mode:
  - `VRBDECODE_RUN_EVM_TESTS=1 cargo test -p vrbdecode-zk --release -- --ignored anvil_e2e_pipeline_wrap_and_verify_acceptance`
  - (Diagnostics) `VRBDECODE_RUN_EVM_TESTS=1 cargo test -p vrbdecode-zk --release -- --ignored anvil_precompile_gas_probe_acceptance`

This generates a tiny wrapped proof (`K=16, N=2`) and verifies it via:
- Rust-side decider verification, then
- deploy + `eth_call` + tx on Anvil via `eval/chain/verify_anvil.py` (asserts returned bool is true and tx `status=1`).
  - The script starts Anvil with a fixed mnemonic (`"test test ... junk"`) and uses `--unlocked` accounts by default (no private key required).
  - If Foundry isn't on `PATH`, set `FOUNDRY_BIN=$HOME/.foundry/bin`.

The precompile gas probe runs a tiny contract that calls BN254 `ECMUL`/`ECADD` precompiles and measures gas deltas via `gasleft()`.
If it reports very low deltas, any “Groth16 baseline gas on-chain” numbers from that node are not paper-grade.

## Remote EVM: Purechain testnet

Purechain is a remote RPC network described as **gas-price-free**.

Security note: you pasted a private key into chat. Treat it as compromised and rotate it; do **not** commit it into the repo.

Configuration example: `eval/chain/purechain.env.example` (defaults to `http://3.34.161.207:8548`).

Wrapped proof verification (writes receipts under `chain_purechain/`):
- Recommended: `PURECHAIN_PRIVATE_KEY_FILE=~/.purechain_key python3 eval/chain/verify_purechain_wrapped.py --artifact-dir eval/artifacts/<run_id>`
- Alternative: `PURECHAIN_PRIVATE_KEY=... PURECHAIN_RPC_URL=http://3.34.161.207:8548 python3 eval/chain/verify_purechain_wrapped.py --artifact-dir eval/artifacts/<run_id>`

Baseline Groth16 verification (optional, writes receipts under your chosen `--out-dir`):
- Recommended: `PURECHAIN_PRIVATE_KEY_FILE=~/.purechain_key python3 eval/chain/verify_purechain_groth16.py --verifier-sol <path> --calldata-bin <path> --out-dir <dir>`
- Alternative: `PURECHAIN_PRIVATE_KEY=... python3 eval/chain/verify_purechain_groth16.py --verifier-sol <path> --calldata-bin <path> --out-dir <dir>`

Notes
- Purechain chainId (expected): `900520900520` (the scripts assert `eth_chainId` matches and record `chain_info.json` in the output directory).
- Purechain RPC reports no EIP-1559 support; the wrappers send legacy transactions (`--legacy`) with `--gas-price 0`.

Paper requirement
- For submission tables/plots, Purechain verification is treated as required and is produced by `python3 eval/run_ict_express_wrap_baselines.py --verify-anvil` (expects `PURECHAIN_PRIVATE_KEY_FILE` and `PURECHAIN_RPC_URL` to be set).
  - For paper-grade Purechain numbers: `python3 eval/run_ict_express_wrap_baselines.py --verify-anvil --verify-purechain` (expects `PURECHAIN_PRIVATE_KEY_FILE` and `PURECHAIN_RPC_URL` to be set).

## Evaluation runs (submission artifacts)

- Folding/IVC microbenchmarks (repeated): `python3 eval/run_ict_express.py`
- Ablation (both candidate-order modes): `python3 eval/run_ict_express.py --mode both`
  - Outputs:
    - optimized default (assume canonical sorted candidates): `eval/ict_express.json`, `eval/ict_express_step.csv`, `eval/ict_express_nova.csv`
    - baseline (prove sorting via selection-permutation): `eval/ict_express_prove_sorting.json`, `eval/ict_express_prove_sorting_step.csv`, `eval/ict_express_prove_sorting_nova.csv`
- Wrapped SNARK + EVM gas + baselines (includes baseline on-chain gas): `python3 eval/run_ict_express_wrap_baselines.py --verify-anvil`
- Constraint breakdown (StepFCircuit): `python3 eval/run_constraint_breakdown.py`
- Single run directory + consolidated `summary.json`: `python3 eval/run_submission.py --run-id <id> --k 16 --n 2 --verify-anvil --verify-baselines-anvil`
