# Testing

This repository has three practical test tiers. Most reviewers only need Tier 1 for a quick confidence check and Tier 2 for artifact-oriented validation.

## Tier 1: Fast correctness

Recommended default:

- `./ci.sh`

This script runs the Python reference tests when `pytest` is available and always runs the Rust test suites for `vrbdecode-core` and `vrbdecode-zk`.

If you only want the Rust tests:

- `cargo test -p vrbdecode-core -p vrbdecode-zk`

Key coverage in this tier:

- `vrbdecode-core/tests/vectors_equivalence.rs`: native decoder vs. golden and randomized vectors
- `vrbdecode-zk/tests/r1cs_vectors.rs`: step-circuit correctness and negative tamper cases
- `vrbdecode-zk/src/cache.rs`: serialization round-trip for cached artifacts

## Tier 2: Acceptance and proof-generation checks

These tests are marked `#[ignore]` because they are substantially slower and may take minutes to hours depending on hardware. Run them in release mode.

- `cargo test -p vrbdecode-zk --release -- --ignored`

Important coverage in this tier:

- `vrbdecode-zk/tests/sonobe_nova_step_ivc.rs`: Nova folding path
- `vrbdecode-zk/tests/pipeline_smoke.rs`: pipeline artifact generation
- `vrbdecode-zk/tests/groth16_smoke.rs`: Groth16 smoke coverage for the step circuit
- `vrbdecode-zk/tests/decider_eth_wrap_acceptance.rs`: Groth16-wrapped Nova, calldata generation, and Solidity template output

The wrap acceptance test is additionally gated behind an environment variable:

- `VRBDECODE_RUN_WRAP_TESTS=1 cargo test -p vrbdecode-zk --release -- --ignored decider_eth_wrap_acceptance`

If you want a cheaper check that stops before Groth16 setup, use the pipeline sanity mode:

- `cargo run -p vrbdecode-zk --release --bin pipeline -- --k 16 --n 2 --decider-sanity-only`

## Tier 3: Local EVM verification

This tier exercises the wrapped proof against a local Anvil node and is the right choice when you want end-to-end verification behavior, calldata, and gas measurements.

Required tools:

- Foundry: `anvil`, `forge`, `cast`
- Install helper: `bash scripts/install_foundry.sh`

Main end-to-end acceptance test:

- `VRBDECODE_RUN_EVM_TESTS=1 cargo test -p vrbdecode-zk --release -- --ignored anvil_e2e_pipeline_wrap_and_verify_acceptance`

Optional diagnostic gas probe:

- `VRBDECODE_RUN_EVM_TESTS=1 cargo test -p vrbdecode-zk --release -- --ignored anvil_precompile_gas_probe_acceptance`

The E2E test generates a small wrapped proof (`K=16`, `N=2`) and verifies it in two places:

- Rust-side decider verification
- deployment plus `eth_call` and transaction execution through `eval/chain/verify_anvil.py`

If Foundry is installed outside your `PATH`, set:

- `FOUNDRY_BIN=$HOME/.foundry/bin`

The precompile gas probe measures BN254 `ECMUL` and `ECADD` gas using `gasleft()`. If the reported deltas are implausibly low, do not use that node for paper-grade gas numbers.

## Remote EVM: Purechain

Purechain support is included for remote verification experiments and paper-grade wrapped-proof measurements.

Configuration template:

- `eval/chain/purechain.env.example`

Recommended credential handling:

- set `PURECHAIN_PRIVATE_KEY_FILE` to a local file path rather than inlining the key in the shell

Wrapped proof verification:

- `PURECHAIN_PRIVATE_KEY_FILE=~/.purechain_key python3 eval/chain/verify_purechain_wrapped.py --artifact-dir eval/artifacts/<run_id>`

Baseline Groth16 verification:

- `PURECHAIN_PRIVATE_KEY_FILE=~/.purechain_key python3 eval/chain/verify_purechain_groth16.py --verifier-sol <path> --calldata-bin <path> --out-dir <dir>`

Operational notes:

- expected chain ID: `900520900520`
- the scripts record `chain_info.json` and assert the chain ID returned by the RPC endpoint
- the current wrapper scripts use legacy transactions with `--gas-price 0`

For the wrapped-proof benchmark runner with local and remote verification:

- `python3 eval/run_ict_express_wrap_baselines.py --verify-anvil --verify-purechain`

## Evaluation-oriented commands

Common evaluation entry points:

- `python3 eval/run_ict_express.py`
- `python3 eval/run_ict_express.py --mode both`
- `python3 eval/run_constraint_breakdown.py`
- `python3 eval/run_submission.py --run-id <id> --k 16 --n 2 --verify-anvil --verify-baselines-anvil`
