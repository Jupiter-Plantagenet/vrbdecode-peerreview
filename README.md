# VRBDecode Peer Review Repository

This repository is the peer-review artifact for VRBDecode. It contains the locked protocol and decoding specifications, the Rust reference implementation, the ZK circuits, and the evaluation runners used to reproduce the submission artifacts. This branch includes a correction to `StepFCircuit` so the folded-circuit path matches the manuscript semantics; see `REVIEWER_NOTE.md`.

## Start Here

- `REPRODUCIBILITY.md`: environment setup and reproduction commands
- `TESTING.md`: test tiers, slow tests, and EVM verification notes
- `REVIEWER_NOTE.md`: brief note on the `StepFCircuit` correction in this branch
- `spec/`: normative decoding, receipt, and public-input specifications

## Quick Start

1. Install Rust via `rustup` and Python 3.10+.
2. From the repository root, run `./ci.sh`.
3. For a reduced reproduction run, use `./scripts/reproduce_ict_express.sh --quick --with-figures`.
4. For wrapped-proof generation and local EVM verification, use `./scripts/reproduce_ict_express.sh --wrap --verify-anvil`.

## Repository Layout

- `spec/`: normative protocol and decoding specs
- `vrbdecode-core/`: native Rust decoding implementation
- `vrbdecode-zk/`: R1CS, folding, wrapping, and proving code
- `vectors/`: golden and randomized test vectors
- `eval/`: evaluation runners, plots, and verification helpers
- `scripts/`: convenience scripts for reviewer workflows

## Notes

- This branch includes the `StepFCircuit` correction and regression tests described in `REVIEWER_NOTE.md`.
- This export intentionally excludes paper sources. The export metadata is recorded in `EXPORT_METADATA.txt`.
- Linux and macOS are the primary targets. On Windows, WSL is the recommended environment.
