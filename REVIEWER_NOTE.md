# Reviewer Note

This branch includes a correction to `StepFCircuit` so the folded-circuit path matches the decoding semantics described in the manuscript.

## Why this note exists

The manuscript describes the canonical-order `StepFCircuit` interface as assuming that the candidate shortlist is already in canonical sorted order while still enforcing the downstream decoding relation.

The originally exported folded-circuit code path did not fully enforce those downstream `W_s` / `R` / token-selection constraints. This branch applies the correction so the reviewer artifact matches the paper.

## What changed

- `vrbdecode-zk/src/step_circuit.rs` now enforces the folded-circuit weight pipeline, top-p threshold, `W_s`, and `R -> y` selection logic.
- `vrbdecode-zk/tests/fcircuit_semantics.rs` adds focused regression tests, including receipt-consistent wrong-`y` and wrong-`W_s` cases.

## How to read this branch

- Treat this branch as the reviewer artifact that matches the manuscript semantics.
- Repository history preserves the earlier export if a reviewer needs to compare them.
