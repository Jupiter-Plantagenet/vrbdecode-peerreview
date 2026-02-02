# VRBDecode v2 (Locked Direction)

This folder contains **v2 rewritten project docs** and **ready-to-drop specs** for an implementation-first research push.

## What changed from v1
- We **lock DecodingSpec v1.0** to be unambiguous and ZK-friendly.
- We prove **verifiable stochastic decoding over a candidate set** (default `K=64`), not full-vocab top-k/top-p.
- We lock the proving stack to **arkworks R1CS + Sonobe IVC/folding + decider proof verifiable in EVM**.
- Blockchain is **required for ICBC**, **optional/minimal for ICT Express** (still 6 pages).

## Key artifacts
- `spec/DecodingSpec_v1.md` — normative decoding semantics (sorting, rounding, exp approx, top-k/top-p, sampling)
- `spec/PublicInputsSpec_v1.md` — what the proofs bind to (policy hash, seed commitment, receipt chain)
- `spec/ReceiptSpec_v1.md` — receipt chaining and transcript format
- `OUTLINE_ICTEXPRESS_6P.md` — fill-in-the-blanks paper outline (6 pages)
- `OUTLINE_ICBC_8P.md` — fill-in-the-blanks paper outline (8 pages)
- `AGENT_IMPLEMENTATION_GUIDE.md` — how to use coding agents with guardrails + tests

## Why this is "agent-proof"
The specs are written so an LLM coding agent can succeed by:
1) implementing the reference exactly,
2) matching golden vectors, and
3) passing randomized equivalence + negative tamper tests.

Date generated: 2026-01-11
