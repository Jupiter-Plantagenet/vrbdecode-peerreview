# ReceiptSpec v1.0 (Normative)

Receipt chaining provides a tamper-evident transcript of the generation that can be stored, audited, or anchored on-chain.

## 1. Hash function
In-circuit receipt updates MUST use **Poseidon** over the circuit field.

On-chain contracts MAY treat receipt hashes as opaque values (no need to recompute Poseidon).

## 2. Encoding
All non-field data MUST be encoded deterministically into field elements.

### 2.1 Field packing
- `bytes32` values are split into two 128-bit limbs and mapped into two field elements.
- `u32` is embedded directly into a field element.
- `u64` is embedded directly into a field element.
- `i32` values used as inputs to candidate digests MUST be embedded as `u32` using two’s complement bit representation (i.e., bitcast).

Domain separators
- Domain separator ASCII bytes are absorbed as individual field elements `Fr(b)` for each byte `b`.

Receipt step index
- `t` is 0-indexed (first step uses `t=0`).

## 3. Receipt initialization (MUST)

The initial receipt state MUST be derived as:
```
h_0 = Poseidon(
  "VRBDecode.ReceiptInit.v1" ||
  request_id ||
  policy_hash_field ||
  seed_commit_field
)
```
Where:
- `request_id` is `bytes32` split into two 128-bit limbs.
- `policy_hash_field` and `seed_commit_field` are field elements as defined in `spec/PublicInputsSpec_v1.md`.

## 3. Receipt state update per step
Let `h_{t-1}` be previous receipt state (field element).

Define receipt update at step t:
```
h_t = Poseidon(
  "VRBDecode.Receipt.v1" ||
  h_{t-1} ||
  request_id ||
  policy_hash_field ||
  seed_commit_field ||
  t ||
  cand_hash_t ||
  y_t ||
  Ws_t ||
  R_t
)
```
Where:
- `y_t` is emitted token id (u32)
- `Ws_t` is sum of weights after top-p (u64 / Q30)
- `R_t` is the sampling threshold used (u64)
- `cand_hash_t` is a field element committing to the candidate set used at step `t` (see below)

The ZK circuit MUST compute and enforce this update.

### 3.1 Candidate digest (MUST)

For each step `t`, define:
```
cand_hash_t = Poseidon(
  "VRBDecode.Candidates.v1" ||
  token_id_sorted[0] || logit_q16_sorted[0] ||
  token_id_sorted[1] || logit_q16_sorted[1] ||
  ... ||
  token_id_sorted[K-1] || logit_q16_sorted[K-1]
)
```
Where:
- The candidates are deterministically sorted by `(scaled_logit DESC, token_id ASC)` as defined in `spec/DecodingSpec_v1.md`.
- `token_id_sorted[i]` is a `u32` embedded as a field element.
- `logit_q16_sorted[i]` is the original `i32` Q16.16 logit embedded as `u32` (two’s complement bitcast) and then embedded as a field element.

Implementation note (non-normative):
- Implementations MAY either (i) require that the candidate shortlist is provided already in this canonical order and only prove sortedness, or (ii) accept candidates in arbitrary order and additionally prove a canonicalization permutation inside the circuit. Both approaches compute the same `cand_hash_t` over the canonical order.

## 4. Final receipt
After N steps, prover outputs:
- `h_final = h_N`
- optionally `y_hash = Poseidon(y_0 || y_1 || ... || y_{N-1})` if needed

## 5. Tamper detection requirements
Changing any of:
- policy parameters (affecting policy_hash)
- seed or seed_commit
- step index t
- candidate set inputs (affecting `cand_hash_t`)
- emitted token y_t
MUST result in verification failure because the receipt chain cannot be recomputed consistently.
