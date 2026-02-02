# PublicInputsSpec v1.0 (Normative)

This spec defines the public inputs bound into VRBDecode proofs and receipts.

## 1. Identifiers and hashes

### 1.1 request_id
- `request_id`: `bytes32`
- MUST be unique per service request.
- Suggested: `keccak256(client_nonce || prompt_hash || provider_id)` (not required)

### 1.2 policy_hash (MUST)
`policy_hash: bytes32` binds the decoding policy.
It MUST be computed as:
```
policy_hash = keccak256(
  "VRBDecode.Policy.v1" ||
  K (u32 LE) ||
  top_k (u32 LE) ||
  top_p (u32 LE, Q16.16) ||
  T (u32 LE, Q16.16) ||
  max_tokens (u32 LE) ||
  hash_fn_id (u32 LE) ||
  exp_approx_id (u32 LE)
)
```
Where:
- `hash_fn_id`: 1=Poseidon (in-circuit), 2=Keccak (off-circuit)
- `exp_approx_id`: 1=ExpPoly5_Q16_16_to_Q30 (as in DecodingSpec v1.0)

#### 1.2.1 Circuit-native policy commitment (MUST)
Because Keccak is not circuit-friendly, the proof MUST also bind to a circuit-native commitment:

- `policy_hash_field: field_element` computed in-circuit as:
```
policy_hash_field = Poseidon(
  "VRBDecode.Policy.v1" ||
  K ||
  top_k ||
  top_p_q16 ||
  T_q16 ||
  max_tokens ||
  hash_fn_id ||
  exp_approx_id
)
```
Encoding rules:
- Domain separator bytes are absorbed as field elements `Fr(b)` for each byte `b`.
- Integers are embedded as field elements using their natural unsigned value.
- `hash_fn_id` MUST be 1 (Poseidon) for v1.
- `exp_approx_id` MUST be 1 (ExpPoly5_Q16_16_to_Q30) for v1.

Bridging rule (MUST state in paper/implementation):
- `policy_hash` (bytes32) is an interoperability commitment.
- `policy_hash_field` is the **normative, in-circuit enforced** commitment. The implementation MAY publish both.

## 2. Randomness binding

### 2.1 seed_commit (MUST)
`seed` is a 32-byte value (e.g., VRF output or agreed protocol).

For circuit-friendliness, the proof MUST bind to a field-native commitment:

- Represent `seed` as `bytes32` split into two 128-bit limbs:
  - `seed_lo` (low 128 bits), `seed_hi` (high 128 bits), both embedded into field elements.
- Define:
```
seed_commit_field = Poseidon("VRBDecode.SeedCommit.v1" || seed_lo || seed_hi)
```

The ZK proof MUST:
- take `seed` as a witness (via `seed_lo`, `seed_hi`),
- expose `seed_commit_field` as a public value, and
- enforce that it matches the Poseidon commitment above.

Interoperability (optional):
- The implementation MAY also publish `seed_commit: bytes32 = keccak256(seed)` for external systems, but the normative in-circuit binding is `seed_commit_field`.

### 2.2 per-step U_t
Per-step randomness is derived by:
```
U_t = low64( Poseidon(
  "VRBDecode.U_t.v1" ||
  request_id ||
  policy_hash_field ||
  seed_commit_field ||
  u32_le(t)
))
```
Notes:
- Domain separator bytes are absorbed as field elements.
- `request_id` is split into two 128-bit limbs (see ReceiptSpec packing) and absorbed as two field elements.
- The circuit MUST compute and enforce the same mapping.

## 3. Receipt chain commitments

### 3.1 h_0 (MUST)
`h_0: field_element` (Poseidon field) is the starting receipt state.
- For v1, `h_0` MUST be derived as:
```
h_0 = Poseidon("VRBDecode.ReceiptInit.v1" || request_id || policy_hash_field || seed_commit_field)
```
- The exact encoding is specified in ReceiptSpec v1.0.

### 3.2 h_final (MUST)
`h_final: field_element` is the final receipt state after N tokens.

The proof MUST expose `h_final` as a public output (or a hash of it if field exposure is inconvenient on-chain).

## 4. Token outputs
The proof MUST bind to either:
- the sequence of emitted token IDs (public), OR
- a rolling hash of outputs inside the receipt chain (recommended).

For v1.0 MVP:
- emitted token `y_t` is included in each receipt update (see ReceiptSpec).

## 5. Candidate-order variants (non-normative)
This spec defines receipts and public inputs in terms of the *canonical* candidate order (see `spec/ReceiptSpec_v1.md` and `spec/DecodingSpec_v1.md`). An implementation may expose different proving interfaces without changing the proved statement:
- **Assume-canonical-order interface:** candidates are provided already sorted; the circuit enforces sortedness and downstream decoding checks.
- **Prove-sorting interface:** candidates are provided in arbitrary order; the circuit additionally proves a canonicalization permutation before continuing.
