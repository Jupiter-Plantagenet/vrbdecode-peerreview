# DecodingSpec v1.0 (Normative)

**Status:** LOCKED for VRBDecode v2 MVP  
**Goal:** make stochastic decoding *unambiguous* and *machine-verifiable* so an implementation (and ZK circuit) can be tested against a reference and proven correct.

This spec defines decoding over a **candidate set** of fixed maximum size `K` (default 64). It does **not** define how the candidate set is produced from a full vocabulary.

---

## 1. Definitions

### 1.1 Types
- `u32`: unsigned 32-bit integer
- `i32`: signed 32-bit integer (two's complement)
- `u64`: unsigned 64-bit integer
- `i64`: signed 64-bit integer
- `bytes32`: 32 bytes

### 1.2 Fixed-point formats (MUST)
- Logits and intermediate scaled logits: **Q16.16** signed integers (`i32` or `i64` as needed)
- Temperature `T`: **Q16.16** unsigned integer (`u32`), MUST satisfy `T >= T_MIN`
- `top_p`: **Q16.16** unsigned in `[0, 1]`
- Exponent weights `w_i`: **Q30** unsigned (`u64`)

Constants:
- `T_MIN = 1` in Q16.16 (i.e., 1/65536). Any `T < T_MIN` MUST be clamped to `T_MIN`.

### 1.3 Rounding (MUST)
- When dividing signed fixed-point values, implementations MUST use **floor toward -∞**.
- When dividing unsigned values, implementations MUST use **floor**.
- When multiplying fixed-point values and downshifting, implementations MUST use **floor** (truncate low bits).

### 1.4 Ordering (MUST)
For each step `t`, candidates MUST be sorted by the key:
1) `scaled_logit DESC` (higher first)
2) `token_id ASC` as tie-break

This ordering is REQUIRED for top-k and top-p semantics.

---

## 2. Inputs per decoding step

### 2.1 Public parameters
- `K`: candidate set size (MAX 64 in v1.0)
- `top_k`: integer, MUST satisfy `1 <= top_k <= K`
- `top_p`: Q16.16, MUST satisfy `0 < top_p <= 1.0`
- `T`: Q16.16, unsigned, clamped to `T_MIN`

### 2.2 Step data (witness to be proven)
Arrays of length `K`:
- `token_id[i]`: `u32`
- `logit[i]`: `i32` in Q16.16

Randomness:
- `U_t`: `u64`, a uniform 64-bit value derived from a PRF (defined at protocol layer)

---

## 3. Algorithm

### 3.1 Temperature scaling (Q16.16)
Define `scaled_logit[i] = floor_div( logit[i] << 16, T_clamped )`, output in Q16.16.

- `logit[i]` is Q16.16; left-shift by 16 yields Q32.32.
- divide by Q16.16 temperature yields Q16.16 after flooring.

### 3.2 Sort
Sort candidates by `(scaled_logit DESC, token_id ASC)` producing arrays:
- `sid[i]`, `slogit[i]` for i in [0..K-1].

### 3.3 Select top-k prefix
Let `k = top_k`. Only indices `i in [0..k-1]` are eligible going forward.

### 3.4 Compute unnormalized exp-weights over top-k
We compute weights `w[i] ≈ exp( slogit[i] - m )`, where `m = max_{i<k} slogit[i]` (note `m = slogit[0]` after sorting).

Let `z[i] = slogit[i] - m` in Q16.16. Since `z[i] <= 0`, clip:
- `z[i] = max(z[i], Z_MIN)` where `Z_MIN = -12.0` in Q16.16 (i.e., `-12 << 16`)

Then compute `w[i]` in Q30 using:
- Decompose `z[i]` into integer part `n` and remainder `r` such that:
  - `n = clamp( floor(-z[i]) in Q16.16 to integer, 0..12 )`
  - `r = z[i] + (n << 16)` so `r ∈ [-1.0, 0]` in Q16.16

Precomputed constants (MUST):
Let `E[n] = round(exp(-n) * 2^30)` for n=0..12:
```
E = [
  1073741824, 395007542, 145315154, 53458458, 19666268,
  7234816, 2661540, 979126, 360200, 132510,
  48748, 17933, 6597
]
```
Compute polynomial approximation `P(r)` for `exp(r)` on r ∈ [-1, 0] using Q16.16 input and Q30 output:
```
P(r) = 1 + r + r^2/2 + r^3/6 + r^4/24 + r^5/120
```
Implementation MUST:
- compute each term in sufficiently wide integer (i128 recommended),
- use exact rational denominators via integer division with flooring,
- output `P` in Q30, clamped to [0, 2^30].

Finally:
- `w[i] = floor( E[n] * P(r) / 2^30 )` (Q30)

For i >= k: define `w[i] = 0`.

### 3.5 Apply top-p (nucleus) within top-k
Let `Wk = sum_{i<k} w[i]`.

Define threshold `TH = floor( top_p * Wk )` where `top_p` is Q16.16:
- `TH = floor( (top_p * Wk) >> 16 )`

Find smallest `s` such that `sum_{i<s} w[i] >= TH` with `1 <= s <= k`.
Eligible set becomes indices `0..s-1`.

Define `Ws = sum_{i<s} w[i]`.

### 3.6 Sample token without modulo bias (MUST)
We sample using 128-bit multiply-high to avoid modulo bias.

Let `U = U_t` as u64. Define:
- `R = high64( U * Ws )`, where the product is u128 and `high64(x) = x >> 64`.

Then choose smallest index `j` in [0..s-1] such that:
- `prefix = sum_{i<=j} w[i]`
- `prefix > R`

Output token `y = sid[j]`.

Tie-breaking is implicit via "smallest j".

---

## 4. Compliance tests (MUST)

### 4.1 Golden vectors
An implementation MUST pass a golden vector suite of >= 50 cases covering:
- ties in logits, different token_id ordering
- T very small and very large
- top_k at edges (1, K)
- top_p at edges (0.5, 0.9, 0.99, 1.0)
- z clipping at -12

### 4.2 Randomized equivalence
An implementation MUST pass >= 1000 randomized tests where:
- random logits and token ids are generated,
- DecodingSpec output is computed by a reference implementation,
- circuit/prover output matches reference exactly.

### 4.3 Negative tamper tests
Changing any of `T`, `top_k`, `top_p`, `U_t`, `t`, or output token `y` MUST be detected by verification (proof fails).

---

## 5. Notes
- This spec is designed for ZK circuits: no division by dynamic denominators in the sampling step; no full-vocab sorting.
- Full-vocab top-k/top-p can be composed as a future layer, but is out-of-scope for v1.0.
