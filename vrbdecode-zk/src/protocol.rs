use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};

use crate::step_circuit::poseidon_params_bn254_rate8;

pub const DS_POLICY: &[u8] = b"VRBDecode.Policy.v1";
pub const DS_SEED_COMMIT: &[u8] = b"VRBDecode.SeedCommit.v1";
pub const DS_U_T: &[u8] = b"VRBDecode.U_t.v1";
pub const DS_CANDIDATES: &[u8] = b"VRBDecode.Candidates.v1";
pub const DS_RECEIPT_INIT: &[u8] = b"VRBDecode.ReceiptInit.v1";
pub const DS_RECEIPT: &[u8] = b"VRBDecode.Receipt.v1";

fn floor_div_i128(n: i128, d: i128) -> i128 {
    if d <= 0 {
        panic!("denominator must be positive");
    }
    if n >= 0 {
        n / d
    } else {
        -((-n + d - 1) / d)
    }
}

/// Canonicalize (token_id, logit_q16) arrays in-place into the ordering used by the spec:
/// (scaled_logit DESC, token_id ASC), where scaled_logit = floor((logit_q16 << 16) / T_clamped).
///
/// This is useful for the "canonical candidate order" proving mode where the circuit assumes the
/// shortlist is already provided in canonical order and only checks sortedness.
pub fn canonicalize_candidates_in_place<const K: usize>(
    token_id: &mut [u32; K],
    logit_q16: &mut [i32; K],
    t_q16: u32,
) {
    let t_clamped = t_q16.max(1);

    let mut slog_native: [i64; K] = [0i64; K];
    for i in 0..K {
        let num = (logit_q16[i] as i128) << 16;
        let q = floor_div_i128(num, t_clamped as i128) as i64;
        slog_native[i] = q;
    }

    let mut perm: Vec<usize> = (0..K).collect();
    perm.sort_by(|&i, &j| {
        let li = slog_native[i];
        let lj = slog_native[j];
        if li != lj {
            return lj.cmp(&li);
        }
        token_id[i].cmp(&token_id[j])
    });

    let tok0 = *token_id;
    let log0 = *logit_q16;
    for (out_idx, &src_idx) in perm.iter().enumerate() {
        token_id[out_idx] = tok0[src_idx];
        logit_q16[out_idx] = log0[src_idx];
    }
}

pub fn policy_hash_field(
    k: u32,
    top_k: u32,
    top_p_q16: u32,
    t_q16: u32,
    max_tokens: u32,
    hash_fn_id: u32,
    exp_approx_id: u32,
) -> Fr {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in DS_POLICY {
        elems.push(Fr::from(b as u64));
    }
    elems.push(Fr::from(k as u64));
    elems.push(Fr::from(top_k as u64));
    elems.push(Fr::from(top_p_q16 as u64));
    elems.push(Fr::from(t_q16 as u64));
    elems.push(Fr::from(max_tokens as u64));
    elems.push(Fr::from(hash_fn_id as u64));
    elems.push(Fr::from(exp_approx_id as u64));

    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn seed_commit_field(seed_lo: Fr, seed_hi: Fr) -> Fr {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in DS_SEED_COMMIT {
        elems.push(Fr::from(b as u64));
    }
    elems.push(seed_lo);
    elems.push(seed_hi);

    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn prf_u_t(
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_field: Fr,
    seed_commit_field: Fr,
    step_idx: u32,
) -> u64 {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in DS_U_T {
        elems.push(Fr::from(b as u64));
    }
    elems.push(request_id_lo);
    elems.push(request_id_hi);
    elems.push(policy_hash_field);
    elems.push(seed_commit_field);
    elems.push(Fr::from(step_idx as u64));

    sponge.absorb(&elems);
    let out = sponge.squeeze_native_field_elements(1)[0];
    let mut bytes = out.into_bigint().to_bytes_le();
    bytes.resize(8, 0u8);
    u64::from_le_bytes(bytes[0..8].try_into().expect("len"))
}

pub fn receipt_init(
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_field: Fr,
    seed_commit_field: Fr,
) -> Fr {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in DS_RECEIPT_INIT {
        elems.push(Fr::from(b as u64));
    }
    elems.push(request_id_lo);
    elems.push(request_id_hi);
    elems.push(policy_hash_field);
    elems.push(seed_commit_field);

    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn candidate_hash<const K: usize>(
    token_id: &[u32; K],
    logit_q16: &[i32; K],
    t_q16: u32,
) -> Fr {
    let t_clamped = t_q16.max(1);

    let mut slog_native: Vec<i64> = Vec::with_capacity(K);
    for i in 0..K {
        let num = (logit_q16[i] as i128) << 16;
        let q = floor_div_i128(num, t_clamped as i128) as i64;
        slog_native.push(q);
    }

    let mut perm: Vec<usize> = (0..K).collect();
    perm.sort_by(|&i, &j| {
        let li = slog_native[i];
        let lj = slog_native[j];
        if li != lj {
            return lj.cmp(&li);
        }
        token_id[i].cmp(&token_id[j])
    });

    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in DS_CANDIDATES {
        elems.push(Fr::from(b as u64));
    }
    for &idx in &perm {
        elems.push(Fr::from(token_id[idx] as u64));
        elems.push(Fr::from(logit_q16[idx] as u32 as u64));
    }

    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn receipt_update(
    h_prev: Fr,
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_field: Fr,
    seed_commit_field: Fr,
    step_idx: u32,
    cand_hash: Fr,
    y: u32,
    ws: u64,
    r: u64,
) -> Fr {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in DS_RECEIPT {
        elems.push(Fr::from(b as u64));
    }
    elems.push(h_prev);
    elems.push(request_id_lo);
    elems.push(request_id_hi);
    elems.push(policy_hash_field);
    elems.push(seed_commit_field);
    elems.push(Fr::from(step_idx as u64));
    elems.push(cand_hash);
    elems.push(Fr::from(y as u64));
    elems.push(Fr::from(ws));
    elems.push(Fr::from(r));

    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}
