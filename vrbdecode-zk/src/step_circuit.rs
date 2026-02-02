use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::FieldVar,
    fields::fp::FpVar,
    select::CondSelectGadget,
    uint32::UInt32,
    uint64::UInt64,
    GR1CSVar,
};
use folding_schemes::frontend::FCircuit;
use folding_schemes::Error;
use serde::Serialize;
use std::borrow::Borrow;

const Q30: u64 = 1 << 30;
const Z_MIN_Q16: i64 = -(12 << 16);
const E_Q30: [u64; 13] = [
    1073741824, 395007542, 145315154, 53458458, 19666268, 7234816, 2661540, 979126, 360200,
    132510, 48748, 17933, 6597,
];

pub fn poseidon_params_bn254_rate8() -> PoseidonConfig<Fr> {
    let rate = 8usize;
    let capacity = 1usize;
    let full_rounds = 8usize;
    let partial_rounds = 57usize;
    let alpha = 5u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0u64,
    );
    PoseidonConfig {
        full_rounds,
        partial_rounds,
        alpha,
        ark,
        mds,
        rate,
        capacity,
    }
}

fn mul_q30_i64(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) >> 30) as i64
}

fn mul_shift30_i64(a: i64, b: i64) -> (i64, u32) {
    let prod: i128 = (a as i128) * (b as i128);
    let q: i64 = (prod >> 30) as i64;
    let rem: i128 = prod - ((q as i128) << 30);
    (q, rem as u32)
}

fn div_euclid_i64(x: i64, d: i64) -> (i64, u32) {
    let q: i64 = floor_div_i128(x as i128, d as i128) as i64;
    let rem: i128 = (x as i128) - (q as i128) * (d as i128);
    (q, rem as u32)
}

fn exp_poly5_q16_16_to_q30(r_q16: i64) -> u64 {
    let r_q30: i64 = r_q16 << 14;

    let r2: i64 = mul_q30_i64(r_q30, r_q30);
    let r3: i64 = mul_q30_i64(r2, r_q30);
    let r4: i64 = mul_q30_i64(r3, r_q30);
    let r5: i64 = mul_q30_i64(r4, r_q30);

    let mut p: i128 = Q30 as i128;
    p += r_q30 as i128;
    p += (r2 as i128) / 2;
    p += floor_div_i128(r3 as i128, 6);
    p += (r4 as i128) / 24;
    p += floor_div_i128(r5 as i128, 120);

    if p <= 0 {
        return 0;
    }
    if p >= Q30 as i128 {
        return Q30;
    }
    p as u64
}

fn fp_from_bits_le(bits: &[Boolean<Fr>]) -> FpVar<Fr> {
    let mut acc = FpVar::Constant(Fr::from(0u64));
    let mut coeff = Fr::from(1u64);
    for b in bits {
        let b_fp: FpVar<Fr> = b.clone().into();
        acc += b_fp * FpVar::Constant(coeff);
        coeff *= Fr::from(2u64);
    }
    acc
}

fn fp_from_uint32_le(u: &UInt32<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    Ok(fp_from_bits_le(&u.to_bits_le()?))
}

fn fp_from_uint64_le(u: &UInt64<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    Ok(fp_from_bits_le(&u.to_bits_le()?))
}

fn enforce_fp_lt_2pow128(x: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let bits = x.to_bits_le()?;
    for i in 128..bits.len() {
        bits[i].enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

fn uint64_is_ge(a: &UInt64<Fr>, b: &UInt64<Fr>) -> Result<Boolean<Fr>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut eq = Boolean::TRUE;
    let mut gt = Boolean::FALSE;
    for i in (0..64).rev() {
        let ai = &a_bits[i];
        let bi = &b_bits[i];
        let not_bi = !bi.clone();
        let ai_and_not_bi = ai & &not_bi;
        let gt_i = &eq & &ai_and_not_bi;
        gt = &gt | &gt_i;

        let ai_xor_bi = ai ^ bi;
        let bit_eq = !ai_xor_bi;
        eq = &eq & &bit_eq;
    }
    Ok(&gt | &eq)
}

fn int64_is_ge(a: &UInt64<Fr>, b: &UInt64<Fr>) -> Result<Boolean<Fr>, SynthesisError> {
    let sign_mask64 = UInt64::constant(0x8000_0000_0000_0000u64);
    let a_key = a ^ &sign_mask64;
    let b_key = b ^ &sign_mask64;
    uint64_is_ge(&a_key, &b_key)
}

fn pow2_64() -> Fr {
    Fr::from(2u64).pow([64u64])
}

fn floor_div_i128(n: i128, d: i128) -> i128 {
    if d <= 0 {
        return 0;
    }
    if n >= 0 {
        n / d
    } else {
        -((-n + d - 1) / d)
    }
}

fn signed_fp_from_u64(u: &UInt64<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let bits = u.to_bits_le()?;
    let u_fp = fp_from_bits_le(&bits);
    let sign_fp: FpVar<Fr> = bits[63].clone().into();
    Ok(u_fp - sign_fp * FpVar::Constant(pow2_64()))
}

fn uint32_is_ge(a: &UInt32<Fr>, b: &UInt32<Fr>) -> Result<Boolean<Fr>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut eq = Boolean::TRUE;
    let mut gt = Boolean::FALSE;
    for i in (0..32).rev() {
        let ai = &a_bits[i];
        let bi = &b_bits[i];
        let not_bi = !bi.clone();
        let ai_and_not_bi = ai & &not_bi;
        let gt_i = &eq & &ai_and_not_bi;
        gt = &gt | &gt_i;

        let ai_xor_bi = ai ^ bi;
        let bit_eq = !ai_xor_bi;
        eq = &eq & &bit_eq;
    }
    Ok(&gt | &eq)
}

#[derive(Clone)]
pub struct StepCircuit<const K: usize> {
    pub top_k: u32,
    pub top_p_q16: u32,
    pub t_q16: u32,
    pub max_tokens: u32,
    pub token_id: Vec<u32>,
    pub logit_q16: Vec<i32>,
    pub u_t: u64,
    pub expected_y: u32,
    pub expected_ws: u64,
    pub expected_r: u64,
    pub expected_lo: u64,
    pub request_id_lo: Fr,
    pub request_id_hi: Fr,
    pub policy_hash_field: Fr,
    pub seed_commit_field: Fr,
    pub seed_lo: Fr,
    pub seed_hi: Fr,
    pub step_idx: u32,
    pub h_prev: Fr,
    pub h_new: Fr,
}

impl<const K: usize> ConstraintSynthesizer<Fr> for StepCircuit<K> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.token_id.len() != K || self.logit_q16.len() != K {
            return Err(SynthesisError::AssignmentMissing);
        }

        if !K.is_power_of_two() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let top_k_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.top_k as u64)),
            AllocationMode::Input,
        )?;
        let top_p_q16_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.top_p_q16 as u64)),
            AllocationMode::Input,
        )?;
        let t_q16_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.t_q16 as u64)),
            AllocationMode::Input,
        )?;
        let max_tokens_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.max_tokens as u64)),
            AllocationMode::Input,
        )?;

        let token_id = self
            .token_id
            .iter()
            .map(|v| UInt32::new_variable(cs.clone(), || Ok(*v), AllocationMode::Witness))
            .collect::<Result<Vec<_>, _>>()?;

        let logit_q16 = self
            .logit_q16
            .iter()
            .map(|v| UInt32::new_variable(cs.clone(), || Ok(*v as u32), AllocationMode::Witness))
            .collect::<Result<Vec<_>, _>>()?;

        let u_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.u_t)),
            AllocationMode::Input,
        )?;
        let ws_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.expected_ws)),
            AllocationMode::Input,
        )?;
        let r_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.expected_r)),
            AllocationMode::Input,
        )?;
        let y_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.expected_y as u64)),
            AllocationMode::Input,
        )?;

        let request_id_lo_in = FpVar::new_variable(
            cs.clone(),
            || Ok(self.request_id_lo),
            AllocationMode::Input,
        )?;
        let request_id_hi_in = FpVar::new_variable(
            cs.clone(),
            || Ok(self.request_id_hi),
            AllocationMode::Input,
        )?;
        let policy_hash_field_in = FpVar::new_variable(
            cs.clone(),
            || Ok(self.policy_hash_field),
            AllocationMode::Input,
        )?;
        let seed_commit_field_in = FpVar::new_variable(
            cs.clone(),
            || Ok(self.seed_commit_field),
            AllocationMode::Input,
        )?;
        let step_idx_in = FpVar::new_variable(
            cs.clone(),
            || Ok(Fr::from(self.step_idx as u64)),
            AllocationMode::Input,
        )?;
        let h_prev_in = FpVar::new_variable(cs.clone(), || Ok(self.h_prev), AllocationMode::Input)?;
        let h_new_in = FpVar::new_variable(cs.clone(), || Ok(self.h_new), AllocationMode::Input)?;

        enforce_fp_lt_2pow128(&request_id_lo_in)?;
        enforce_fp_lt_2pow128(&request_id_hi_in)?;
        // policy_hash_field_in and seed_commit_field_in are field elements and are not limb-restricted.

        let seed_lo = FpVar::new_variable(cs.clone(), || Ok(self.seed_lo), AllocationMode::Witness)?;
        let seed_hi = FpVar::new_variable(cs.clone(), || Ok(self.seed_hi), AllocationMode::Witness)?;
        enforce_fp_lt_2pow128(&seed_lo)?;
        enforce_fp_lt_2pow128(&seed_hi)?;

        let top_k = UInt32::new_variable(cs.clone(), || Ok(self.top_k), AllocationMode::Witness)?;
        let top_p_q16 =
            UInt32::new_variable(cs.clone(), || Ok(self.top_p_q16), AllocationMode::Witness)?;
        let t_q16 = UInt32::new_variable(cs.clone(), || Ok(self.t_q16), AllocationMode::Witness)?;
        let max_tokens = UInt32::new_variable(cs.clone(), || Ok(self.max_tokens), AllocationMode::Witness)?;
        let u = UInt64::new_variable(cs.clone(), || Ok(self.u_t), AllocationMode::Witness)?;
        let ws = UInt64::new_variable(cs.clone(), || Ok(self.expected_ws), AllocationMode::Witness)?;
        let r = UInt64::new_variable(cs.clone(), || Ok(self.expected_r), AllocationMode::Witness)?;
        let y = UInt32::new_variable(cs.clone(), || Ok(self.expected_y), AllocationMode::Witness)?;

        let step_idx = UInt32::new_variable(cs.clone(), || Ok(self.step_idx), AllocationMode::Witness)?;

        uint32_is_ge(&top_k, &UInt32::constant(1u32))?.enforce_equal(&Boolean::TRUE)?;
        uint32_is_ge(&UInt32::constant(K as u32), &top_k)?.enforce_equal(&Boolean::TRUE)?;
        uint32_is_ge(&UInt32::constant(0x0001_0000u32), &top_p_q16)?.enforce_equal(&Boolean::TRUE)?;
        top_p_q16
            .is_eq(&UInt32::constant(0u32))?
            .enforce_equal(&Boolean::FALSE)?;

        let t_is_zero = t_q16.is_eq(&UInt32::constant(0u32))?;
        let t_clamped = UInt32::conditionally_select(&t_is_zero, &UInt32::constant(1u32), &t_q16)?;

        fp_from_uint32_le(&top_k)?.enforce_equal(&top_k_in)?;
        fp_from_uint32_le(&top_p_q16)?.enforce_equal(&top_p_q16_in)?;
        fp_from_uint32_le(&t_q16)?.enforce_equal(&t_q16_in)?;
        fp_from_uint32_le(&max_tokens)?.enforce_equal(&max_tokens_in)?;
        fp_from_uint64_le(&u)?.enforce_equal(&u_in)?;
        fp_from_uint64_le(&ws)?.enforce_equal(&ws_in)?;
        fp_from_uint64_le(&r)?.enforce_equal(&r_in)?;
        fp_from_uint32_le(&y)?.enforce_equal(&y_in)?;

        fp_from_uint32_le(&step_idx)?.enforce_equal(&step_idx_in)?;

        // Enforce seed commitment.
        let poseidon_params = poseidon_params_bn254_rate8();
        let mut seed_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &poseidon_params);
        for &b in b"VRBDecode.SeedCommit.v1" {
            seed_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        seed_sponge.absorb(&seed_lo)?;
        seed_sponge.absorb(&seed_hi)?;
        let seed_commit_out = seed_sponge.squeeze_field_elements(1)?;
        seed_commit_out[0].enforce_equal(&seed_commit_field_in)?;

        // Enforce policy commitment.
        let mut pol_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &poseidon_params);
        for &b in b"VRBDecode.Policy.v1" {
            pol_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        pol_sponge.absorb(&FpVar::Constant(Fr::from(K as u64)))?;
        pol_sponge.absorb(&top_k_in)?;
        pol_sponge.absorb(&top_p_q16_in)?;
        pol_sponge.absorb(&t_q16_in)?;
        pol_sponge.absorb(&max_tokens_in)?;
        pol_sponge.absorb(&FpVar::Constant(Fr::from(1u64)))?;
        pol_sponge.absorb(&FpVar::Constant(Fr::from(1u64)))?;
        let pol_out = pol_sponge.squeeze_field_elements(1)?;
        pol_out[0].enforce_equal(&policy_hash_field_in)?;

        // Enforce receipt initialization when step_idx==0.
        let is_first = step_idx.is_eq(&UInt32::constant(0u32))?;
        let is_first_fp: FpVar<Fr> = is_first.clone().into();
        let mut init_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &poseidon_params);
        for &b in b"VRBDecode.ReceiptInit.v1" {
            init_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        init_sponge.absorb(&request_id_lo_in)?;
        init_sponge.absorb(&request_id_hi_in)?;
        init_sponge.absorb(&policy_hash_field_in)?;
        init_sponge.absorb(&seed_commit_field_in)?;
        let init_out = init_sponge.squeeze_field_elements(1)?;
        let diff = h_prev_in.clone() - init_out[0].clone();
        (diff * is_first_fp).enforce_equal(&FpVar::Constant(Fr::from(0u64)))?;

        let lo = UInt64::new_variable(cs.clone(), || Ok(self.expected_lo), AllocationMode::Witness)?;

        let u_fp = fp_from_uint64_le(&u)?;
        let ws_fp = fp_from_uint64_le(&ws)?;
        let r_fp = fp_from_uint64_le(&r)?;
        let lo_fp = fp_from_uint64_le(&lo)?;

        let two_pow_64 = pow2_64();
        let prod = u_fp * ws_fp;
        let rhs = r_fp * FpVar::Constant(two_pow_64) + lo_fp;
        prod.enforce_equal(&rhs)?;

        let t_clamped_native = self.t_q16.max(1);
        let mut slog_native: Vec<i64> = Vec::with_capacity(K);
        let mut rem_native: Vec<u32> = Vec::with_capacity(K);
        for i in 0..K {
            let num = (self.logit_q16[i] as i128) << 16;
            let q = floor_div_i128(num, t_clamped_native as i128) as i64;
            let rem = (num - (q as i128) * (t_clamped_native as i128)) as i128;
            slog_native.push(q);
            rem_native.push(rem as u32);
        }

        let mut slog: Vec<UInt64<Fr>> = Vec::with_capacity(K);
        let mut _rem: Vec<UInt32<Fr>> = Vec::with_capacity(K);
        let d_fp = fp_from_uint32_le(&t_clamped)?;
        for i in 0..K {
            let q_u64 = slog_native[i] as u64;
            let q = UInt64::new_variable(cs.clone(), || Ok(q_u64), AllocationMode::Witness)?;
            let r = UInt32::new_variable(cs.clone(), || Ok(rem_native[i]), AllocationMode::Witness)?;

            let logit_bits = logit_q16[i].to_bits_le()?;
            let sign = logit_bits[31].clone();
            let mut ext = Vec::with_capacity(64);
            ext.extend_from_slice(&logit_bits);
            for _ in 32..64 {
                ext.push(sign.clone());
            }
            let mut num_bits = Vec::with_capacity(64);
            for _ in 0..16 {
                num_bits.push(Boolean::FALSE);
            }
            for j in 0..48 {
                num_bits.push(ext[j].clone());
            }
            let num_u64 = UInt64::from_bits_le(&num_bits);

            let num_fp = signed_fp_from_u64(&num_u64)?;
            let q_fp = signed_fp_from_u64(&q)?;
            let r_fp = fp_from_uint32_le(&r)?;
            num_fp.enforce_equal(&(q_fp * d_fp.clone() + r_fp))?;

            let r_ge_d = uint32_is_ge(&r, &t_clamped)?;
            r_ge_d.enforce_equal(&Boolean::FALSE)?;

            slog.push(q);
            _rem.push(r);
        }

        let mut perm: Vec<usize> = (0..K).collect();
        perm.sort_by(|&i, &j| {
            let li = slog_native[i];
            let lj = slog_native[j];
            if li != lj {
                return lj.cmp(&li);
            }
            self.token_id[i].cmp(&self.token_id[j])
        });

        let mut sid_sorted_native: Vec<u32> = Vec::with_capacity(K);
        let mut slog_sorted_native: Vec<i64> = Vec::with_capacity(K);
        for &idx in &perm {
            sid_sorted_native.push(self.token_id[idx]);
            slog_sorted_native.push(slog_native[idx]);
        }

        let top_k_native = self.top_k as usize;
        let mut w_native: Vec<u64> = vec![0u64; K];
        let mut z_clip_native: Vec<i64> = vec![0i64; K];
        let mut neg_z_native: Vec<u64> = vec![0u64; K];
        let mut n_native: Vec<u32> = vec![0u32; K];
        let mut rem16_native: Vec<u32> = vec![0u32; K];
        let mut r_native: Vec<i64> = vec![0i64; K];
        let mut r_q30_native: Vec<i64> = vec![0i64; K];
        let mut r2_native: Vec<i64> = vec![0i64; K];
        let mut r3_native: Vec<i64> = vec![0i64; K];
        let mut r4_native: Vec<i64> = vec![0i64; K];
        let mut r5_native: Vec<i64> = vec![0i64; K];
        let mut r2_rem30_native: Vec<u32> = vec![0u32; K];
        let mut r3_rem30_native: Vec<u32> = vec![0u32; K];
        let mut r4_rem30_native: Vec<u32> = vec![0u32; K];
        let mut r5_rem30_native: Vec<u32> = vec![0u32; K];
        let mut r2_div2_native: Vec<i64> = vec![0i64; K];
        let mut r2_div2_rem_native: Vec<u32> = vec![0u32; K];
        let mut r3_div6_native: Vec<i64> = vec![0i64; K];
        let mut r3_div6_rem_native: Vec<u32> = vec![0u32; K];
        let mut r4_div24_native: Vec<i64> = vec![0i64; K];
        let mut r4_div24_rem_native: Vec<u32> = vec![0u32; K];
        let mut r5_div120_native: Vec<i64> = vec![0i64; K];
        let mut r5_div120_rem_native: Vec<u32> = vec![0u32; K];
        let mut p_raw_native: Vec<i64> = vec![0i64; K];
        let mut p_clamped_native: Vec<u64> = vec![0u64; K];
        let mut w_rem30_native: Vec<u32> = vec![0u32; K];
        if top_k_native > 0 {
            let m = slog_sorted_native[0];
            for i in 0..top_k_native.min(K) {
                let mut z = slog_sorted_native[i] - m;
                if z < Z_MIN_Q16 {
                    z = Z_MIN_Q16;
                }
                z_clip_native[i] = z;
                let neg_z = -z;
                neg_z_native[i] = neg_z as u64;
                let mut n = (neg_z >> 16) as i64;
                if n < 0 {
                    n = 0;
                }
                if n > 12 {
                    n = 12;
                }
                n_native[i] = n as u32;
                rem16_native[i] = (neg_z as u32) & 0xFFFF;
                let r = z + (n << 16);
                r_native[i] = r;

                let r_q30: i64 = r << 14;
                r_q30_native[i] = r_q30;
                let (r2, r2_rem30) = mul_shift30_i64(r_q30, r_q30);
                r2_native[i] = r2;
                r2_rem30_native[i] = r2_rem30;
                let (r3, r3_rem30) = mul_shift30_i64(r2, r_q30);
                r3_native[i] = r3;
                r3_rem30_native[i] = r3_rem30;
                let (r4, r4_rem30) = mul_shift30_i64(r3, r_q30);
                r4_native[i] = r4;
                r4_rem30_native[i] = r4_rem30;
                let (r5, r5_rem30) = mul_shift30_i64(r4, r_q30);
                r5_native[i] = r5;
                r5_rem30_native[i] = r5_rem30;

                let (r2_div2, r2_div2_rem) = div_euclid_i64(r2, 2);
                r2_div2_native[i] = r2_div2;
                r2_div2_rem_native[i] = r2_div2_rem;
                let (r3_div6, r3_div6_rem) = div_euclid_i64(r3, 6);
                r3_div6_native[i] = r3_div6;
                r3_div6_rem_native[i] = r3_div6_rem;
                let (r4_div24, r4_div24_rem) = div_euclid_i64(r4, 24);
                r4_div24_native[i] = r4_div24;
                r4_div24_rem_native[i] = r4_div24_rem;
                let (r5_div120, r5_div120_rem) = div_euclid_i64(r5, 120);
                r5_div120_native[i] = r5_div120;
                r5_div120_rem_native[i] = r5_div120_rem;

                let p_raw: i64 = (Q30 as i64)
                    + r_q30
                    + r2_div2
                    + r3_div6
                    + r4_div24
                    + r5_div120;
                p_raw_native[i] = p_raw;

                let p = exp_poly5_q16_16_to_q30(r);
                p_clamped_native[i] = p;
                let prod_w: u128 = (E_Q30[n as usize] as u128) * (p as u128);
                let wi = (prod_w >> 30) as u64;
                let wrem = (prod_w & ((1u128 << 30) - 1)) as u32;
                w_native[i] = wi;
                w_rem30_native[i] = wrem;
            }
        }

        let mut prefix_native: Vec<u64> = vec![0u64; K];
        let mut acc: u64 = 0;
        for i in 0..K {
            acc = acc.wrapping_add(w_native[i]);
            prefix_native[i] = acc;
        }

        let wk_native: u64 = acc;
        let prod_th_native = (self.top_p_q16 as u128) * (wk_native as u128);
        let th_native = (prod_th_native >> 16) as u64;
        let th_rem_native = (prod_th_native & 0xFFFF) as u32;

        let mut _stop_idx_native: usize = 0;
        if top_k_native > 0 {
            let mut p: u64 = 0;
            for i in 0..top_k_native.min(K) {
                p = p.wrapping_add(w_native[i]);
                if p >= th_native {
                    _stop_idx_native = i;
                    break;
                }
            }
        }

        let log_k = (K as u64).trailing_zeros() as usize;
        let mut idx_bits_le: Vec<Vec<Boolean<Fr>>> = Vec::with_capacity(K);
        for &idx in &perm {
            let mut bits = Vec::with_capacity(log_k);
            for b in 0..log_k {
                let bit = ((idx >> b) & 1) == 1;
                bits.push(Boolean::new_variable(cs.clone(), || Ok(bit), AllocationMode::Witness)?);
            }
            idx_bits_le.push(bits);
        }

        if K > 64 {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut pow2_table: Vec<UInt64<Fr>> = Vec::with_capacity(K);
        for j in 0..K {
            pow2_table.push(UInt64::constant(1u64 << j));
        }
        let mut pow_sum = FpVar::Constant(Fr::from(0u64));
        for i in 0..K {
            let mut bits_be = idx_bits_le[i].clone();
            bits_be.reverse();
            let pow = UInt64::conditionally_select_power_of_two_vector(&bits_be, &pow2_table)?;
            pow_sum += fp_from_uint64_le(&pow)?;
        }
        let full_mask: u64 = if K == 64 { u64::MAX } else { (1u64 << K) - 1 };
        pow_sum.enforce_equal(&FpVar::Constant(Fr::from(full_mask)))?;

        let mut sorted_token_id: Vec<UInt32<Fr>> = Vec::with_capacity(K);
        let mut sorted_slog: Vec<UInt64<Fr>> = Vec::with_capacity(K);
        let mut sorted_logit_q16: Vec<UInt32<Fr>> = Vec::with_capacity(K);
        for i in 0..K {
            let mut bits_be = idx_bits_le[i].clone();
            bits_be.reverse();
            let sel_token = UInt32::conditionally_select_power_of_two_vector(&bits_be, &token_id)?;
            let sel_slog = UInt64::conditionally_select_power_of_two_vector(&bits_be, &slog)?;
            let sel_logit = UInt32::conditionally_select_power_of_two_vector(&bits_be, &logit_q16)?;
            sorted_token_id.push(sel_token);
            sorted_slog.push(sel_slog);
            sorted_logit_q16.push(sel_logit);
        }

        let w: Vec<UInt64<Fr>> = (0..K)
            .map(|i| UInt64::new_variable(cs.clone(), || Ok(w_native[i]), AllocationMode::Witness))
            .collect::<Result<Vec<_>, _>>()?;

        let z_min_u64 = UInt64::constant(Z_MIN_Q16 as u64);
        let zero_i64 = UInt64::constant(0u64);
        let minus_one_q16 = UInt64::constant((-((1i64) << 16)) as u64);

        let m_slog = sorted_slog[0].clone();
        let m_fp = signed_fp_from_u64(&m_slog)?;

        for i in 0..K {
            let i_lt_topk = uint32_is_ge(&top_k, &UInt32::constant((i as u32) + 1u32))?;
            let b_fp: FpVar<Fr> = i_lt_topk.clone().into();

            let z = UInt64::new_variable(cs.clone(), || Ok((slog_sorted_native[i] - slog_sorted_native[0]) as u64), AllocationMode::Witness)?;
            let z_clip = UInt64::new_variable(cs.clone(), || Ok(z_clip_native[i] as u64), AllocationMode::Witness)?;
            let neg_z = UInt64::new_variable(cs.clone(), || Ok(neg_z_native[i]), AllocationMode::Witness)?;
            let n = UInt32::new_variable(cs.clone(), || Ok(n_native[i]), AllocationMode::Witness)?;
            let rem16 = UInt32::new_variable(cs.clone(), || Ok(rem16_native[i]), AllocationMode::Witness)?;
            let r_q16 = UInt64::new_variable(cs.clone(), || Ok(r_native[i] as u64), AllocationMode::Witness)?;

            let slog_i_fp = signed_fp_from_u64(&sorted_slog[i])?;
            let z_fp = signed_fp_from_u64(&z)?;
            (z_fp - (slog_i_fp - m_fp.clone()))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let ge_zmin = int64_is_ge(&z, &z_min_u64)?;
            let z_clip_sel = UInt64::conditionally_select(&ge_zmin, &z, &z_min_u64)?;
            let z_clip_diff = signed_fp_from_u64(&z_clip)? - signed_fp_from_u64(&z_clip_sel)?;
            z_clip_diff.mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let le_zero = int64_is_ge(&zero_i64, &z_clip)?;
            let le_zero_fp: FpVar<Fr> = le_zero.into();
            (le_zero_fp - FpVar::Constant(Fr::from(1u64)))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let neg_z_fp = signed_fp_from_u64(&neg_z)?;
            let zc_fp = signed_fp_from_u64(&z_clip)?;
            (neg_z_fp + zc_fp)
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;
            let neg_z_bits = neg_z.to_bits_le()?;
            neg_z_bits[63].enforce_equal(&Boolean::FALSE)?;

            let rem16_bits = rem16.to_bits_le()?;
            for bit in 16..32 {
                rem16_bits[bit].enforce_equal(&Boolean::FALSE)?;
            }

            uint32_is_ge(&UInt32::constant(12u32), &n)?.enforce_equal(&Boolean::TRUE)?;

            let neg_z_u = fp_from_uint64_le(&neg_z)?;
            let n_fp = fp_from_uint32_le(&n)?;
            let rem16_fp = fp_from_uint32_le(&rem16)?;
            let two_pow_16_fp = FpVar::Constant(Fr::from(1u64 << 16));
            (neg_z_u - (n_fp.clone() * two_pow_16_fp.clone() + rem16_fp))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let r_fp = signed_fp_from_u64(&r_q16)?;
            let zc_fp2 = signed_fp_from_u64(&z_clip)?;
            let n_shift_fp = n_fp * two_pow_16_fp;
            (r_fp - (zc_fp2 + n_shift_fp))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            int64_is_ge(&r_q16, &minus_one_q16)?.enforce_equal(&Boolean::TRUE)?;
            int64_is_ge(&zero_i64, &r_q16)?.enforce_equal(&Boolean::TRUE)?;

            let r_q30 = UInt64::new_variable(
                cs.clone(),
                || Ok(r_q30_native[i] as u64),
                AllocationMode::Witness,
            )?;
            let r2 = UInt64::new_variable(cs.clone(), || Ok(r2_native[i] as u64), AllocationMode::Witness)?;
            let r3 = UInt64::new_variable(cs.clone(), || Ok(r3_native[i] as u64), AllocationMode::Witness)?;
            let r4 = UInt64::new_variable(cs.clone(), || Ok(r4_native[i] as u64), AllocationMode::Witness)?;
            let r5 = UInt64::new_variable(cs.clone(), || Ok(r5_native[i] as u64), AllocationMode::Witness)?;

            let r2_rem30 = UInt32::new_variable(
                cs.clone(),
                || Ok(r2_rem30_native[i]),
                AllocationMode::Witness,
            )?;
            let r3_rem30 = UInt32::new_variable(
                cs.clone(),
                || Ok(r3_rem30_native[i]),
                AllocationMode::Witness,
            )?;
            let r4_rem30 = UInt32::new_variable(
                cs.clone(),
                || Ok(r4_rem30_native[i]),
                AllocationMode::Witness,
            )?;
            let r5_rem30 = UInt32::new_variable(
                cs.clone(),
                || Ok(r5_rem30_native[i]),
                AllocationMode::Witness,
            )?;

            let r2_div2 = UInt64::new_variable(
                cs.clone(),
                || Ok(r2_div2_native[i] as u64),
                AllocationMode::Witness,
            )?;
            let r2_div2_rem = UInt32::new_variable(
                cs.clone(),
                || Ok(r2_div2_rem_native[i]),
                AllocationMode::Witness,
            )?;
            let r3_div6 = UInt64::new_variable(
                cs.clone(),
                || Ok(r3_div6_native[i] as u64),
                AllocationMode::Witness,
            )?;
            let r3_div6_rem = UInt32::new_variable(
                cs.clone(),
                || Ok(r3_div6_rem_native[i]),
                AllocationMode::Witness,
            )?;
            let r4_div24 = UInt64::new_variable(
                cs.clone(),
                || Ok(r4_div24_native[i] as u64),
                AllocationMode::Witness,
            )?;
            let r4_div24_rem = UInt32::new_variable(
                cs.clone(),
                || Ok(r4_div24_rem_native[i]),
                AllocationMode::Witness,
            )?;
            let r5_div120 = UInt64::new_variable(
                cs.clone(),
                || Ok(r5_div120_native[i] as u64),
                AllocationMode::Witness,
            )?;
            let r5_div120_rem = UInt32::new_variable(
                cs.clone(),
                || Ok(r5_div120_rem_native[i]),
                AllocationMode::Witness,
            )?;
            let p_raw = UInt64::new_variable(cs.clone(), || Ok(p_raw_native[i] as u64), AllocationMode::Witness)?;
            let p_clamped = UInt64::new_variable(
                cs.clone(),
                || Ok(p_clamped_native[i]),
                AllocationMode::Witness,
            )?;
            let w_rem30 = UInt32::new_variable(
                cs.clone(),
                || Ok(w_rem30_native[i]),
                AllocationMode::Witness,
            )?;

            let r_q16_fp = signed_fp_from_u64(&r_q16)?;
            let r_q30_fp = signed_fp_from_u64(&r_q30)?;
            let two_pow_14_fp = FpVar::Constant(Fr::from(1u64 << 14));
            (r_q30_fp.clone() - (r_q16_fp * two_pow_14_fp))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let rem30s = [&r2_rem30, &r3_rem30, &r4_rem30, &r5_rem30, &w_rem30];
            for rem in rem30s {
                let rem_bits = rem.to_bits_le()?;
                for bit in 30..32 {
                    rem_bits[bit].enforce_equal(&Boolean::FALSE)?;
                }
            }

            let two_pow_30_fp = FpVar::Constant(Fr::from(1u64 << 30));

            let r2_fp = signed_fp_from_u64(&r2)?;
            let r3_fp = signed_fp_from_u64(&r3)?;
            let r4_fp = signed_fp_from_u64(&r4)?;
            let r5_fp = signed_fp_from_u64(&r5)?;

            let r2_rem_fp = fp_from_uint32_le(&r2_rem30)?;
            let r3_rem_fp = fp_from_uint32_le(&r3_rem30)?;
            let r4_rem_fp = fp_from_uint32_le(&r4_rem30)?;
            let r5_rem_fp = fp_from_uint32_le(&r5_rem30)?;

            let prod_r2 = r_q30_fp.clone() * r_q30_fp.clone();
            let r2_decomp = r2_fp.clone() * two_pow_30_fp.clone() + r2_rem_fp;
            (prod_r2 - r2_decomp).mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let prod_r3 = r2_fp.clone() * r_q30_fp.clone();
            let r3_decomp = r3_fp.clone() * two_pow_30_fp.clone() + r3_rem_fp;
            (prod_r3 - r3_decomp).mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let prod_r4 = r3_fp.clone() * r_q30_fp.clone();
            let r4_decomp = r4_fp.clone() * two_pow_30_fp.clone() + r4_rem_fp;
            (prod_r4 - r4_decomp).mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let prod_r5 = r4_fp.clone() * r_q30_fp.clone();
            let r5_decomp = r5_fp.clone() * two_pow_30_fp.clone() + r5_rem_fp;
            (prod_r5 - r5_decomp).mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let d2 = FpVar::Constant(Fr::from(2u64));
            let d6 = FpVar::Constant(Fr::from(6u64));
            let d24 = FpVar::Constant(Fr::from(24u64));
            let d120 = FpVar::Constant(Fr::from(120u64));

            uint32_is_ge(&r2_div2_rem, &UInt32::constant(2u32))?.enforce_equal(&Boolean::FALSE)?;
            uint32_is_ge(&r3_div6_rem, &UInt32::constant(6u32))?.enforce_equal(&Boolean::FALSE)?;
            uint32_is_ge(&r4_div24_rem, &UInt32::constant(24u32))?.enforce_equal(&Boolean::FALSE)?;
            uint32_is_ge(&r5_div120_rem, &UInt32::constant(120u32))?.enforce_equal(&Boolean::FALSE)?;

            let r2_div2_rem_bits = r2_div2_rem.to_bits_le()?;
            let r3_div6_rem_bits = r3_div6_rem.to_bits_le()?;
            let r4_div24_rem_bits = r4_div24_rem.to_bits_le()?;
            let r5_div120_rem_bits = r5_div120_rem.to_bits_le()?;
            for bit in 7..32 {
                r3_div6_rem_bits[bit].enforce_equal(&Boolean::FALSE)?;
                r4_div24_rem_bits[bit].enforce_equal(&Boolean::FALSE)?;
                r5_div120_rem_bits[bit].enforce_equal(&Boolean::FALSE)?;
            }
            for bit in 1..32 {
                r2_div2_rem_bits[bit].enforce_equal(&Boolean::FALSE)?;
            }

            let r2_div2_fp = signed_fp_from_u64(&r2_div2)?;
            let r2_div2_rem_fp = fp_from_uint32_le(&r2_div2_rem)?;
            (r2_fp - (r2_div2_fp.clone() * d2 + r2_div2_rem_fp))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let r3_div6_fp = signed_fp_from_u64(&r3_div6)?;
            let r3_div6_rem_fp = fp_from_uint32_le(&r3_div6_rem)?;
            (r3_fp - (r3_div6_fp.clone() * d6 + r3_div6_rem_fp))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let r4_div24_fp = signed_fp_from_u64(&r4_div24)?;
            let r4_div24_rem_fp = fp_from_uint32_le(&r4_div24_rem)?;
            (r4_fp - (r4_div24_fp.clone() * d24 + r4_div24_rem_fp))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let r5_div120_fp = signed_fp_from_u64(&r5_div120)?;
            let r5_div120_rem_fp = fp_from_uint32_le(&r5_div120_rem)?;
            (r5_fp - (r5_div120_fp.clone() * d120 + r5_div120_rem_fp))
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let p_raw_fp = signed_fp_from_u64(&p_raw)?;
            let q30_fp = FpVar::Constant(Fr::from(Q30));
            let p_expr = q30_fp
                + r_q30_fp.clone()
                + r2_div2_fp.clone()
                + r3_div6_fp.clone()
                + r4_div24_fp.clone()
                + r5_div120_fp.clone();
            (p_raw_fp - p_expr).mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            uint64_is_ge(&UInt64::constant(Q30), &p_clamped)?.enforce_equal(&Boolean::TRUE)?;
            let p_le_zero = int64_is_ge(&zero_i64, &p_raw)?;
            let p_ge_q30 = int64_is_ge(&p_raw, &UInt64::constant(Q30))?;
            let p_nonneg = UInt64::conditionally_select(&p_le_zero, &UInt64::constant(0u64), &p_raw)?;
            let p_sel =
                UInt64::conditionally_select(&p_ge_q30, &UInt64::constant(Q30), &p_nonneg)?;
            let p_clamped_fp = fp_from_uint64_le(&p_clamped)?;
            let p_sel_fp = fp_from_uint64_le(&p_sel)?;
            (p_clamped_fp - p_sel_fp)
                .mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;

            let n_bits = n.to_bits_le()?;
            let n_bits_be = vec![
                n_bits[3].clone(),
                n_bits[2].clone(),
                n_bits[1].clone(),
                n_bits[0].clone(),
            ];
            let mut e_table: Vec<UInt64<Fr>> = Vec::with_capacity(16);
            for j in 0..16 {
                let v = if j < 13 { E_Q30[j] } else { 0u64 };
                e_table.push(UInt64::constant(v));
            }
            let e_n = UInt64::conditionally_select_power_of_two_vector(&n_bits_be, &e_table)?;
            let e_fp = fp_from_uint64_le(&e_n)?;
            let p_fp = fp_from_uint64_le(&p_clamped)?;
            let prod_w_fp = e_fp * p_fp;
            let w_fp = fp_from_uint64_le(&w[i])?;
            let w_rem_fp = fp_from_uint32_le(&w_rem30)?;
            let w_decomp = w_fp * two_pow_30_fp + w_rem_fp;
            (prod_w_fp - w_decomp).mul_equals(&b_fp, &FpVar::Constant(Fr::from(0u64)))?;
        }

        for i in 0..K {
            uint64_is_ge(&UInt64::constant(Q30), &w[i])?.enforce_equal(&Boolean::TRUE)?;
            let i_lt_topk = uint32_is_ge(&top_k, &UInt32::constant((i as u32) + 1u32))?;
            let w_allowed =
                UInt64::conditionally_select(&i_lt_topk, &w[i], &UInt64::constant(0u64))?;
            w[i].enforce_equal(&w_allowed)?;
        }

        let prefix: Vec<UInt64<Fr>> = (0..K)
            .map(|i| {
                UInt64::new_variable(cs.clone(), || Ok(prefix_native[i]), AllocationMode::Witness)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let w0_fp = fp_from_uint64_le(&w[0])?;
        let p0_fp = fp_from_uint64_le(&prefix[0])?;
        p0_fp.enforce_equal(&w0_fp)?;
        for i in 1..K {
            let pi_fp = fp_from_uint64_le(&prefix[i])?;
            let pim1_fp = fp_from_uint64_le(&prefix[i - 1])?;
            let wi_fp = fp_from_uint64_le(&w[i])?;
            pi_fp.enforce_equal(&(pim1_fp + wi_fp))?;
            uint64_is_ge(&prefix[i], &prefix[i - 1])?.enforce_equal(&Boolean::TRUE)?;
        }

        let wk_fp = fp_from_uint64_le(&prefix[K - 1])?;
        let top_p_fp = fp_from_uint32_le(&top_p_q16)?;
        let th = UInt64::new_variable(cs.clone(), || Ok(th_native), AllocationMode::Witness)?;
        let th_rem =
            UInt32::new_variable(cs.clone(), || Ok(th_rem_native), AllocationMode::Witness)?;

        let th_rem_bits = th_rem.to_bits_le()?;
        for b in 16..32 {
            th_rem_bits[b].enforce_equal(&Boolean::FALSE)?;
        }

        let th_fp = fp_from_uint64_le(&th)?;
        let th_rem_fp = fp_from_uint32_le(&th_rem)?;
        let prod_th_fp = top_p_fp * wk_fp;
        let two_pow_16 = FpVar::Constant(Fr::from(1u64 << 16));
        prod_th_fp.enforce_equal(&(th_fp * two_pow_16 + th_rem_fp))?;

        let prefix_ge_th: Vec<Boolean<Fr>> = (0..K)
            .map(|i| uint64_is_ge(&prefix[i], &th))
            .collect::<Result<Vec<_>, _>>()?;

        let mut stop: Vec<Boolean<Fr>> = Vec::with_capacity(K);
        stop.push(prefix_ge_th[0].clone());
        for i in 1..K {
            let not_prev = !prefix_ge_th[i - 1].clone();
            stop.push(&prefix_ge_th[i] & &not_prev);
        }
        let mut stop_sum = FpVar::Constant(Fr::from(0u64));
        for i in 0..K {
            let b: FpVar<Fr> = stop[i].clone().into();
            stop_sum += b;
        }
        stop_sum.enforce_equal(&FpVar::Constant(Fr::from(1u64)))?;

        let mut ws_calc = FpVar::Constant(Fr::from(0u64));
        for i in 0..K {
            let stop_fp: FpVar<Fr> = stop[i].clone().into();
            let pi_fp = fp_from_uint64_le(&prefix[i])?;
            ws_calc += pi_fp * stop_fp;
        }
        fp_from_uint64_le(&ws)?.enforce_equal(&ws_calc)?;
        ws.is_eq(&UInt64::constant(0u64))?
            .enforce_equal(&Boolean::FALSE)?;

        let prefix_gt_r: Vec<Boolean<Fr>> = (0..K)
            .map(|i| {
                let ge = uint64_is_ge(&prefix[i], &r)?;
                let eq = prefix[i].is_eq(&r)?;
                let not_eq = !eq;
                Ok(&ge & &not_eq)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut choose: Vec<Boolean<Fr>> = Vec::with_capacity(K);
        choose.push(prefix_gt_r[0].clone());
        for i in 1..K {
            let not_prev = !prefix_gt_r[i - 1].clone();
            choose.push(&prefix_gt_r[i] & &not_prev);
        }

        for i in 1..K {
            let prev_ge_th = prefix_ge_th[i - 1].clone();
            (&choose[i] & &prev_ge_th).enforce_equal(&Boolean::FALSE)?;
        }
        let mut choose_sum = FpVar::Constant(Fr::from(0u64));
        for i in 0..K {
            let b: FpVar<Fr> = choose[i].clone().into();
            choose_sum += b;
        }
        choose_sum.enforce_equal(&FpVar::Constant(Fr::from(1u64)))?;

        let mut y_calc = sorted_token_id[0].clone();
        for i in 1..K {
            y_calc = UInt32::conditionally_select(&choose[i], &sorted_token_id[i], &y_calc)?;
        }
        y_calc.enforce_equal(&y)?;

        let mut y_in_topk = Vec::with_capacity(K);
        for j in 0..K {
            let y_eq_j = sorted_token_id[j].is_eq(&y)?;
            let j_lt_topk = uint32_is_ge(&top_k, &UInt32::constant((j as u32) + 1u32))?;
            y_in_topk.push(&y_eq_j & &j_lt_topk);
        }
        Boolean::kary_or(&y_in_topk)?.enforce_equal(&Boolean::TRUE)?;

        let sign_mask64 = UInt64::constant(0x8000_0000_0000_0000u64);
        for i in 0..(K - 1) {
            let a_key = &sorted_slog[i] ^ &sign_mask64;
            let b_key = &sorted_slog[i + 1] ^ &sign_mask64;
            let ge_logits = uint64_is_ge(&a_key, &b_key)?;
            ge_logits.enforce_equal(&Boolean::TRUE)?;

            let eq_logits = sorted_slog[i].is_eq(&sorted_slog[i + 1])?;
            let ge_tokens = uint32_is_ge(&sorted_token_id[i + 1], &sorted_token_id[i])?;
            let not_ge_tokens = !ge_tokens;
            let bad = &eq_logits & &not_ge_tokens;
            bad.enforce_equal(&Boolean::FALSE)?;
        }

        let poseidon_params = poseidon_params_bn254_rate8();

        let mut u_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &poseidon_params);
        for &b in b"VRBDecode.U_t.v1" {
            u_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        u_sponge.absorb(&request_id_lo_in)?;
        u_sponge.absorb(&request_id_hi_in)?;
        u_sponge.absorb(&policy_hash_field_in)?;
        u_sponge.absorb(&seed_commit_field_in)?;
        let step_idx_fp = fp_from_uint32_le(&step_idx)?;
        u_sponge.absorb(&step_idx_fp)?;
        let u_out = u_sponge.squeeze_field_elements(1)?;
        let u_bits = u_out[0].to_bits_le()?;
        let u_bits_64 = u_bits.into_iter().take(64).collect::<Vec<_>>();
        let u_prf = UInt64::from_bits_le(&u_bits_64);
        u_prf.enforce_equal(&u)?;

        let mut cand_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &poseidon_params);
        for &b in b"VRBDecode.Candidates.v1" {
            cand_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        for i in 0..K {
            let tok_fp = fp_from_uint32_le(&sorted_token_id[i])?;
            let logit_fp = fp_from_uint32_le(&sorted_logit_q16[i])?;
            cand_sponge.absorb(&tok_fp)?;
            cand_sponge.absorb(&logit_fp)?;
        }
        let cand_hash = cand_sponge.squeeze_field_elements(1)?;

        let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &poseidon_params);
        for &b in b"VRBDecode.Receipt.v1" {
            sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        sponge.absorb(&h_prev_in)?;
        sponge.absorb(&request_id_lo_in)?;
        sponge.absorb(&request_id_hi_in)?;
        sponge.absorb(&policy_hash_field_in)?;
        sponge.absorb(&seed_commit_field_in)?;
        sponge.absorb(&step_idx_fp)?;
        sponge.absorb(&cand_hash[0])?;
        let y_fp = fp_from_uint32_le(&y)?;
        let ws_fp = fp_from_uint64_le(&ws)?;
        let r_fp = fp_from_uint64_le(&r)?;
        sponge.absorb(&y_fp)?;
        sponge.absorb(&ws_fp)?;
        sponge.absorb(&r_fp)?;
        let out = sponge.squeeze_field_elements(1)?;
        out[0].enforce_equal(&h_new_in)?;

        Ok(())
    }
}

/// External inputs for StepFCircuit - per-step witness data not part of folded state.
/// Contains per-step witness data (candidate set + expected outputs) and private seed witness
/// used to bind to the public `seed_commit_field`.
#[derive(Clone, Debug)]
pub struct StepExternalInputs<const K: usize> {
    pub seed_lo: Fr,
    pub seed_hi: Fr,
    pub token_id: [u32; K],
    pub logit_q16: [i32; K],
    pub expected_y: u32,
    pub expected_ws: u64,
    pub expected_r: u64,
    pub expected_lo: u64,
    pub h_new: Fr,
}

impl<const K: usize> Default for StepExternalInputs<K> {
    fn default() -> Self {
        Self {
            seed_lo: Fr::from(0u64),
            seed_hi: Fr::from(0u64),
            token_id: [0u32; K],
            logit_q16: [0i32; K],
            expected_y: 0,
            expected_ws: 1,
            expected_r: 0,
            expected_lo: 0,
            h_new: Fr::from(0u64),
        }
    }
}

/// Allocated variables for StepExternalInputs in R1CS.
#[derive(Clone, Debug)]
pub struct StepExternalInputsVar<const K: usize> {
    pub seed_lo: FpVar<Fr>,
    pub seed_hi: FpVar<Fr>,
    pub token_id: [UInt32<Fr>; K],
    pub logit_q16: [UInt32<Fr>; K],
    pub expected_y: UInt32<Fr>,
    pub expected_ws: UInt64<Fr>,
    pub expected_r: UInt64<Fr>,
    pub expected_lo: UInt64<Fr>,
    pub h_new: FpVar<Fr>,
}

impl<const K: usize> AllocVar<StepExternalInputs<K>, Fr> for StepExternalInputsVar<K> {
    fn new_variable<T: Borrow<StepExternalInputs<K>>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let binding = f()?;
        let val = binding.borrow();

        let seed_lo = FpVar::new_variable(cs.clone(), || Ok(val.seed_lo), mode)?;
        let seed_hi = FpVar::new_variable(cs.clone(), || Ok(val.seed_hi), mode)?;

        let token_id: [UInt32<Fr>; K] = std::array::from_fn(|i| {
            UInt32::new_variable(cs.clone(), || Ok(val.token_id[i]), mode).unwrap()
        });
        let logit_q16: [UInt32<Fr>; K] = std::array::from_fn(|i| {
            UInt32::new_variable(cs.clone(), || Ok(val.logit_q16[i] as u32), mode).unwrap()
        });

        let expected_y = UInt32::new_variable(cs.clone(), || Ok(val.expected_y), mode)?;
        let expected_ws = UInt64::new_variable(cs.clone(), || Ok(val.expected_ws), mode)?;
        let expected_r = UInt64::new_variable(cs.clone(), || Ok(val.expected_r), mode)?;
        let expected_lo = UInt64::new_variable(cs.clone(), || Ok(val.expected_lo), mode)?;
        let h_new = FpVar::new_variable(cs.clone(), || Ok(val.h_new), mode)?;

        Ok(Self {
            seed_lo,
            seed_hi,
            token_id,
            logit_q16,
            expected_y,
            expected_ws,
            expected_r,
            expected_lo,
            h_new,
        })
    }
}

/// Variant that proves sorting inside the circuit by applying a selection-permutation.
/// This accepts candidates in arbitrary order (more general) but is more expensive.
pub type StepFCircuitUnsorted<const K: usize> = StepFCircuit<K, true>;

/// Sonobe FCircuit for full StepCircuit semantics.
/// Folded state z_i (public) includes:
/// - request_id limbs (2x 128-bit)
/// - policy parameters (top_k, top_p_q16, T_q16, max_tokens) as u32 embedded in the field
/// - policy_hash_field (public) (enforced in-circuit)
/// - seed_commit_field (public) (enforced in-circuit via private seed witness)
/// - h_prev (receipt state)
/// The step_idx is derived from Nova's internal step counter i.
#[derive(Clone, Debug)]
pub struct StepFCircuit<const K: usize, const PROVE_SORTING: bool = false> {
    poseidon_config: PoseidonConfig<Fr>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConstraintBreakdownPoint {
    pub label: &'static str,
    pub constraints_total: usize,
}

impl<const K: usize, const PROVE_SORTING: bool> StepFCircuit<K, PROVE_SORTING> {
    pub fn new_default() -> Result<Self, Error> {
        Ok(Self {
            poseidon_config: poseidon_params_bn254_rate8(),
        })
    }

    pub fn generate_step_constraints_with_breakdown(
        &self,
        cs: ConstraintSystemRef<Fr>,
        i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: StepExternalInputsVar<K>,
        breakdown: &mut Vec<ConstraintBreakdownPoint>,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        self.generate_step_constraints_inner(cs, i, z_i, external_inputs, Some(breakdown))
    }

    fn generate_step_constraints_inner(
        &self,
        cs: ConstraintSystemRef<Fr>,
        i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: StepExternalInputsVar<K>,
        mut breakdown: Option<&mut Vec<ConstraintBreakdownPoint>>,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let mut record = |label: &'static str| {
            if let Some(out) = breakdown.as_mut() {
                (**out).push(ConstraintBreakdownPoint {
                    label,
                    constraints_total: cs.num_constraints(),
                });
            }
        };

        record("start");
        if !K.is_power_of_two() || K > 64 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Unpack folded state z_i
        let request_id_lo = z_i[0].clone();
        let request_id_hi = z_i[1].clone();
        let top_k_fp = z_i[2].clone();
        let top_p_q16_fp = z_i[3].clone();
        let t_q16_fp = z_i[4].clone();
        let max_tokens_fp = z_i[5].clone();
        let policy_hash_field_fp = z_i[6].clone();
        let seed_commit_field_fp = z_i[7].clone();
        let h_prev = z_i[8].clone();

        // Enforce 128-bit bounds on request_id limbs (bytes32 split into 2x 128-bit).
        enforce_fp_lt_2pow128(&request_id_lo)?;
        enforce_fp_lt_2pow128(&request_id_hi)?;
        record("request_id_bounds");

        // step_idx = i (Nova's step counter, 0-indexed)
        let step_idx = UInt32::new_variable(cs.clone(), || Ok(i as u32), AllocationMode::Witness)?;
        let step_idx_fp = fp_from_uint32_le(&step_idx)?;

        // Decode policy params from folded state as u32 without requiring witness values
        // (preprocessing can synthesize the circuit without concrete assignments).
        let uint32_from_fp = |fp: &FpVar<Fr>| -> Result<UInt32<Fr>, SynthesisError> {
            let bits = fp.to_bits_le()?;
            for i in 32..bits.len() {
                bits[i].enforce_equal(&Boolean::FALSE)?;
            }
            Ok(UInt32::from_bits_le(&bits[..32]))
        };

        let top_k = uint32_from_fp(&top_k_fp)?;
        let top_p_q16 = uint32_from_fp(&top_p_q16_fp)?;
        let t_q16 = uint32_from_fp(&t_q16_fp)?;
        let _max_tokens = uint32_from_fp(&max_tokens_fp)?;
        record("policy_decode");

        // Private seed witness; enforce the public seed_commit_field.
        enforce_fp_lt_2pow128(&external_inputs.seed_lo)?;
        enforce_fp_lt_2pow128(&external_inputs.seed_hi)?;

        let mut seed_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_config);
        for &b in b"VRBDecode.SeedCommit.v1" {
            seed_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        seed_sponge.absorb(&external_inputs.seed_lo)?;
        seed_sponge.absorb(&external_inputs.seed_hi)?;
        let seed_commit_out = seed_sponge.squeeze_field_elements(1)?;
        seed_commit_out[0].enforce_equal(&seed_commit_field_fp)?;
        record("seed_commit");

        // Enforce policy_hash_field from policy parameters.
        // v1 constants: hash_fn_id=1 (Poseidon), exp_approx_id=1 (ExpPoly5_Q16_16_to_Q30)
        let mut pol_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_config);
        for &b in b"VRBDecode.Policy.v1" {
            pol_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        pol_sponge.absorb(&FpVar::Constant(Fr::from(K as u64)))?;
        pol_sponge.absorb(&top_k_fp)?;
        pol_sponge.absorb(&top_p_q16_fp)?;
        pol_sponge.absorb(&t_q16_fp)?;
        pol_sponge.absorb(&max_tokens_fp)?;
        pol_sponge.absorb(&FpVar::Constant(Fr::from(1u64)))?;
        pol_sponge.absorb(&FpVar::Constant(Fr::from(1u64)))?;
        let pol_out = pol_sponge.squeeze_field_elements(1)?;
        pol_out[0].enforce_equal(&policy_hash_field_fp)?;
        record("policy_hash");

        // Enforce receipt initialization at step 0: h_prev == Poseidon(ReceiptInit || request_id || policy_hash_field || seed_commit_field)
        let is_first = step_idx.is_eq(&UInt32::constant(0u32))?;
        let is_first_fp: FpVar<Fr> = is_first.clone().into();
        let mut init_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_config);
        for &b in b"VRBDecode.ReceiptInit.v1" {
            init_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        init_sponge.absorb(&request_id_lo)?;
        init_sponge.absorb(&request_id_hi)?;
        init_sponge.absorb(&policy_hash_field_fp)?;
        init_sponge.absorb(&seed_commit_field_fp)?;
        let init_out = init_sponge.squeeze_field_elements(1)?;
        let diff = h_prev.clone() - init_out[0].clone();
        (diff * is_first_fp).enforce_equal(&FpVar::Constant(Fr::from(0u64)))?;
        record("receipt_init_gate");

        let token_id = &external_inputs.token_id;
        let logit_q16 = &external_inputs.logit_q16;

        // Enforce policy param bounds
        uint32_is_ge(&top_k, &UInt32::constant(1u32))?.enforce_equal(&Boolean::TRUE)?;
        uint32_is_ge(&UInt32::constant(K as u32), &top_k)?.enforce_equal(&Boolean::TRUE)?;
        uint32_is_ge(&UInt32::constant(0x0001_0000u32), &top_p_q16)?.enforce_equal(&Boolean::TRUE)?;
        top_p_q16
            .is_eq(&UInt32::constant(0u32))?
            .enforce_equal(&Boolean::FALSE)?;

        let t_is_zero = t_q16.is_eq(&UInt32::constant(0u32))?;
        let t_clamped = UInt32::conditionally_select(&t_is_zero, &UInt32::constant(1u32), &t_q16)?;
        record("policy_param_bounds");

        // Compute PRF for u_t
        let mut u_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_config);
        for &b in b"VRBDecode.U_t.v1" {
            u_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        u_sponge.absorb(&request_id_lo)?;
        u_sponge.absorb(&request_id_hi)?;
        u_sponge.absorb(&policy_hash_field_fp)?;
        u_sponge.absorb(&seed_commit_field_fp)?;
        u_sponge.absorb(&step_idx_fp)?;
        let u_out = u_sponge.squeeze_field_elements(1)?;
        let u_bits = u_out[0].to_bits_le()?;
        let u_bits_64 = u_bits.into_iter().take(64).collect::<Vec<_>>();
        let u = UInt64::from_bits_le(&u_bits_64);
        record("u_t");

        // Expected outputs from external inputs
        let y = &external_inputs.expected_y;
        let ws = &external_inputs.expected_ws;
        let r = &external_inputs.expected_r;
        let lo = &external_inputs.expected_lo;
        let h_new = &external_inputs.h_new;

        // Verify u * ws = r * 2^64 + lo
        let u_fp = fp_from_uint64_le(&u)?;
        let ws_fp = fp_from_uint64_le(ws)?;
        let r_fp = fp_from_uint64_le(r)?;
        let lo_fp = fp_from_uint64_le(lo)?;
        let two_pow_64 = pow2_64();
        let prod = u_fp * ws_fp.clone();
        let rhs = r_fp.clone() * FpVar::Constant(two_pow_64) + lo_fp;
        prod.enforce_equal(&rhs)?;

        // ws must be non-zero
        ws.is_eq(&UInt64::constant(0u64))?
            .enforce_equal(&Boolean::FALSE)?;
        record("ws_arithmetic");

        // Generate native witness values for constraint verification
        // (This mirrors the native computation to get intermediate values)
        let _top_k_native = top_k.value().unwrap_or(1);
        let t_clamped_native = t_q16.value().unwrap_or(1).max(1);

        let token_id_native: Vec<u32> = (0..K)
            .map(|j| token_id[j].value().unwrap_or(0))
            .collect();
        let logit_q16_native: Vec<i32> = (0..K)
            .map(|j| logit_q16[j].value().unwrap_or(0) as i32)
            .collect();

        let mut slog_native: Vec<i64> = Vec::with_capacity(K);
        let mut rem_native: Vec<u32> = Vec::with_capacity(K);
        for j in 0..K {
            let num = (logit_q16_native[j] as i128) << 16;
            let q = floor_div_i128(num, t_clamped_native as i128) as i64;
            let rem = (num - (q as i128) * (t_clamped_native as i128)) as i128;
            slog_native.push(q);
            rem_native.push(rem as u32);
        }

        // Compute scaled logits in-circuit
        let mut slog: Vec<UInt64<Fr>> = Vec::with_capacity(K);
        let d_fp = fp_from_uint32_le(&t_clamped)?;
        for j in 0..K {
            let q_u64 = slog_native[j] as u64;
            let q = UInt64::new_variable(cs.clone(), || Ok(q_u64), AllocationMode::Witness)?;
            let rem = UInt32::new_variable(cs.clone(), || Ok(rem_native[j]), AllocationMode::Witness)?;

            let logit_bits = logit_q16[j].to_bits_le()?;
            let sign = logit_bits[31].clone();
            let mut ext = Vec::with_capacity(64);
            ext.extend_from_slice(&logit_bits);
            for _ in 32..64 {
                ext.push(sign.clone());
            }
            let mut num_bits = Vec::with_capacity(64);
            for _ in 0..16 {
                num_bits.push(Boolean::FALSE);
            }
            for k in 0..48 {
                num_bits.push(ext[k].clone());
            }
            let num_u64 = UInt64::from_bits_le(&num_bits);

            let num_fp = signed_fp_from_u64(&num_u64)?;
            let q_fp = signed_fp_from_u64(&q)?;
            let rem_fp = fp_from_uint32_le(&rem)?;
            num_fp.enforce_equal(&(q_fp * d_fp.clone() + rem_fp))?;

            let r_ge_d = uint32_is_ge(&rem, &t_clamped)?;
            r_ge_d.enforce_equal(&Boolean::FALSE)?;

            slog.push(q);
        }
        record("scaled_logits");

        let (sorted_token_id, sorted_slog, sorted_logit_q16) = if PROVE_SORTING {
            // Prove sorting inside the circuit: accept arbitrary order then apply a selection-permutation.
            let mut perm: Vec<usize> = (0..K).collect();
            perm.sort_by(|&a, &b| {
                let la = slog_native[a];
                let lb = slog_native[b];
                if la != lb {
                    return lb.cmp(&la);
                }
                token_id_native[a].cmp(&token_id_native[b])
            });

            let log_k = (K as u64).trailing_zeros() as usize;
            let mut idx_bits_le: Vec<Vec<Boolean<Fr>>> = Vec::with_capacity(K);
            for &idx in &perm {
                let mut bits = Vec::with_capacity(log_k);
                for b in 0..log_k {
                    let bit = ((idx >> b) & 1) == 1;
                    bits.push(Boolean::new_variable(cs.clone(), || Ok(bit), AllocationMode::Witness)?);
                }
                idx_bits_le.push(bits);
            }
            record("perm_bits");

            // Enforce permutation uniqueness via sum of powers
            let mut pow2_table: Vec<UInt64<Fr>> = Vec::with_capacity(K);
            for j in 0..K {
                pow2_table.push(UInt64::constant(1u64 << j));
            }
            let mut pow_sum = FpVar::Constant(Fr::from(0u64));
            for j in 0..K {
                let mut bits_be = idx_bits_le[j].clone();
                bits_be.reverse();
                let pow = UInt64::conditionally_select_power_of_two_vector(&bits_be, &pow2_table)?;
                pow_sum += fp_from_uint64_le(&pow)?;
            }
            let full_mask: u64 = if K == 64 { u64::MAX } else { (1u64 << K) - 1 };
            pow_sum.enforce_equal(&FpVar::Constant(Fr::from(full_mask)))?;
            record("perm_unique");

            // Apply permutation to get sorted arrays
            let mut sorted_token_id: Vec<UInt32<Fr>> = Vec::with_capacity(K);
            let mut sorted_slog: Vec<UInt64<Fr>> = Vec::with_capacity(K);
            let mut sorted_logit_q16: Vec<UInt32<Fr>> = Vec::with_capacity(K);
            let token_id_vec: Vec<UInt32<Fr>> = token_id.iter().cloned().collect();
            let logit_vec: Vec<UInt32<Fr>> = logit_q16.iter().cloned().collect();
            for j in 0..K {
                let mut bits_be = idx_bits_le[j].clone();
                bits_be.reverse();
                let sel_token = UInt32::conditionally_select_power_of_two_vector(&bits_be, &token_id_vec)?;
                let sel_slog = UInt64::conditionally_select_power_of_two_vector(&bits_be, &slog)?;
                let sel_logit = UInt32::conditionally_select_power_of_two_vector(&bits_be, &logit_vec)?;
                sorted_token_id.push(sel_token);
                sorted_slog.push(sel_slog);
                sorted_logit_q16.push(sel_logit);
            }
            record("apply_perm");
            (sorted_token_id, sorted_slog, sorted_logit_q16)
        } else {
            // Canonical candidate order variant: candidates are provided already sorted.
            record("assume_sorted_candidates");
            (
                token_id.iter().cloned().collect::<Vec<_>>(),
                slog.clone(),
                logit_q16.iter().cloned().collect::<Vec<_>>(),
            )
        };

        // Enforce sorting order
        let sign_mask64 = UInt64::constant(0x8000_0000_0000_0000u64);
        for j in 0..(K - 1) {
            let a_key = &sorted_slog[j] ^ &sign_mask64;
            let b_key = &sorted_slog[j + 1] ^ &sign_mask64;
            let ge_logits = uint64_is_ge(&a_key, &b_key)?;
            ge_logits.enforce_equal(&Boolean::TRUE)?;

            let eq_logits = sorted_slog[j].is_eq(&sorted_slog[j + 1])?;
            let ge_tokens = uint32_is_ge(&sorted_token_id[j + 1], &sorted_token_id[j])?;
            let not_ge_tokens = !ge_tokens;
            let bad = &eq_logits & &not_ge_tokens;
            bad.enforce_equal(&Boolean::FALSE)?;
        }
        record("sort_order");

        // Compute candidate hash
        let mut cand_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_config);
        for &b in b"VRBDecode.Candidates.v1" {
            cand_sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        for j in 0..K {
            let tok_fp = fp_from_uint32_le(&sorted_token_id[j])?;
            let logit_fp = fp_from_uint32_le(&sorted_logit_q16[j])?;
            cand_sponge.absorb(&tok_fp)?;
            cand_sponge.absorb(&logit_fp)?;
        }
        let cand_hash = cand_sponge.squeeze_field_elements(1)?;
        record("candidate_hash");

        // Compute expected receipt hash and enforce against h_new
        let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.poseidon_config);
        for &b in b"VRBDecode.Receipt.v1" {
            sponge.absorb(&FpVar::Constant(Fr::from(b as u64)))?;
        }
        sponge.absorb(&h_prev)?;
        sponge.absorb(&request_id_lo)?;
        sponge.absorb(&request_id_hi)?;
        sponge.absorb(&policy_hash_field_fp)?;
        sponge.absorb(&seed_commit_field_fp)?;
        sponge.absorb(&step_idx_fp)?;
        sponge.absorb(&cand_hash[0])?;
        let y_fp = fp_from_uint32_le(y)?;
        sponge.absorb(&y_fp)?;
        sponge.absorb(&ws_fp)?;
        sponge.absorb(&r_fp)?;
        let out = sponge.squeeze_field_elements(1)?;
        out[0].enforce_equal(h_new)?;
        record("receipt_update");

        // y must be in top-k sorted set
        let mut y_in_topk = Vec::with_capacity(K);
        for j in 0..K {
            let y_eq_j = sorted_token_id[j].is_eq(y)?;
            let j_lt_topk = uint32_is_ge(&top_k, &UInt32::constant((j as u32) + 1u32))?;
            y_in_topk.push(&y_eq_j & &j_lt_topk);
        }
        Boolean::kary_or(&y_in_topk)?.enforce_equal(&Boolean::TRUE)?;
        record("y_in_topk");

        // Return new state: same static values, updated h_prev -> h_new
        let out_state = vec![
            request_id_lo,
            request_id_hi,
            top_k_fp,
            top_p_q16_fp,
            t_q16_fp,
            max_tokens_fp,
            policy_hash_field_fp,
            seed_commit_field_fp,
            h_new.clone(),
        ];
        record("end");
        Ok(out_state)
    }
}

impl<const K: usize, const PROVE_SORTING: bool> FCircuit<Fr> for StepFCircuit<K, PROVE_SORTING> {
    type Params = PoseidonConfig<Fr>;
    type ExternalInputs = StepExternalInputs<K>;
    type ExternalInputsVar = StepExternalInputsVar<K>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_config: params,
        })
    }

    fn state_len(&self) -> usize {
        9 // request_id_lo, request_id_hi, top_k, top_p_q16, T_q16, max_tokens, policy_hash_field, seed_commit_field, h_prev
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        self.generate_step_constraints_inner(cs, i, z_i, external_inputs, None)
    }
}
