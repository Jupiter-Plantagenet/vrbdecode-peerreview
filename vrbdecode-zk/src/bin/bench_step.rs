use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::FpVar;
use std::time::Instant;

use folding_schemes::frontend::FCircuit;
use vrbdecode_zk::{protocol, StepCircuit, StepExternalInputs, StepExternalInputsVar, StepFCircuit};

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;

fn poseidon_params_bn254_rate8() -> PoseidonConfig<Fr> {
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

fn prf_u_t(
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_lo: Fr,
    policy_hash_hi: Fr,
    seed_commit_lo: Fr,
    seed_commit_hi: Fr,
    step_idx: u32,
) -> u64 {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.U_t.v1" {
        elems.push(Fr::from(b as u64));
    }
    elems.push(request_id_lo);
    elems.push(request_id_hi);
    elems.push(policy_hash_lo);
    elems.push(policy_hash_hi);
    elems.push(seed_commit_lo);
    elems.push(seed_commit_hi);
    elems.push(Fr::from(step_idx as u64));

    sponge.absorb(&elems);
    let out = sponge.squeeze_native_field_elements(1)[0];
    let mut bytes = out.into_bigint().to_bytes_le();
    bytes.resize(8, 0u8);
    u64::from_le_bytes(bytes[0..8].try_into().expect("len"))
}

fn candidate_hash<const K: usize>(
    token_id: &[u32],
    logit_q16: &[i32],
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
    for &b in b"VRBDecode.Candidates.v1" {
        elems.push(Fr::from(b as u64));
    }
    for &idx in &perm {
        elems.push(Fr::from(token_id[idx] as u64));
        elems.push(Fr::from(logit_q16[idx] as u32 as u64));
    }
    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

fn receipt_update(
    h_prev: Fr,
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_lo: Fr,
    policy_hash_hi: Fr,
    seed_commit_lo: Fr,
    seed_commit_hi: Fr,
    step_idx: u32,
    cand_hash: Fr,
    y: u32,
    ws: u64,
    r: u64,
) -> Fr {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.Receipt.v1" {
        elems.push(Fr::from(b as u64));
    }
    elems.push(h_prev);
    elems.push(request_id_lo);
    elems.push(request_id_hi);
    elems.push(policy_hash_lo);
    elems.push(policy_hash_hi);
    elems.push(seed_commit_lo);
    elems.push(seed_commit_hi);
    elems.push(Fr::from(step_idx as u64));
    elems.push(cand_hash);
    elems.push(Fr::from(y as u64));
    elems.push(Fr::from(ws));
    elems.push(Fr::from(r));

    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

const Q30: u64 = 1 << 30;
const Z_MIN_Q16: i64 = -(12 << 16);
const E_Q30: [u64; 13] = [
    1073741824, 395007542, 145315154, 53458458, 19666268, 7234816, 2661540, 979126, 360200,
    132510, 48748, 17933, 6597,
];

fn mul_q30_i64(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) >> 30) as i64
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

    if p <= 0 { return 0; }
    if p >= Q30 as i128 { return Q30; }
    p as u64
}

fn decode_step_native(
    k: usize,
    top_k: usize,
    top_p_q16: u32,
    t_q16: u32,
    token_id: &[u32],
    logit_q16: &[i32],
    u_t: u64,
) -> (u32, u64, u64) {
    let t_clamped = t_q16.max(1);

    let mut items: Vec<(u32, i64)> = Vec::with_capacity(k);
    for i in 0..k {
        let num = (logit_q16[i] as i128) << 16;
        let s = floor_div_i128(num, t_clamped as i128) as i64;
        items.push((token_id[i], s));
    }

    items.sort_by(|a, b| {
        if a.1 != b.1 { return b.1.cmp(&a.1); }
        a.0.cmp(&b.0)
    });

    let m = items[0].1;
    let mut w: Vec<u64> = vec![0; k];
    for i in 0..top_k {
        let mut z = items[i].1 - m;
        if z < Z_MIN_Q16 { z = Z_MIN_Q16; }
        let neg_z = -z;
        let mut n = (neg_z >> 16) as i64;
        if n < 0 { n = 0; }
        if n > 12 { n = 12; }
        let r = z + (n << 16);
        let p = exp_poly5_q16_16_to_q30(r);
        let wi = ((E_Q30[n as usize] as u128 * p as u128) >> 30) as u64;
        w[i] = wi;
    }

    let mut wk: u64 = 0;
    for i in 0..top_k { wk = wk.wrapping_add(w[i]); }
    let th = ((top_p_q16 as u128 * wk as u128) >> 16) as u64;

    let mut prefix: u64 = 0;
    let mut s: usize = 1;
    for i in 0..top_k {
        prefix = prefix.wrapping_add(w[i]);
        if prefix >= th { s = i + 1; break; }
    }

    let mut ws: u64 = 0;
    for i in 0..s { ws = ws.wrapping_add(w[i]); }

    let r = (((u_t as u128) * (ws as u128)) >> 64) as u64;

    let mut prefix2: u64 = 0;
    let mut j: usize = 0;
    for i in 0..s {
        prefix2 = prefix2.wrapping_add(w[i]);
        if prefix2 > r { j = i; break; }
    }

    (items[j].0, ws, r)
}

fn mk_circuit<const K: usize>(
    top_k: u32,
    top_p_q16: u32,
    t_q16: u32,
    token_id: Vec<u32>,
    logit_q16: Vec<i32>,
) -> StepCircuit<K> {
    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let step_idx = 0u32;
    let max_tokens: u32 = 1;

    let policy_hash_field =
        protocol::policy_hash_field(K as u32, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h_prev = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);

    let (y, ws, r) = decode_step_native(
        K,
        top_k as usize,
        top_p_q16,
        t_q16,
        &token_id,
        &logit_q16,
        u_t,
    );
    let lo = ((u_t as u128) * (ws as u128)) as u64;

    let mut token_id_arr: [u32; K] = token_id.clone().try_into().expect("token_id length");
    let mut logit_arr: [i32; K] = logit_q16.clone().try_into().expect("logit_q16 length");
    protocol::canonicalize_candidates_in_place(&mut token_id_arr, &mut logit_arr, t_q16);
    let cand_hash = protocol::candidate_hash::<K>(&token_id_arr, &logit_arr, t_q16);
    let h_new = protocol::receipt_update(
        h_prev,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        step_idx,
        cand_hash,
        y,
        ws,
        r,
    );

    StepCircuit::<K> {
        top_k,
        top_p_q16,
        t_q16,
        max_tokens,
        token_id,
        logit_q16,
        u_t,
        expected_y: y,
        expected_ws: ws,
        expected_r: r,
        expected_lo: lo,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        seed_lo,
        seed_hi,
        step_idx,
        h_prev,
        h_new,
    }
}

fn mk_fcircuit_input<const K: usize>(
    top_k: u32,
    top_p_q16: u32,
    t_q16: u32,
    token_id: Vec<u32>,
    logit_q16: Vec<i32>,
    i: usize,
) -> (Vec<Fr>, StepExternalInputs<K>) {
    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let max_tokens: u32 = 1;
    let policy_hash_field =
        protocol::policy_hash_field(K as u32, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h_prev = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, i as u32);

    let (y, ws, r) = decode_step_native(
        K,
        top_k as usize,
        top_p_q16,
        t_q16,
        &token_id,
        &logit_q16,
        u_t,
    );
    let lo = ((u_t as u128) * (ws as u128)) as u64;

    let token_id_arr: [u32; K] = token_id.clone().try_into().expect("token_id length");
    let logit_arr: [i32; K] = logit_q16.clone().try_into().expect("logit_q16 length");
    let cand_hash = protocol::candidate_hash::<K>(&token_id_arr, &logit_arr, t_q16);
    let h_new = protocol::receipt_update(
        h_prev,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        i as u32,
        cand_hash,
        y,
        ws,
        r,
    );

    let token_id: [u32; K] = token_id_arr;
    let logit_q16: [i32; K] = logit_arr;

    let z_i = vec![
        request_id_lo,
        request_id_hi,
        Fr::from(top_k as u64),
        Fr::from(top_p_q16 as u64),
        Fr::from(t_q16 as u64),
        Fr::from(max_tokens as u64),
        policy_hash_field,
        seed_commit_field,
        h_prev,
    ];

    let ext = StepExternalInputs::<K> {
        seed_lo,
        seed_hi,
        token_id,
        logit_q16,
        expected_y: y,
        expected_ws: ws,
        expected_r: r,
        expected_lo: lo,
        h_new,
    };

    (z_i, ext)
}

fn bench_constraints<const K: usize>() -> (usize, f64) {
    let top_k = K as u32;
    let top_p_q16 = 0x10000u32; // 1.0
    let t_q16 = 0x10000u32; // 1.0

    let token_id: Vec<u32> = (0..K).map(|i| i as u32).collect();
    let logit_q16: Vec<i32> = (0..K).map(|i| ((K - i) as i32) << 10).collect();

    let circuit = mk_circuit::<K>(top_k, top_p_q16, t_q16, token_id, logit_q16);

    let start = Instant::now();
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("constraints");
    let elapsed = start.elapsed().as_secs_f64();

    let num_constraints = cs.num_constraints();
    assert!(cs.is_satisfied().expect("is_satisfied"), "Circuit must be satisfied");

    (num_constraints, elapsed)
}

fn bench_fcircuit_constraints<const K: usize, const PROVE_SORTING: bool>() -> (usize, f64) {
    let top_k = K as u32;
    let top_p_q16 = 0x10000u32;
    let t_q16 = 0x10000u32;

    let token_id: Vec<u32> = (0..K).map(|i| i as u32).collect();
    let logit_q16: Vec<i32> = (0..K).map(|i| ((K - i) as i32) << 10).collect();

    let (z_i_native, ext_native) = mk_fcircuit_input::<K>(top_k, top_p_q16, t_q16, token_id, logit_q16, 0);

    let f = StepFCircuit::<K, PROVE_SORTING>::new_default().expect("fcircuit");
    let cs = ConstraintSystem::<Fr>::new_ref();

    let start = Instant::now();
    let z_i: Vec<FpVar<Fr>> = z_i_native
        .iter()
        .map(|v| FpVar::new_variable(cs.clone(), || Ok(*v), AllocationMode::Witness).expect("alloc"))
        .collect();
    let ext: StepExternalInputsVar<K> =
        StepExternalInputsVar::<K>::new_variable(cs.clone(), || Ok(ext_native), AllocationMode::Witness)
            .expect("alloc ext");

    let z_next = f
        .generate_step_constraints(cs.clone(), 0, z_i, ext)
        .expect("generate step constraints");
    let elapsed = start.elapsed().as_secs_f64();

    assert_eq!(z_next.len(), 9);
    assert!(cs.is_satisfied().expect("is_satisfied"), "FCircuit must be satisfied");

    (cs.num_constraints(), elapsed)
}

#[derive(serde::Serialize)]
struct BenchRow {
    k: usize,
    prove_sorting: bool,
    step_circuit_constraints: usize,
    step_circuit_gen_time_s: f64,
    step_fcircuit_constraints: usize,
    step_fcircuit_gen_time_s: f64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_only = args.iter().any(|a| a == "--json");
    let prove_sorting = args.iter().any(|a| a == "--prove-sorting")
        || matches!(
            std::env::var("VRBDECODE_PROVE_SORTING").ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
        );

    let (c16, t16) = bench_constraints::<16>();
    let (c16f, t16f) = if prove_sorting {
        bench_fcircuit_constraints::<16, true>()
    } else {
        bench_fcircuit_constraints::<16, false>()
    };
    let (c32, t32) = bench_constraints::<32>();
    let (c32f, t32f) = if prove_sorting {
        bench_fcircuit_constraints::<32, true>()
    } else {
        bench_fcircuit_constraints::<32, false>()
    };
    let (c64, t64) = bench_constraints::<64>();
    let (c64f, t64f) = if prove_sorting {
        bench_fcircuit_constraints::<64, true>()
    } else {
        bench_fcircuit_constraints::<64, false>()
    };

    let rows = vec![
        BenchRow {
            k: 16,
            prove_sorting,
            step_circuit_constraints: c16,
            step_circuit_gen_time_s: t16,
            step_fcircuit_constraints: c16f,
            step_fcircuit_gen_time_s: t16f,
        },
        BenchRow {
            k: 32,
            prove_sorting,
            step_circuit_constraints: c32,
            step_circuit_gen_time_s: t32,
            step_fcircuit_constraints: c32f,
            step_fcircuit_gen_time_s: t32f,
        },
        BenchRow {
            k: 64,
            prove_sorting,
            step_circuit_constraints: c64,
            step_circuit_gen_time_s: t64,
            step_fcircuit_constraints: c64f,
            step_fcircuit_gen_time_s: t64f,
        },
    ];

    if json_only {
        println!("{}", serde_json::to_string(&rows).expect("json"));
        return;
    }

    println!("Candidate order mode: {}", if prove_sorting { "prove_sorting" } else { "assume_canonical_sorted" });
    println!("=== VRBDecode Step Constraints Benchmarks ===\n");
    println!(
        "{:<6} {:>14} {:>12} {:>14} {:>12}",
        "K", "StepCircuit", "Time(s)", "StepFCircuit", "Time(s)"
    );
    println!("{}", "-".repeat(62));

    for r in &rows {
        println!(
            "{:<6} {:>14} {:>12.4} {:>14} {:>12.4}",
            r.k,
            r.step_circuit_constraints,
            r.step_circuit_gen_time_s,
            r.step_fcircuit_constraints,
            r.step_fcircuit_gen_time_s
        );
    }

    println!("\n=== Summary for Table 1 ===");
    println!("StepFCircuit constraints: K=16: {}, K=32: {}, K=64: {}", c16f, c32f, c64f);
}
