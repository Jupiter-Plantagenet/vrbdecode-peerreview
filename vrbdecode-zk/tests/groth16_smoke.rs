use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16};
use rand::{rngs::StdRng, SeedableRng};
use serde::Deserialize;

use vrbdecode_core::decode_step;
use vrbdecode_zk::{protocol, StepCircuit};

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;

#[derive(Debug, Deserialize, Clone)]
struct Expected {
    y: u32,
    #[serde(rename = "Ws")]
    ws: u64,
    #[serde(rename = "R")]
    r: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct Vector {
    #[serde(rename = "K")]
    k: usize,
    top_k: usize,
    top_p_q16: u32,
    #[serde(rename = "T_q16")]
    t_q16: u32,
    token_id: Vec<u32>,
    logit_q16: Vec<i32>,
    #[serde(rename = "U_t")]
    u_t: u64,
    expected: Expected,
    tag: Option<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn load_policy_sensitive_golden() -> Vector {
    let path = workspace_root().join("vectors").join("golden.jsonl");
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    for line in r.lines().filter_map(|l| l.ok()) {
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str::<Vector>(&line).expect("parse vector json");
        if row.tag.as_deref() == Some("policy_sensitive_v1") {
            return row;
        }
    }
    panic!("policy_sensitive_v1 not found");
}

fn load_another_k16_golden() -> Vector {
    let path = workspace_root().join("vectors").join("golden.jsonl");
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    for line in r.lines().filter_map(|l| l.ok()) {
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str::<Vector>(&line).expect("parse vector json");
        if row.k == 16 && row.tag.as_deref() != Some("policy_sensitive_v1") {
            return row;
        }
    }
    panic!("no other k16 golden vector found");
}

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

fn candidate_hash<const K: usize>(row: &Vector) -> Fr {
    assert_eq!(row.k, K);
    assert_eq!(row.token_id.len(), K);
    assert_eq!(row.logit_q16.len(), K);

    let t_clamped = row.t_q16.max(1);

    let mut slog_native: Vec<i64> = Vec::with_capacity(K);
    for i in 0..K {
        let num = (row.logit_q16[i] as i128) << 16;
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
        row.token_id[i].cmp(&row.token_id[j])
    });

    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.Candidates.v1" {
        elems.push(Fr::from(b as u64));
    }
    for &idx in &perm {
        elems.push(Fr::from(row.token_id[idx] as u64));
        elems.push(Fr::from(row.logit_q16[idx] as u32 as u64));
    }
    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
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

fn public_inputs(row: &Vector) -> Vec<Fr> {
    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let step_idx = 0u32;
    let max_tokens: u32 = 256;

    let top_k: u32 = row.top_k as u32;
    let top_p_q16: u32 = row.top_p_q16;
    let t_q16: u32 = row.t_q16;

    let policy_hash_field =
        protocol::policy_hash_field(16, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h_prev = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);
    let expected = decode_step(
        16,
        row.top_k,
        row.top_p_q16,
        row.t_q16,
        &row.token_id,
        &row.logit_q16,
        u_t,
    );

    let token_id: [u32; 16] = row.token_id.clone().try_into().expect("K=16");
    let logit_q16: [i32; 16] = row.logit_q16.clone().try_into().expect("K=16");
    let cand_hash = protocol::candidate_hash::<16>(&token_id, &logit_q16, t_q16);
    let h_new = protocol::receipt_update(
        h_prev,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        step_idx,
        cand_hash,
        expected.y,
        expected.ws,
        expected.r,
    );
    vec![
        Fr::from(top_k as u64),
        Fr::from(top_p_q16 as u64),
        Fr::from(t_q16 as u64),
        Fr::from(max_tokens as u64),
        Fr::from(u_t),
        Fr::from(expected.ws),
        Fr::from(expected.r),
        Fr::from(expected.y as u64),
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        Fr::from(step_idx as u64),
        h_prev,
        h_new,
    ]
}

fn mk_circuit_k16(row: &Vector) -> StepCircuit<16> {
    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let step_idx = 0u32;
    let max_tokens: u32 = 256;

    let top_k: u32 = row.top_k as u32;
    let top_p_q16: u32 = row.top_p_q16;
    let t_q16: u32 = row.t_q16;

    let policy_hash_field =
        protocol::policy_hash_field(16, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h_prev = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);
    let expected = decode_step(
        16,
        row.top_k,
        row.top_p_q16,
        row.t_q16,
        &row.token_id,
        &row.logit_q16,
        u_t,
    );
    let lo = ((u_t as u128) * (expected.ws as u128)) as u64;

    let token_id: [u32; 16] = row.token_id.clone().try_into().expect("K=16");
    let logit_q16: [i32; 16] = row.logit_q16.clone().try_into().expect("K=16");
    let cand_hash = protocol::candidate_hash::<16>(&token_id, &logit_q16, t_q16);
    let h_new = protocol::receipt_update(
        h_prev,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        step_idx,
        cand_hash,
        expected.y,
        expected.ws,
        expected.r,
    );
    StepCircuit::<16> {
        top_k,
        top_p_q16,
        t_q16,
        max_tokens,
        token_id: row.token_id.clone(),
        logit_q16: row.logit_q16.clone(),
        u_t,
        expected_y: expected.y,
        expected_ws: expected.ws,
        expected_r: expected.r,
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

#[test]
#[ignore]
fn groth16_smoke_prove_verify_policy_sensitive_v1_k16() {
    let row0 = load_policy_sensitive_golden();
    let row1 = load_another_k16_golden();
    assert_eq!(row0.k, 16);
    assert_eq!(row1.k, 16);

    let circuit0 = mk_circuit_k16(&row0);

    let mut rng = StdRng::seed_from_u64(0);

    let pk =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit0.clone(), &mut rng)
            .expect("setup");
    let pvk = prepare_verifying_key(&pk.vk);

    for row in [row0, row1] {
        let step_idx = 0u32;
        let request_id_lo = Fr::from(0u64);
        let request_id_hi = Fr::from(0u64);
        let max_tokens: u32 = 256;
        let top_k: u32 = row.top_k as u32;
        let top_p_q16: u32 = row.top_p_q16;
        let t_q16: u32 = row.t_q16;

        let policy_hash_field =
            protocol::policy_hash_field(16, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
        let seed_lo = Fr::from(1u64);
        let seed_hi = Fr::from(0u64);
        let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
        let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);
        let expected = decode_step(16, row.top_k, row.top_p_q16, row.t_q16, &row.token_id, &row.logit_q16, u_t);

        let circuit = mk_circuit_k16(&row);
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng)
                .expect("prove");

        let public_inputs = public_inputs(&row);
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).expect("verify");
        assert!(ok);

        let mut bad = public_inputs.clone();
        bad[7] = Fr::from(((expected.y as u64) + 1) & 0xFFFF_FFFF);
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &bad).expect("verify");
        assert!(!ok);

        let mut bad = public_inputs.clone();
        bad[5] = Fr::from(expected.ws.wrapping_add(1));
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &bad).expect("verify");
        assert!(!ok);

        let mut bad = public_inputs.clone();
        bad[6] = Fr::from(expected.r.wrapping_add(1));
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &bad).expect("verify");
        assert!(!ok);

        let mut bad = public_inputs.clone();
        bad[4] = Fr::from(u_t.wrapping_add(1));
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &bad).expect("verify");
        assert!(!ok);
    }
}
