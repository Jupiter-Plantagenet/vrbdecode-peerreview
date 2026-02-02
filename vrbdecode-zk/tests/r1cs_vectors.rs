use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
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

fn load_jsonl(path: &PathBuf) -> Vec<Vector> {
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    r.lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Vector>(&line).expect("parse vector json"))
        .collect()
}

fn golden_vectors() -> Vec<Vector> {
    let path = workspace_root().join("vectors").join("golden.jsonl");
    load_jsonl(&path)
}

fn random_vectors() -> Vec<Vector> {
    let path = workspace_root().join("vectors").join("random.jsonl");
    load_jsonl(&path)
}

fn mk_circuit<const K: usize>(row: &Vector) -> StepCircuit<K> {
    assert_eq!(row.k, K);

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let step_idx = 0u32;
    let max_tokens: u32 = 256;

    let top_k: u32 = row.top_k as u32;
    let top_p_q16: u32 = row.top_p_q16;
    let t_q16: u32 = row.t_q16;

    let policy_hash_field =
        protocol::policy_hash_field(K as u32, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h_prev = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);
    let expected = decode_step(
        K,
        row.top_k,
        row.top_p_q16,
        row.t_q16,
        &row.token_id,
        &row.logit_q16,
        u_t,
    );
    let lo = ((u_t as u128) * (expected.ws as u128)) as u64;

    let token_id: [u32; K] = row.token_id.clone().try_into().expect("token_id length");
    let logit_q16: [i32; K] = row.logit_q16.clone().try_into().expect("logit_q16 length");
    let cand_hash = protocol::candidate_hash::<K>(&token_id, &logit_q16, t_q16);
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
    StepCircuit::<K> {
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

fn assert_satisfied<const K: usize>(row: &Vector) {
    let cs = ConstraintSystem::new_ref();
    let c = mk_circuit::<K>(row);
    c.generate_constraints(cs.clone()).expect("constraints");
    assert!(cs.is_satisfied().expect("is_satisfied"));
}

fn assert_unsatisfied<const K: usize>(row: &Vector) {
    let cs = ConstraintSystem::new_ref();
    let c = mk_circuit::<K>(row);
    c.generate_constraints(cs.clone()).expect("constraints");
    assert!(!cs.is_satisfied().expect("is_satisfied"));
}

fn assert_unsatisfied_circuit<const K: usize>(c: StepCircuit<K>) {
    let cs = ConstraintSystem::new_ref();
    c.generate_constraints(cs.clone()).expect("constraints");
    assert!(!cs.is_satisfied().expect("is_satisfied"));
}

#[test]
fn native_equivalence_random_vectors_1000_vs_python_ref() {
    let rows = random_vectors();
    assert!(
        rows.len() >= 1000,
        "Need at least 1000 random vectors, found {}",
        rows.len()
    );

    for (i, row) in rows.iter().take(1000).enumerate() {
        let got = decode_step(
            row.k,
            row.top_k,
            row.top_p_q16,
            row.t_q16,
            &row.token_id,
            &row.logit_q16,
            row.u_t,
        );

        assert_eq!(got.y, row.expected.y, "y mismatch at i={}", i);
        assert_eq!(got.ws, row.expected.ws, "ws mismatch at i={}", i);
        assert_eq!(got.r, row.expected.r, "r mismatch at i={}", i);

        if (i + 1) % 100 == 0 {
            println!("Verified native-vs-python for {}/1000 random vectors", i + 1);
        }
    }
}

#[test]
fn r1cs_golden_samples_satisfy_k16() {
    let rows = golden_vectors();
    assert!(!rows.is_empty());

    let row16 = rows.iter().find(|r| r.k == 16).expect("k16 exists");

    assert_satisfied::<16>(row16);
}

#[test]
#[ignore]
fn r1cs_golden_samples_satisfy_k32() {
    let rows = golden_vectors();
    assert!(!rows.is_empty());

    let row32 = rows.iter().find(|r| r.k == 32).expect("k32 exists");
    assert_satisfied::<32>(row32);
}

#[test]
#[ignore]
fn r1cs_golden_samples_satisfy_k64() {
    let rows = golden_vectors();
    assert!(!rows.is_empty());

    let row64 = rows.iter().find(|r| r.k == 64).expect("k64 exists");
    assert_satisfied::<64>(row64);
}

#[test]
#[ignore]
fn r1cs_constraint_count_k64_guard() {
    let rows = golden_vectors();
    assert!(!rows.is_empty());

    let row64 = rows.iter().find(|r| r.k == 64).expect("k64 exists");

    let cs = ConstraintSystem::new_ref();
    let c = mk_circuit::<64>(row64);
    c.generate_constraints(cs.clone()).expect("constraints");
    assert!(cs.is_satisfied().expect("is_satisfied"));

    let n = cs.num_constraints();
    println!("K=64 constraint count: {}", n);
    assert!(n < 5_000_000);
}

#[test]
fn r1cs_tamper_logit_unsatisfied_policy_sensitive_v1_k16() {
    let row = golden_vectors()
        .into_iter()
        .find(|r| r.tag.as_deref() == Some("policy_sensitive_v1"))
        .expect("policy_sensitive_v1 exists");
    assert_eq!(row.k, 16);

    let mut c = mk_circuit::<16>(&row);
    c.logit_q16[0] = c.logit_q16[0].wrapping_add(1);
    assert_unsatisfied_circuit::<16>(c);
}

#[test]
fn r1cs_tamper_receipt_hnew_unsatisfied_policy_sensitive_v1_k16() {
    let row = golden_vectors()
        .into_iter()
        .find(|r| r.tag.as_deref() == Some("policy_sensitive_v1"))
        .expect("policy_sensitive_v1 exists");
    assert_eq!(row.k, 16);

    let mut c = mk_circuit::<16>(&row);
    c.h_new += Fr::from(1u64);
    assert_unsatisfied_circuit::<16>(c);
}

#[test]
fn r1cs_tamper_receipt_step_idx_unsatisfied_policy_sensitive_v1_k16() {
    let row = golden_vectors()
        .into_iter()
        .find(|r| r.tag.as_deref() == Some("policy_sensitive_v1"))
        .expect("policy_sensitive_v1 exists");
    assert_eq!(row.k, 16);

    let mut c = mk_circuit::<16>(&row);
    c.step_idx = 1u32;
    assert_unsatisfied_circuit::<16>(c);
}

#[test]
fn r1cs_tamper_receipt_policy_hash_unsatisfied_policy_sensitive_v1_k16() {
    let row = golden_vectors()
        .into_iter()
        .find(|r| r.tag.as_deref() == Some("policy_sensitive_v1"))
        .expect("policy_sensitive_v1 exists");
    assert_eq!(row.k, 16);

    let mut c = mk_circuit::<16>(&row);
    c.policy_hash_field += Fr::from(1u64);
    assert_unsatisfied_circuit::<16>(c);
}

#[test]
fn r1cs_tamper_receipt_seed_commit_unsatisfied_policy_sensitive_v1_k16() {
    let row = golden_vectors()
        .into_iter()
        .find(|r| r.tag.as_deref() == Some("policy_sensitive_v1"))
        .expect("policy_sensitive_v1 exists");
    assert_eq!(row.k, 16);

    let mut c = mk_circuit::<16>(&row);
    c.seed_commit_field += Fr::from(1u64);
    assert_unsatisfied_circuit::<16>(c);
}

#[test]
fn r1cs_tamper_candidate_set_unsatisfied_policy_sensitive_v1_k16() {
    let row = golden_vectors()
        .into_iter()
        .find(|r| r.tag.as_deref() == Some("policy_sensitive_v1"))
        .expect("policy_sensitive_v1 exists");
    assert_eq!(row.k, 16);

    let mut c = mk_circuit::<16>(&row);
    c.token_id[15] = c.token_id[15].wrapping_add(1);
    assert_unsatisfied_circuit::<16>(c);
}

#[test]
fn r1cs_random_vectors_satisfy_sampled_all_k() {
    let rows = random_vectors();
    assert!(rows.len() >= 1000, "Need at least 1000 random vectors, found {}", rows.len());

    let samples_per_k: usize = std::env::var("VRBDECODE_R1CS_RANDOM_SAMPLES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    let mut passed_k16 = 0;
    let mut passed_k32 = 0;
    let mut passed_k64 = 0;

    let mut checked = 0usize;
    for (i, row) in rows.iter().enumerate() {
        match row.k {
            16 => {
                if passed_k16 >= samples_per_k {
                    continue;
                }
                let cs = ConstraintSystem::new_ref();
                let c = mk_circuit::<16>(row);
                c.generate_constraints(cs.clone()).expect("constraints");
                assert!(cs.is_satisfied().expect("is_satisfied"), "Random vector {} (K=16) failed", i);
                passed_k16 += 1;
            }
            32 => {
                if passed_k32 >= samples_per_k {
                    continue;
                }
                let cs = ConstraintSystem::new_ref();
                let c = mk_circuit::<32>(row);
                c.generate_constraints(cs.clone()).expect("constraints");
                assert!(cs.is_satisfied().expect("is_satisfied"), "Random vector {} (K=32) failed", i);
                passed_k32 += 1;
            }
            64 => {
                if passed_k64 >= samples_per_k {
                    continue;
                }
                let cs = ConstraintSystem::new_ref();
                let c = mk_circuit::<64>(row);
                c.generate_constraints(cs.clone()).expect("constraints");
                assert!(cs.is_satisfied().expect("is_satisfied"), "Random vector {} (K=64) failed", i);
                passed_k64 += 1;
            }
            _ => panic!("Unsupported K={}", row.k),
        }

        checked += 1;

        let target = samples_per_k.saturating_mul(3);
        println!("Verified {}/{} sampled random vectors", checked, target);

        if passed_k16 >= samples_per_k && passed_k32 >= samples_per_k && passed_k64 >= samples_per_k {
            break;
        }
    }

    assert_eq!(passed_k16, samples_per_k, "Did not test enough K=16 vectors");
    assert_eq!(passed_k32, samples_per_k, "Did not test enough K=32 vectors");
    assert_eq!(passed_k64, samples_per_k, "Did not test enough K=64 vectors");

    println!(
        "All {} sampled random vectors satisfied R1CS (K16={}, K32={}, K64={})",
        checked, passed_k16, passed_k32, passed_k64
    );
}
