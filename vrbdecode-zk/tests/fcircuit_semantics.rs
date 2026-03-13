use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use ark_bn254::Fr;
use ark_relations::gr1cs::ConstraintSystem;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::FpVar;
use folding_schemes::frontend::FCircuit;
use serde::Deserialize;

use vrbdecode_core::decode_step;
use vrbdecode_zk::{protocol, StepExternalInputs, StepExternalInputsVar, StepFCircuit};

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;

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
    tag: Option<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn load_policy_sensitive_golden_k16() -> Vector {
    let path = workspace_root().join("vectors").join("golden.jsonl");
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    for line in r.lines().filter_map(|l| l.ok()) {
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str::<Vector>(&line).expect("parse vector json");
        if row.k == 16 && row.tag.as_deref() == Some("policy_sensitive_v1") {
            return row;
        }
    }
    panic!("policy_sensitive_v1 k=16 vector not found");
}

fn build_fcircuit_case() -> (Vec<Fr>, StepExternalInputs<16>, u32) {
    let row = load_policy_sensitive_golden_k16();

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let step_idx = 0u32;
    let max_tokens = 256u32;
    let top_k = row.top_k as u32;
    let top_p_q16 = row.top_p_q16;
    let t_q16 = row.t_q16;

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

    let mut token_id: [u32; 16] = row.token_id.clone().try_into().expect("token_id length");
    let mut logit_q16: [i32; 16] = row.logit_q16.clone().try_into().expect("logit_q16 length");
    protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16, t_q16);

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

    let ext = StepExternalInputs::<16> {
        seed_lo,
        seed_hi,
        token_id,
        logit_q16,
        expected_y: expected.y,
        expected_ws: expected.ws,
        expected_r: expected.r,
        expected_lo: lo,
        h_new,
    };

    (z_i, ext, t_q16)
}

fn assert_fcircuit_satisfied(z_i_native: Vec<Fr>, ext_native: StepExternalInputs<16>) {
    let fcircuit = StepFCircuit::<16>::new_default().expect("fcircuit");
    let cs = ConstraintSystem::<Fr>::new_ref();

    let z_i: Vec<FpVar<Fr>> = z_i_native
        .iter()
        .map(|v| FpVar::new_variable(cs.clone(), || Ok(*v), AllocationMode::Witness).expect("alloc"))
        .collect();
    let ext: StepExternalInputsVar<16> =
        StepExternalInputsVar::<16>::new_variable(cs.clone(), || Ok(ext_native), AllocationMode::Witness)
            .expect("alloc ext");

    fcircuit
        .generate_step_constraints(cs.clone(), 0, z_i, ext)
        .expect("generate constraints");
    assert!(cs.is_satisfied().expect("is_satisfied"));
}

fn assert_fcircuit_unsatisfied(z_i_native: Vec<Fr>, ext_native: StepExternalInputs<16>) {
    let fcircuit = StepFCircuit::<16>::new_default().expect("fcircuit");
    let cs = ConstraintSystem::<Fr>::new_ref();

    let z_i: Vec<FpVar<Fr>> = z_i_native
        .iter()
        .map(|v| FpVar::new_variable(cs.clone(), || Ok(*v), AllocationMode::Witness).expect("alloc"))
        .collect();
    let ext: StepExternalInputsVar<16> =
        StepExternalInputsVar::<16>::new_variable(cs.clone(), || Ok(ext_native), AllocationMode::Witness)
            .expect("alloc ext");

    fcircuit
        .generate_step_constraints(cs.clone(), 0, z_i, ext)
        .expect("generate constraints");
    assert!(!cs.is_satisfied().expect("is_satisfied"));
}

#[test]
fn fcircuit_policy_sensitive_v1_k16_satisfies() {
    let (z_i, ext, _) = build_fcircuit_case();
    assert_fcircuit_satisfied(z_i, ext);
}

#[test]
fn fcircuit_rejects_receipt_consistent_wrong_y_k16() {
    let (z_i, mut ext, t_q16) = build_fcircuit_case();

    let alt_y = ext.token_id[..4]
        .iter()
        .copied()
        .find(|&token_id| token_id != ext.expected_y)
        .expect("alternate top-k token");

    let cand_hash = protocol::candidate_hash::<16>(&ext.token_id, &ext.logit_q16, t_q16);
    ext.expected_y = alt_y;
    ext.h_new = protocol::receipt_update(
        z_i[8],
        z_i[0],
        z_i[1],
        z_i[6],
        z_i[7],
        0u32,
        cand_hash,
        ext.expected_y,
        ext.expected_ws,
        ext.expected_r,
    );

    assert_fcircuit_unsatisfied(z_i, ext);
}

#[test]
fn fcircuit_rejects_receipt_consistent_wrong_ws_k16() {
    let (z_i, mut ext, t_q16) = build_fcircuit_case();

    let u_t = protocol::prf_u_t(z_i[0], z_i[1], z_i[6], z_i[7], 0u32);
    let tampered_ws = ext.expected_ws.wrapping_add(1);
    let prod = (u_t as u128) * (tampered_ws as u128);
    let tampered_r = (prod >> 64) as u64;
    let tampered_lo = prod as u64;
    let cand_hash = protocol::candidate_hash::<16>(&ext.token_id, &ext.logit_q16, t_q16);

    ext.expected_ws = tampered_ws;
    ext.expected_r = tampered_r;
    ext.expected_lo = tampered_lo;
    ext.h_new = protocol::receipt_update(
        z_i[8],
        z_i[0],
        z_i[1],
        z_i[6],
        z_i[7],
        0u32,
        cand_hash,
        ext.expected_y,
        ext.expected_ws,
        ext.expected_r,
    );

    assert_fcircuit_unsatisfied(z_i, ext);
}
