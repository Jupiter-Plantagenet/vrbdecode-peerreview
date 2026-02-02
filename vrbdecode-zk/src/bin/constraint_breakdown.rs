use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use ark_bn254::Fr;
use ark_relations::gr1cs::ConstraintSystem;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::FpVar;
use serde::Deserialize;

use vrbdecode_core::decode_step;
use vrbdecode_zk::{protocol, ConstraintBreakdownPoint, StepExternalInputs, StepExternalInputsVar, StepFCircuit};

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;

#[derive(Debug, Deserialize, Clone)]
struct VectorRow {
    #[serde(rename = "K")]
    k: usize,
    token_id: Vec<u32>,
    logit_q16: Vec<i32>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read_jsonl_rows(path: &Path) -> Vec<VectorRow> {
    let f = fs::File::open(path).expect("open jsonl");
    let r = BufReader::new(f);
    r.lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<VectorRow>(&l).expect("parse jsonl row"))
        .collect()
}

fn load_vectors_for_k(k: usize) -> Vec<VectorRow> {
    let root = workspace_root().join("vectors");
    let mut out = Vec::new();
    out.extend(read_jsonl_rows(&root.join("golden.jsonl")));
    out.extend(read_jsonl_rows(&root.join("random.jsonl")));
    out.into_iter().filter(|r| r.k == k).collect()
}

#[derive(Debug, serde::Serialize)]
struct BreakdownRow {
    label: String,
    constraints_total: usize,
    constraints_delta: usize,
}

#[derive(Debug, serde::Serialize)]
struct OneCase {
    k: usize,
    step_idx: usize,
    instance_vars: usize,
    witness_vars: usize,
    constraints: usize,
    breakdown: Vec<BreakdownRow>,
}

fn build_case<const K: usize>(step_idx: usize, max_tokens: u32) -> (Vec<Fr>, StepExternalInputs<K>) {
    let vectors = load_vectors_for_k(K);
    assert!(vectors.len() > step_idx, "need >= {} vectors for K={}", step_idx + 1, K);

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let top_k: u32 = K as u32;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;

    let policy_hash_field =
        protocol::policy_hash_field(K as u32, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h0 = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let mut h_prev = h0;
    let mut ext_for_step: Option<StepExternalInputs<K>> = None;
    for s in 0..=step_idx {
        let row = &vectors[s];
        let mut token_id: [u32; K] = row.token_id.clone().try_into().expect("token_id length");
        let mut logit_q16_arr: [i32; K] = row.logit_q16.clone().try_into().expect("logit_q16 length");
        protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16_arr, t_q16);

        let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, s as u32);
        let expected = decode_step(
            K,
            top_k as usize,
            top_p_q16,
            t_q16,
            &row.token_id,
            &row.logit_q16,
            u_t,
        );
        let lo = ((u_t as u128) * (expected.ws as u128)) as u64;
        let cand_hash = protocol::candidate_hash::<K>(&token_id, &logit_q16_arr, t_q16);
        let h_new = protocol::receipt_update(
            h_prev,
            request_id_lo,
            request_id_hi,
            policy_hash_field,
            seed_commit_field,
            s as u32,
            cand_hash,
            expected.y,
            expected.ws,
            expected.r,
        );

        if s == step_idx {
            ext_for_step = Some(StepExternalInputs::<K> {
                seed_lo,
                seed_hi,
                token_id,
                logit_q16: logit_q16_arr,
                expected_y: expected.y,
                expected_ws: expected.ws,
                expected_r: expected.r,
                expected_lo: lo,
                h_new,
            });
        }
        h_prev = h_new;
    }

    let z_i: Vec<Fr> = vec![
        request_id_lo,
        request_id_hi,
        Fr::from(top_k as u64),
        Fr::from(top_p_q16 as u64),
        Fr::from(t_q16 as u64),
        Fr::from(max_tokens as u64),
        policy_hash_field,
        seed_commit_field,
        // state before applying step_idx update:
        if step_idx == 0 {
            h0
        } else {
            // We advanced h_prev through step_idx in the loop. Recompute h_{step_idx-1} cheaply.
            let mut h = h0;
            for s in 0..step_idx {
                let row = &vectors[s];
                let mut token_id: [u32; K] = row.token_id.clone().try_into().expect("token_id length");
                let mut logit_q16_arr: [i32; K] = row.logit_q16.clone().try_into().expect("logit_q16 length");
                protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16_arr, t_q16);
                let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, s as u32);
                let expected = decode_step(
                    K,
                    top_k as usize,
                    top_p_q16,
                    t_q16,
                    &row.token_id,
                    &row.logit_q16,
                    u_t,
                );
                let cand_hash = protocol::candidate_hash::<K>(&token_id, &logit_q16_arr, t_q16);
                h = protocol::receipt_update(
                    h,
                    request_id_lo,
                    request_id_hi,
                    policy_hash_field,
                    seed_commit_field,
                    s as u32,
                    cand_hash,
                    expected.y,
                    expected.ws,
                    expected.r,
                );
            }
            h
        },
    ];

    (z_i, ext_for_step.expect("ext step"))
}

fn measure_one<const K: usize>(step_idx: usize, max_tokens: u32) -> OneCase {
    let (z_i, ext) = build_case::<K>(step_idx, max_tokens);

    let cs = ConstraintSystem::<Fr>::new_ref();
    let z_vars: Vec<FpVar<Fr>> = z_i
        .iter()
        .map(|v| FpVar::new_variable(cs.clone(), || Ok(*v), AllocationMode::Input))
        .collect::<Result<Vec<_>, _>>()
        .expect("alloc z_i");

    let ext_var: StepExternalInputsVar<K> =
        StepExternalInputsVar::<K>::new_variable(cs.clone(), || Ok(ext), AllocationMode::Witness).expect("alloc ext");

    let fcircuit = StepFCircuit::<K>::new_default().expect("fcircuit");
    let mut points: Vec<ConstraintBreakdownPoint> = Vec::new();
    let _ = fcircuit
        .generate_step_constraints_with_breakdown(cs.clone(), step_idx, z_vars, ext_var, &mut points)
        .expect("synthesize");

    assert!(cs.is_satisfied().expect("is_satisfied"), "constructed witness must satisfy");

    let mut breakdown_rows: Vec<BreakdownRow> = Vec::new();
    let mut prev = 0usize;
    for p in points {
        let total = p.constraints_total;
        let delta = total.saturating_sub(prev);
        breakdown_rows.push(BreakdownRow {
            label: p.label.to_string(),
            constraints_total: total,
            constraints_delta: delta,
        });
        prev = total;
    }

    OneCase {
        k: K,
        step_idx,
        instance_vars: cs.num_instance_variables(),
        witness_vars: cs.num_witness_variables(),
        constraints: cs.num_constraints(),
        breakdown: breakdown_rows,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let run_id = args
        .iter()
        .position(|a| a == "--run-id")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "constraint_breakdown_tmp".to_string());
    let max_tokens = args
        .iter()
        .position(|a| a == "--max-tokens")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(2u32);
    let steps: Vec<usize> = args
        .iter()
        .position(|a| a == "--steps")
        .and_then(|i| args.get(i + 1))
        .map(|v| {
            v.split(',')
                .filter_map(|x| x.trim().parse::<usize>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![0, 1]);

    let out_dir = workspace_root().join("eval").join("artifacts").join(run_id).join("constraints");
    fs::create_dir_all(&out_dir).expect("mkdir out");

    let mut cases: Vec<OneCase> = Vec::new();
    for &step_idx in &steps {
        cases.push(measure_one::<16>(step_idx, max_tokens));
        cases.push(measure_one::<32>(step_idx, max_tokens));
        cases.push(measure_one::<64>(step_idx, max_tokens));
    }

    let doc = serde_json::json!({
        "max_tokens": max_tokens,
        "steps": steps,
        "cases": cases,
    });
    let out_path = out_dir.join("constraint_breakdown.json");
    fs::write(&out_path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    println!("{}", out_path.display());
}
