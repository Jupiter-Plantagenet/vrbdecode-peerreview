use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_serialize::CanonicalSerialize;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;

use folding_schemes::frontend::FCircuit;

use solidity_verifiers::verifiers::g16::Groth16VerifierKey;
use solidity_verifiers::ProtocolVerifierKey;

use vrbdecode_core::decode_step;
use vrbdecode_zk::{protocol, StepExternalInputs, StepExternalInputsVar, StepFCircuit};

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;
const FUNCTION_SELECTOR_GROTH16_VERIFY_PROOF_18: [u8; 4] = [0x44, 0x83, 0xe7, 0x21];

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

#[derive(Clone)]
struct BatchFCircuitGroth16<const K: usize, const B: usize> {
    z0: [Fr; 9],
    zB: [Fr; 9],
    steps: [StepExternalInputs<K>; B],
}

impl<const K: usize, const B: usize> ConstraintSynthesizer<Fr> for BatchFCircuitGroth16<K, B> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let fcircuit = StepFCircuit::<K>::new_default().map_err(|_| SynthesisError::Unsatisfiable)?;

        let mut z: Vec<FpVar<Fr>> = self
            .z0
            .iter()
            .map(|v| FpVar::new_variable(cs.clone(), || Ok(*v), AllocationMode::Input))
            .collect::<Result<Vec<_>, _>>()?;

        for i in 0..B {
            let ext: StepExternalInputsVar<K> = StepExternalInputsVar::<K>::new_variable(
                cs.clone(),
                || Ok(self.steps[i].clone()),
                AllocationMode::Witness,
            )?;
            z = fcircuit.generate_step_constraints(cs.clone(), i, z, ext)?;
        }

        let zB_vars: Vec<FpVar<Fr>> = self
            .zB
            .iter()
            .map(|v| FpVar::new_variable(cs.clone(), || Ok(*v), AllocationMode::Input))
            .collect::<Result<Vec<_>, _>>()?;

        if z.len() != zB_vars.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..z.len() {
            z[i].enforce_equal(&zB_vars[i])?;
        }

        Ok(())
    }
}

fn run_for<const K: usize, const B: usize>(out_dir: &Path) {
    let n_steps = B;
    let vectors = load_vectors_for_k(K);
    assert!(vectors.len() >= n_steps, "need {} vectors for K={}", n_steps, K);

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);

    let top_k: u32 = K as u32;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;
    let max_tokens: u32 = n_steps as u32;

    let policy_hash_field =
        protocol::policy_hash_field(K as u32, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h0 = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let z0: [Fr; 9] = [
        request_id_lo,
        request_id_hi,
        Fr::from(top_k as u64),
        Fr::from(top_p_q16 as u64),
        Fr::from(t_q16 as u64),
        Fr::from(max_tokens as u64),
        policy_hash_field,
        seed_commit_field,
        h0,
    ];

    let mut steps: Vec<StepExternalInputs<K>> = Vec::with_capacity(B);
    let mut h_prev = h0;
    for (step_idx, row) in vectors.iter().take(B).enumerate() {
        let mut token_id: [u32; K] = row.token_id.clone().try_into().expect("token_id length");
        let mut logit_q16: [i32; K] = row.logit_q16.clone().try_into().expect("logit_q16 length");
        protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16, t_q16);

        let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx as u32);
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
        let cand_hash = protocol::candidate_hash::<K>(&token_id, &logit_q16, t_q16);
        let h_new = protocol::receipt_update(
            h_prev,
            request_id_lo,
            request_id_hi,
            policy_hash_field,
            seed_commit_field,
            step_idx as u32,
            cand_hash,
            expected.y,
            expected.ws,
            expected.r,
        );

        steps.push(StepExternalInputs::<K> {
            seed_lo,
            seed_hi,
            token_id,
            logit_q16,
            expected_y: expected.y,
            expected_ws: expected.ws,
            expected_r: expected.r,
            expected_lo: lo,
            h_new,
        });
        h_prev = h_new;
    }

    let zB: [Fr; 9] = [
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

    let steps_arr: [StepExternalInputs<K>; B] = steps.try_into().expect("steps len");
    let circuit = BatchFCircuitGroth16::<K, B> { z0, zB, steps: steps_arr };

    let mut rng = StdRng::seed_from_u64(0);

    let setup_start = Instant::now();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
        .expect("setup");
    let setup_s = setup_start.elapsed().as_secs_f64();
    let pvk = prepare_verifying_key(&pk.vk);

    let prove_start = Instant::now();
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng).expect("prove");
    let prove_s = prove_start.elapsed().as_secs_f64();

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).expect("serialize");

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&z0);
    public_inputs.extend_from_slice(&zB);

    let verify_start = Instant::now();
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).expect("verify");
    let verify_s = verify_start.elapsed().as_secs_f64();
    assert!(ok);

    // Write Groth16 verifier + calldata for on-chain baseline measurements.
    // Public inputs are fixed-length (18) because the Step state length is fixed (z0=9, zB=9).
    let verifier_sol = Groth16VerifierKey::from(pk.vk.clone()).render_as_template(None);
    fs::write(
        out_dir.join(format!("baseline_groth16_batch_fcircuit_k{}_b{}_verifier.sol", K, B)),
        verifier_sol,
    )
    .expect("write verifier.sol");

    fn pad32(mut v: Vec<u8>) -> Vec<u8> {
        if v.len() > 32 {
            v = v[v.len() - 32..].to_vec();
        }
        if v.len() < 32 {
            let mut out = vec![0u8; 32 - v.len()];
            out.extend_from_slice(&v);
            out
        } else {
            v
        }
    }

    let (a_x, a_y) = proof.a.xy().expect("A xy");
    let (b_x, b_y) = proof.b.xy().expect("B xy");
    let (c_x, c_y) = proof.c.xy().expect("C xy");

    let mut calldata: Vec<u8> = Vec::new();
    calldata.extend_from_slice(&FUNCTION_SELECTOR_GROTH16_VERIFY_PROOF_18);
    calldata.extend_from_slice(&pad32(a_x.into_bigint().to_bytes_be()));
    calldata.extend_from_slice(&pad32(a_y.into_bigint().to_bytes_be()));
    // Match the Solidity template's order: b_x.c1, b_x.c0, b_y.c1, b_y.c0
    calldata.extend_from_slice(&pad32(b_x.c1.into_bigint().to_bytes_be()));
    calldata.extend_from_slice(&pad32(b_x.c0.into_bigint().to_bytes_be()));
    calldata.extend_from_slice(&pad32(b_y.c1.into_bigint().to_bytes_be()));
    calldata.extend_from_slice(&pad32(b_y.c0.into_bigint().to_bytes_be()));
    calldata.extend_from_slice(&pad32(c_x.into_bigint().to_bytes_be()));
    calldata.extend_from_slice(&pad32(c_y.into_bigint().to_bytes_be()));
    assert_eq!(public_inputs.len(), 18, "expected fixed 18 public inputs for baseline");
    for fr in &public_inputs {
        calldata.extend_from_slice(&pad32(fr.into_bigint().to_bytes_be()));
    }
    fs::write(
        out_dir.join(format!("baseline_groth16_batch_fcircuit_k{}_b{}_calldata.bin", K, B)),
        &calldata,
    )
    .expect("write calldata.bin");

    let out = serde_json::json!({
        "k": K,
        "batch_steps": B,
        "setup_time_s": setup_s,
        "prove_time_s": prove_s,
        "verify_time_s": verify_s,
        "proof_size_bytes": proof_bytes.len(),
        "public_inputs_len": public_inputs.len(),
    });

    fs::create_dir_all(out_dir).expect("mkdir out");
    let out_path = out_dir.join(format!("baseline_groth16_batch_fcircuit_k{}_b{}.json", K, B));
    fs::write(out_path, serde_json::to_string_pretty(&out).expect("json")).expect("write");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let k = args
        .iter()
        .position(|a| a == "--k")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(16);
    let b = args
        .iter()
        .position(|a| a == "--b")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);

    let run_id = args
        .iter()
        .position(|a| a == "--run-id")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "baseline_tmp".to_string());

    let out_dir = workspace_root().join("eval").join("artifacts").join(run_id).join("baselines");

    match (k, b) {
        (16, 1) => run_for::<16, 1>(&out_dir),
        (16, 8) => run_for::<16, 8>(&out_dir),
        (16, 16) => run_for::<16, 16>(&out_dir),
        (32, 1) => run_for::<32, 1>(&out_dir),
        (32, 8) => run_for::<32, 8>(&out_dir),
        (32, 16) => run_for::<32, 16>(&out_dir),
        (64, 1) => run_for::<64, 1>(&out_dir),
        (64, 8) => run_for::<64, 8>(&out_dir),
        (64, 16) => run_for::<64, 16>(&out_dir),
        _ => panic!("unsupported (use --k 16/32/64 and --b 1/8/16)"),
    }

    println!("{}", out_dir.parent().unwrap().display());
}
