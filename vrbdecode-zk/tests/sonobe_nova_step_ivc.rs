use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as Projective2;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::FoldingScheme;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;

use vrbdecode_core::decode_step;
use vrbdecode_zk::{protocol, StepExternalInputs, StepFCircuit};

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
    assert_eq!(token_id.len(), K);
    assert_eq!(logit_q16.len(), K);

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
    _u_t: u64,
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

fn golden_vectors_k16() -> Vec<Vector> {
    let path = workspace_root().join("vectors").join("golden.jsonl");
    load_jsonl(&path)
        .into_iter()
        .filter(|v| v.k == 16)
        .collect()
}

/// Build StepExternalInputs for a given step from golden vector data
fn mk_external_inputs(
    row: &Vector,
    seed_lo: Fr,
    seed_hi: Fr,
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_field: Fr,
    seed_commit_field: Fr,
    top_k: u32,
    top_p_q16: u32,
    t_q16: u32,
    step_idx: u32,
    h_prev: Fr,
) -> StepExternalInputs<16> {
    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);

    let expected = decode_step(
        16,
        top_k as usize,
        top_p_q16,
        t_q16,
        &row.token_id,
        &row.logit_q16,
        u_t,
    );

    let lo = ((u_t as u128) * (expected.ws as u128)) as u64;

    let mut token_id: [u32; 16] = row.token_id.clone().try_into().expect("K=16");
    let mut logit_q16: [i32; 16] = row.logit_q16.clone().try_into().expect("K=16");
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

    StepExternalInputs {
        seed_lo,
        seed_hi,
        token_id,
        logit_q16,
        expected_y: expected.y,
        expected_ws: expected.ws,
        expected_r: expected.r,
        expected_lo: lo,
        h_new,
    }
}

#[test]
#[ignore]
fn sonobe_nova_step_fcircuit_ivc_golden_k16() -> Result<(), folding_schemes::Error> {
    type N = Nova<
        Projective,
        Projective2,
        StepFCircuit<16>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        false,
    >;

    let vectors = golden_vectors_k16();
    assert!(!vectors.is_empty(), "Need at least one K=16 golden vector");

    // Use first 3 vectors (or fewer if not available) for folding steps
    let num_steps = vectors.len().min(3);

    // Static commitments (same across all steps)
    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let top_k: u32 = 16;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;
    let max_tokens: u32 = num_steps as u32;

    let policy_hash_field =
        protocol::policy_hash_field(16, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h0 = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    // Initial state: z_0 = [request_id_lo, request_id_hi, top_k, top_p_q16, T_q16, max_tokens, policy_hash_field, seed_commit_field, h_prev=h0]
    let initial_state = vec![
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

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let f_circuit = StepFCircuit::<16>::new_default()?;

    // Build external inputs for each step
    let mut ext_inputs: Vec<StepExternalInputs<16>> = Vec::with_capacity(num_steps);
    let mut h_prev = h0;
    for (step_idx, row) in vectors.iter().take(num_steps).enumerate() {
        let ext = mk_external_inputs(
            row,
            seed_lo,
            seed_hi,
            request_id_lo,
            request_id_hi,
            policy_hash_field,
            seed_commit_field,
            top_k,
            top_p_q16,
            t_q16,
            step_idx as u32,
            h_prev,
        );
        h_prev = ext.h_new;
        ext_inputs.push(ext);
    }

    let mut rng = StdRng::seed_from_u64(123456789u64);

    let pp = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let params = N::preprocess(&mut rng, &pp)?;

    let mut folding = N::init(&params, f_circuit, initial_state.clone())?;

    // Prove each step and track expected final state
    let mut expected_h = Fr::from(0u64);
    for (step_idx, ext) in ext_inputs.iter().enumerate() {
        folding.prove_step(&mut rng, ext.clone(), None)?;
        expected_h = ext.h_new;
        println!("Step {} folded successfully, h_new = {:?}", step_idx, expected_h);
    }

    // Verify final folded state matches expected
    let state = folding.state();
    assert_eq!(state.len(), 9);
    assert_eq!(state[0], request_id_lo, "request_id_lo mismatch");
    assert_eq!(state[1], request_id_hi, "request_id_hi mismatch");
    assert_eq!(state[2], Fr::from(top_k as u64), "top_k mismatch");
    assert_eq!(state[3], Fr::from(top_p_q16 as u64), "top_p_q16 mismatch");
    assert_eq!(state[4], Fr::from(t_q16 as u64), "t_q16 mismatch");
    assert_eq!(state[5], Fr::from(max_tokens as u64), "max_tokens mismatch");
    assert_eq!(state[6], policy_hash_field, "policy_hash_field mismatch");
    assert_eq!(state[7], seed_commit_field, "seed_commit_field mismatch");
    assert_eq!(state[8], expected_h, "final receipt hash mismatch");

    // Verify IVC proof
    let proof = folding.ivc_proof();
    N::verify(params.1, proof)?;
    println!("IVC proof verified successfully after {} steps", num_steps);

    Ok(())
}

#[test]
#[ignore]
fn sonobe_nova_step_fcircuit_rejects_tampered_external_inputs_k16() -> Result<(), folding_schemes::Error> {
    type N = Nova<
        Projective,
        Projective2,
        StepFCircuit<16>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        false,
    >;

    let vectors = golden_vectors_k16();
    assert!(vectors.len() >= 2, "Need at least two K=16 golden vectors");

    let num_steps = 2usize;

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let top_k: u32 = 16;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;
    let max_tokens: u32 = num_steps as u32;

    let policy_hash_field =
        protocol::policy_hash_field(16, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h0 = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let initial_state = vec![
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

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let f_circuit = StepFCircuit::<16>::new_default()?;
    let mut rng = StdRng::seed_from_u64(987654321u64);

    let pp = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let params = N::preprocess(&mut rng, &pp)?;

    let mut folding = N::init(&params, f_circuit, initial_state.clone())?;

    // Step 0 succeeds
    let ext0 = mk_external_inputs(
        &vectors[0],
        seed_lo,
        seed_hi,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        top_k,
        top_p_q16,
        t_q16,
        0u32,
        h0,
    );
    folding.prove_step(&mut rng, ext0, None)?;

    // Step 1 with tampered expected output must fail.
    let mut ext1 = mk_external_inputs(
        &vectors[1],
        seed_lo,
        seed_hi,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        top_k,
        top_p_q16,
        t_q16,
        1u32,
        folding.state()[8],
    );
    ext1.expected_y = ext1.expected_y.wrapping_add(1);
    folding.prove_step(&mut rng, ext1, None)?;

    // Proof must fail verification if a step was inconsistent with constraints.
    let proof = folding.ivc_proof();
    assert!(N::verify(params.1, proof).is_err());

    Ok(())
}
