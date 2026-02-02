use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{decider_eth::Decider as DeciderEth, Nova, PreprocessorParam};
use folding_schemes::folding::traits::CommittedInstanceOps;
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, FoldingScheme};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;
use solidity_verifiers::calldata::{prepare_calldata_for_nova_cyclefold_verifier, NovaVerificationMode};
use solidity_verifiers::verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider;
use solidity_verifiers::NovaCycleFoldVerifierKey;

use vrbdecode_core::decode_step;
use vrbdecode_zk::{protocol, StepExternalInputs, StepFCircuit};

type NovaK = Nova<G1, G2, StepFCircuit<16>, KZG<'static, Bn254>, Pedersen<G2>, false>;
type DeciderK = DeciderEth<G1, G2, StepFCircuit<16>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, NovaK>;

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

fn read_jsonl(path: &PathBuf) -> Vec<VectorRow> {
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    r.lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<VectorRow>(&l).expect("parse"))
        .collect()
}

fn golden_k16() -> Vec<VectorRow> {
    let root = workspace_root().join("vectors");
    read_jsonl(&root.join("golden.jsonl"))
        .into_iter()
        .filter(|r| r.k == 16)
        .collect()
}

fn mk_ext(
    row: &VectorRow,
    step_idx: u32,
    h_prev: Fr,
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_field: Fr,
    seed_commit_field: Fr,
    seed_lo: Fr,
    seed_hi: Fr,
    top_k: u32,
    top_p_q16: u32,
    t_q16: u32,
) -> StepExternalInputs<16> {
    let mut token_id: [u32; 16] = row.token_id.clone().try_into().expect("token_id length");
    let mut logit_q16: [i32; 16] = row.logit_q16.clone().try_into().expect("logit_q16 length");
    protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16, t_q16);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);
    let expected = decode_step(16, top_k as usize, top_p_q16, t_q16, &row.token_id, &row.logit_q16, u_t);
    let lo = ((u_t as u128) * (expected.ws as u128)) as u64;

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
fn decider_eth_wrap_k16_n2_acceptance() -> Result<(), folding_schemes::Error> {
    if std::env::var("VRBDECODE_RUN_WRAP_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping (set VRBDECODE_RUN_WRAP_TESTS=1 to enable)");
        return Ok(());
    }
    if cfg!(debug_assertions) {
        eprintln!("skipping in debug mode (run `cargo test -p vrbdecode-zk --release -- --ignored decider_eth_wrap_k16_n2_acceptance`)");
        return Ok(());
    }

    let vectors = golden_k16();
    assert!(vectors.len() >= 2, "need at least two K=16 golden vectors");

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let n_steps = 2u32;
    let top_k: u32 = 16;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;
    let max_tokens: u32 = n_steps;

    let policy_hash_field =
        protocol::policy_hash_field(16, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h0 = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let z0 = vec![
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

    let mut rng = StdRng::seed_from_u64(123456789u64);
    let f_circuit = StepFCircuit::<16>::new_default()?;
    let transcript_cfg = poseidon_canonical_config::<Fr>();
    let pp = PreprocessorParam::new(transcript_cfg, f_circuit.clone());
    let nova_params = NovaK::preprocess(&mut rng, &pp)?;

    let mut folding = NovaK::init(&nova_params, f_circuit.clone(), z0.clone())?;

    let mut h_prev = h0;
    for (i, row) in vectors.iter().take(2).enumerate() {
        let ext = mk_ext(
            row,
            i as u32,
            h_prev,
            request_id_lo,
            request_id_hi,
            policy_hash_field,
            seed_commit_field,
            seed_lo,
            seed_hi,
            top_k,
            top_p_q16,
            t_q16,
        );
        h_prev = ext.h_new;
        folding.prove_step(&mut rng, ext, None)?;
    }

    let (decider_pp, decider_vp) = DeciderK::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;
    let i = folding.i;
    let z_i = folding.z_i.clone();
    let u_i = folding.u_i.clone();
    let u_i_comm = u_i.get_commitments();
    let u_big_i = folding.U_i.clone();
    let u_big_i_comm = u_big_i.get_commitments();

    let proof = DeciderK::prove(&mut rng, decider_pp, folding)?;
    let verified = DeciderK::verify(
        decider_vp.clone(),
        i,
        z0.clone(),
        z_i.clone(),
        &u_big_i_comm,
        &u_i_comm,
        &proof,
    )?;
    assert!(verified);

    let calldata: Vec<u8> = prepare_calldata_for_nova_cyclefold_verifier(
        NovaVerificationMode::Explicit,
        i,
        z0,
        z_i,
        &u_big_i,
        &u_i,
        &proof,
    )?;
    assert!(!calldata.is_empty());

    let vk = NovaCycleFoldVerifierKey::from((decider_vp, f_circuit.state_len()));
    let solidity_code = get_decider_template_for_cyclefold_decider(vk);
    assert!(solidity_code.contains("contract NovaDecider"));

    Ok(())
}
