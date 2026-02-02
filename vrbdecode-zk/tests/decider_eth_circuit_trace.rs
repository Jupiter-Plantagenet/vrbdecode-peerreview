use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_relations::gr1cs::{trace::TracingMode, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_std::Zero;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{
    decider_eth_circuit::DeciderEthCircuit,
    Nova, PreprocessorParam,
};
use folding_schemes::folding::traits::CommittedInstanceOps;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::FoldingScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tracing_subscriber::{layer::SubscriberExt, Registry};

use ark_grumpkin::Projective as G2;
use std::io::BufRead;

use vrbdecode_zk::{protocol, StepExternalInputs, StepFCircuit};

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;

type NovaK<const K: usize> = Nova<G1, G2, StepFCircuit<K>, KZG<'static, Bn254>, Pedersen<G2>, false>;

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn load_k16_rows(n: usize) -> Vec<serde_json::Value> {
    let path = workspace_root().join("vectors").join("golden.jsonl");
    let f = std::fs::File::open(path).expect("open golden.jsonl");
    let r = std::io::BufReader::new(f);
    r.lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(&l).expect("json"))
        .filter(|v| v.get("K").and_then(|x| x.as_u64()) == Some(16))
        .take(n)
        .collect()
}

fn row_token_logits<const K: usize>(row: &serde_json::Value) -> ([u32; K], [i32; K]) {
    let token_id = row
        .get("token_id")
        .expect("token_id")
        .as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_u64().expect("u64") as u32)
        .collect::<Vec<_>>();
    let logit_q16 = row
        .get("logit_q16")
        .expect("logit_q16")
        .as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_i64().expect("i64") as i32)
        .collect::<Vec<_>>();
    (
        token_id.try_into().expect("K"),
        logit_q16.try_into().expect("K"),
    )
}

fn mk_ext_inputs<const K: usize>(
    token_id: [u32; K],
    logit_q16: [i32; K],
    seed_lo: Fr,
    seed_hi: Fr,
    step_idx: u32,
    request_id_lo: Fr,
    request_id_hi: Fr,
    policy_hash_field: Fr,
    seed_commit_field: Fr,
    top_k: u32,
    top_p_q16: u32,
    t_q16: u32,
    h_prev: Fr,
) -> StepExternalInputs<K> {
    let mut token_id = token_id;
    let mut logit_q16 = logit_q16;
    protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16, t_q16);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);
    let expected = vrbdecode_core::decode_step(
        K,
        top_k as usize,
        top_p_q16,
        t_q16,
        &token_id,
        &logit_q16,
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
        step_idx,
        cand_hash,
        expected.y,
        expected.ws,
        expected.r,
    );
    StepExternalInputs::<K> {
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
fn decider_eth_circuit_trace_k16_n2() -> Result<(), folding_schemes::Error> {
    // Enable constraint tracing so `which_is_unsatisfied()` provides a meaningful trace.
    let constraint_layer = ark_relations::gr1cs::trace::ConstraintLayer::new(TracingMode::OnlyConstraints);
    let subscriber = Registry::default().with(constraint_layer);
    let _ = tracing::subscriber::set_global_default(subscriber);

    let rows = load_k16_rows(2);
    assert_eq!(rows.len(), 2);

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let top_k: u32 = 16;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;
    let max_tokens: u32 = 2;

    let policy_hash_field =
        protocol::policy_hash_field(16, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
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
    let mut rng = StdRng::seed_from_u64(123456789u64);

    let pp = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let params = NovaK::<16>::preprocess(&mut rng, &pp)?;
    let mut folding = NovaK::<16>::init(&params, f_circuit, initial_state)?;

    let (token_id0, logit_q160) = row_token_logits::<16>(&rows[0]);
    let ext0 = mk_ext_inputs::<16>(
        token_id0,
        logit_q160,
        seed_lo,
        seed_hi,
        0,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        top_k,
        top_p_q16,
        t_q16,
        h0,
    );
    folding.prove_step(&mut rng, ext0, None)?;

    let h1 = folding.state().last().cloned().unwrap_or_else(|| Fr::zero());
    let (token_id1, logit_q161) = row_token_logits::<16>(&rows[1]);
    let ext1 = mk_ext_inputs::<16>(
        token_id1,
        logit_q161,
        seed_lo,
        seed_hi,
        1,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        top_k,
        top_p_q16,
        t_q16,
        h1,
    );
    folding.prove_step(&mut rng, ext1, None)?;

    // Quick sanity: incoming instance should be non-relaxed.
    let u_i_comm = folding.u_i.get_commitments();
    assert!(u_i_comm.get(1).is_some_and(|cm_e| cm_e.is_zero()));

    let circuit = DeciderEthCircuit::<G1, G2>::try_from(folding)?;
    let cs: ConstraintSystemRef<Fr> = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone())?;

    if !cs.is_satisfied()? {
        let trace = cs.which_is_unsatisfied()?.unwrap_or_else(|| "<no trace>".to_string());
        panic!("DeciderEthCircuit unsatisfied.\n{trace}");
    }
    Ok(())
}
