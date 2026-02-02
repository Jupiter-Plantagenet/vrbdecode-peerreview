use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{decider_eth::Decider as DeciderEth, Nova, PreprocessorParam};
use folding_schemes::folding::traits::CommittedInstanceOps;
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, Error, FoldingScheme};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;
use solidity_verifiers::calldata::{prepare_calldata_for_nova_cyclefold_verifier, NovaVerificationMode};
use solidity_verifiers::evm::{compile_solidity, Evm};
use solidity_verifiers::verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider;
use solidity_verifiers::NovaCycleFoldVerifierKey;

use vrbdecode_zk::{protocol, StepExternalInputs, StepFCircuit};
use vrbdecode_core::decode_step;

type N = Nova<G1, G2, StepFCircuit<64>, KZG<'static, Bn254>, Pedersen<G2>, false>;
type D = DeciderEth<G1, G2, StepFCircuit<64>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N>;

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
}

fn workspace_root() -> PathBuf {
    std::env::current_dir()
        .expect("current dir")
        .to_path_buf()
}

fn load_jsonl(path: &PathBuf) -> Vec<Vector> {
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    r.lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Vector>(&l).expect("parse"))
        .collect()
}

fn vectors_k64() -> Vec<Vector> {
    let root = workspace_root().join("vectors");
    let mut rows: Vec<Vector> = Vec::new();
    rows.extend(load_jsonl(&root.join("golden.jsonl")));
    rows.extend(load_jsonl(&root.join("random.jsonl")));
    rows.into_iter().filter(|v| v.k == 64).collect()
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

fn candidate_hash<const K: usize>(token_id: &[u32], logit_q16: &[i32], t_q16: u32) -> Fr {
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

fn mk_external_inputs<const K: usize>(
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
) -> StepExternalInputs<K> {
    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);

    let expected = decode_step(K, top_k as usize, top_p_q16, t_q16, &row.token_id, &row.logit_q16, u_t);
    let lo = ((u_t as u128) * (expected.ws as u128)) as u64;

    let mut token_id: [u32; K] = row.token_id.clone().try_into().expect("token_id length");
    let mut logit_q16: [i32; K] = row.logit_q16.clone().try_into().expect("logit_q16 length");
    protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16, t_q16);

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

fn solc_available() -> bool {
    std::process::Command::new("solc")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn main() -> Result<(), Error> {
    let json_only = std::env::args().any(|a| a == "--json");
    let progress = std::env::args().any(|a| a == "--progress")
        || std::env::var("VRBDECODE_BENCH_PROGRESS").ok().as_deref() == Some("1");

    let mut step_counts: Vec<usize> = vec![32, 64, 128];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--steps" {
            if let Some(v) = args.next() {
                let parsed: Vec<usize> = v
                    .split(',')
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim().parse::<usize>().expect("parse steps"))
                    .collect();
                if !parsed.is_empty() {
                    step_counts = parsed;
                }
            }
        }
    }

    let vectors = vectors_k64();
    let max_n = *step_counts.iter().max().unwrap_or(&0);
    assert!(
        vectors.len() >= max_n,
        "Need at least {} K=64 vectors (golden+random), found {}",
        max_n,
        vectors.len()
    );

    let f_circuit = StepFCircuit::<64>::new_default()?;

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::seed_from_u64(123456789u64);

    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

    let (decider_pp, decider_vp) =
        D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;
    let mut decider_pp_opt = Some(decider_pp);

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);

    let top_k: u32 = 64;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;
    let max_tokens: u32 = max_n as u32;

    let policy_hash_field =
        protocol::policy_hash_field(64, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
    let seed_lo = Fr::from(1u64);
    let seed_hi = Fr::from(0u64);
    let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
    let h0 = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);

    let mut outputs: Vec<serde_json::Value> = Vec::new();

    for &n_steps in &step_counts {
        if !json_only {
            println!("=== DeciderEth (Groth16/Bn254) for K=64, N={} ===", n_steps);
        }

        let z_0 = vec![
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

        let mut nova = N::init(&nova_params, f_circuit.clone(), z_0.clone())?;

        let fold_start = Instant::now();
        let mut h_prev = h0;
        for (step_idx, row) in vectors.iter().take(n_steps).enumerate() {
            let ext = mk_external_inputs::<64>(
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
            let start = Instant::now();
            nova.prove_step(&mut rng, ext, None)?;
            if progress {
                eprintln!("prove_step {}: {:.3}s", step_idx, start.elapsed().as_secs_f64());
            }
        }
        let total_fold_time_s = fold_start.elapsed().as_secs_f64();
        let avg_step_time_s = total_fold_time_s / (n_steps as f64);

        // Avoid cloning the full Nova state (can double peak memory in CI).
        // Extract the values we need for verify/calldata, then move `nova` into `D::prove`.
        let i = nova.i;
        let z_0 = nova.z_0.clone();
        let z_i = nova.z_i.clone();
        let U_i = nova.U_i.clone();
        let u_i = nova.u_i.clone();
        let U_i_comm = U_i.get_commitments();
        let u_i_comm = u_i.get_commitments();

        if progress {
            eprintln!("decider_prove start (K=64, N={})", n_steps);
        }
        let start = Instant::now();
        // Cloning the Groth16 proving params can cause a large peak in memory.
        // In CI we run a single N (e.g. --steps 32), so we can move `decider_pp` instead.
        let decider_pp_for_prove = if step_counts.len() == 1 {
            decider_pp_opt.take().expect("decider_pp")
        } else {
            decider_pp_opt.as_ref().expect("decider_pp").clone()
        };
        let proof = D::prove(&mut rng, decider_pp_for_prove, nova)?;
        let decider_prove_time_s = start.elapsed().as_secs_f64();
        if progress {
            eprintln!("decider_prove done (K=64, N={})", n_steps);
        }

        let verified = D::verify(
            decider_vp.clone(),
            i,
            z_0.clone(),
            z_i.clone(),
            &U_i_comm,
            &u_i_comm,
            &proof,
        )?;
        assert!(verified);

        let calldata: Vec<u8> = prepare_calldata_for_nova_cyclefold_verifier(
            NovaVerificationMode::Explicit,
            i,
            z_0,
            z_i,
            &U_i,
            &u_i,
            &proof,
        )?;

        let vk = NovaCycleFoldVerifierKey::from((decider_vp.clone(), f_circuit.state_len()));
        let solidity_code = get_decider_template_for_cyclefold_decider(vk);

        let out_dir = workspace_root().join("eval").join("evm");
        std::fs::create_dir_all(&out_dir).expect("mkdir");
        std::fs::write(out_dir.join(format!("nova_decider_k64_n{}.sol", n_steps)), solidity_code.as_bytes())
            .expect("write sol");
        std::fs::write(out_dir.join(format!("nova_decider_k64_n{}.calldata", n_steps)), calldata.as_slice())
            .expect("write calldata");

        let mut evm_gas_used: Option<u64> = None;
        let mut evm_ok: Option<bool> = None;
        if solc_available() {
            let bytecode = compile_solidity(solidity_code.as_bytes(), "NovaDecider");
            let mut evm = Evm::default();
            let verifier_address = evm.create(bytecode);
            let (gas_used, output) = evm.call(verifier_address, calldata.clone());
            evm_gas_used = Some(gas_used);
            evm_ok = output.last().copied().map(|b| b == 1);
            if !json_only {
                println!("EVM verify ok: {:?}, gas_used: {}", evm_ok, gas_used);
            }
        } else if !json_only {
            println!("solc not found; skipping in-EVM verification. Install solc to measure gas (or run verification with your own tooling). Solidity and calldata written to eval/evm/");
        }

        outputs.push(serde_json::json!({
            "k": 64,
            "n_steps": n_steps,
            "avg_step_time_s": avg_step_time_s,
            "total_fold_time_s": total_fold_time_s,
            "decider_prove_time_s": decider_prove_time_s,
            "proof_calldata_bytes": calldata.len(),
            "evm_verify_ok": evm_ok,
            "evm_gas_used": evm_gas_used
        }));
    }

    if json_only {
        println!("{}", serde_json::to_string(&outputs).expect("json"));
    }

    Ok(())
}
