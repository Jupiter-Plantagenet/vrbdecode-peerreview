use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_serialize::{CanonicalSerialize, Compress, Validate};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::Zero;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen, CommitmentScheme};
use folding_schemes::folding::nova::{
    decider_eth::{Decider as DeciderEth, DeciderEthCircuit},
    IVCProof, Nova, PreprocessorParam,
};
use folding_schemes::folding::traits::CommittedInstanceOps;
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, Error, FoldingScheme};
use hex::ToHex;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solidity_verifiers::calldata::{prepare_calldata_for_nova_cyclefold_verifier, NovaVerificationMode};
use solidity_verifiers::verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider;
use solidity_verifiers::NovaCycleFoldVerifierKey;

use vrbdecode_core::decode_step;
use vrbdecode_zk::{cache, poseidon_params_bn254_rate8, protocol, StepExternalInputs, StepFCircuit};

type NovaK<const K: usize, const PROVE_SORTING: bool> =
    Nova<G1, G2, StepFCircuit<K, PROVE_SORTING>, KZG<'static, Bn254>, Pedersen<G2>, false>;
type DeciderK<const K: usize, const PROVE_SORTING: bool> = DeciderEth<
    G1,
    G2,
    StepFCircuit<K, PROVE_SORTING>,
    KZG<'static, Bn254>,
    Pedersen<G2>,
    Groth16<Bn254>,
    NovaK<K, PROVE_SORTING>,
>;
type DeciderVerifierParam<const K: usize, const PROVE_SORTING: bool> =
    <DeciderK<K, PROVE_SORTING> as Decider<G1, G2, StepFCircuit<K, PROVE_SORTING>, NovaK<K, PROVE_SORTING>>>::VerifierParam;
type Groth16Pk = ark_groth16::ProvingKey<Bn254>;

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;
const PROTOCOL_VERSION: &str = "1";
const DECIDER_CIRCUIT_VERSION: &str = "pedersen_safe_v1";

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

fn sha256_files(paths: &[PathBuf]) -> String {
    let mut h = Sha256::new();
    for p in paths {
        let b = fs::read(p).unwrap_or_default();
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(&b);
    }
    let digest = h.finalize();
    digest.encode_hex::<String>()
}

fn fr_hex(fr: &Fr) -> String {
    let mut out = Vec::new();
    fr.serialize_compressed(&mut out).expect("serialize");
    out.encode_hex::<String>()
}

fn cmd_output(cwd: &Path, program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).current_dir(cwd).output().ok();
    let out = match out {
        Some(out) => Some(out),
        None => {
            let home = std::env::var("HOME").ok().unwrap_or_default();
            if home.is_empty() {
                None
            } else {
                let candidate = PathBuf::from(home).join(".foundry").join("bin").join(program);
                Command::new(candidate).args(args).current_dir(cwd).output().ok()
            }
        }
    }?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn mk_run_id() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("run_{}_{}", now.as_secs(), std::process::id())
}

fn parse_arg_u32(args: &[String], name: &str) -> Option<u32> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u32>().ok())
}

fn parse_arg_usize(args: &[String], name: &str) -> Option<usize> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn run_for_k<const K: usize, const PROVE_SORTING: bool>(
    n_steps: usize,
    top_k: u32,
    top_p_q16: u32,
    t_q16: u32,
    max_tokens: u32,
    out_dir: &Path,
    skip_wrap: bool,
    only_fold: bool,
    only_wrap: bool,
    decider_sanity_only: bool,
    force: bool,
    cache_dir: &Path,
    no_cache: bool,
) -> Result<(), Error> {
    let f_circuit = StepFCircuit::<K, PROVE_SORTING>::new_default()?;
    let state_len = f_circuit.state_len();
    let transcript_cfg = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::seed_from_u64(123456789u64);
    eprintln!(
        "[pipeline] start k={} n_steps={} state_len={} prove_sorting={} skip_wrap={} only_fold={} only_wrap={}",
        K,
        n_steps,
        state_len,
        PROVE_SORTING,
        skip_wrap,
        only_fold,
        only_wrap
    );

    if !out_dir.exists() {
        fs::create_dir_all(out_dir)?;
    }
    fs::create_dir_all(out_dir.join("nova"))?;
    fs::create_dir_all(out_dir.join("wrapped"))?;
    fs::create_dir_all(out_dir.join("chain"))?;
    fs::create_dir_all(out_dir.join("baselines"))?;
    if !only_wrap {
        fs::write(out_dir.join("protocol_version.txt"), PROTOCOL_VERSION)?;
    }

    let cache_prefix = format!("k{}_state{}_v{}_prove_sorting{}", K, state_len, PROTOCOL_VERSION, PROVE_SORTING as u8);
    let nova_pp_cache = cache_dir.join(format!("nova_{}_pp.bin", cache_prefix));
    let nova_vp_cache = cache_dir.join(format!("nova_{}_vp.bin", cache_prefix));

    eprintln!("[pipeline] nova preprocess...");
    let preprocess_start = Instant::now();
    let fc_params = poseidon_params_bn254_rate8();
    let nova_params = if !no_cache && nova_pp_cache.exists() && nova_vp_cache.exists() {
        let nova_pp = {
            let f = fs::File::open(&nova_pp_cache)?;
            NovaK::<K, PROVE_SORTING>::pp_deserialize_with_mode(f, Compress::Yes, Validate::Yes, fc_params.clone())?
        };
        let nova_vp = {
            let f = fs::File::open(&nova_vp_cache)?;
            NovaK::<K, PROVE_SORTING>::vp_deserialize_with_mode(f, Compress::Yes, Validate::Yes, fc_params.clone())?
        };
        (nova_pp, nova_vp)
    } else {
        let pp = PreprocessorParam::new(transcript_cfg, f_circuit.clone());
        let params = NovaK::<K, PROVE_SORTING>::preprocess(&mut rng, &pp)?;
        if !no_cache {
            cache::write_compressed(&nova_pp_cache, &params.0)?;
            cache::write_compressed(&nova_vp_cache, &params.1)?;
        }
        params
    };
    let nova_preprocess_s = preprocess_start.elapsed().as_secs_f64();
    eprintln!("[pipeline] nova preprocess done: {:.2}s", nova_preprocess_s);

    let (folding, z_0_for_wrap, receipt_h0, h_prev, fold_s) = if only_wrap {
        eprintln!("[pipeline] only-wrap: loading ivc_proof.bin and reconstructing Nova...");
        let proof_path = out_dir.join("nova").join("ivc_proof.bin");
        let ivc_proof: IVCProof<G1, G2> = cache::read_compressed(&proof_path)?;
        let z_0_for_wrap = ivc_proof.z_0.clone();
        let receipt_h0 = z_0_for_wrap.last().cloned();
        let h_prev = ivc_proof.z_i.last().cloned().unwrap_or_else(|| Fr::from(0u64));
        let folding = NovaK::<K, PROVE_SORTING>::from_ivc_proof(ivc_proof, fc_params.clone(), nova_params.clone())?;
        (folding, z_0_for_wrap, receipt_h0, h_prev, 0.0f64)
    } else {
        eprintln!("[pipeline] folding {} steps...", n_steps);
        let vectors = load_vectors_for_k(K);
        assert!(vectors.len() >= n_steps, "need at least {} vectors for K={}", n_steps, K);

        let request_id_lo = Fr::from(0u64);
        let request_id_hi = Fr::from(0u64);

        let policy_hash_field =
            protocol::policy_hash_field(K as u32, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);
        let seed_lo = Fr::from(1u64);
        let seed_hi = Fr::from(0u64);
        let seed_commit_field = protocol::seed_commit_field(seed_lo, seed_hi);
        let h0 = protocol::receipt_init(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field);
        let receipt_h0 = Some(h0);

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
        let z_0_for_wrap = z_0.clone();

        if !skip_wrap && !only_fold && n_steps < 2 {
            return Err(Error::NotEnoughSteps);
        }

        let vectors_paths = vec![
            workspace_root().join("vectors").join("golden.jsonl"),
            workspace_root().join("vectors").join("random.jsonl"),
        ];
        let vectors_hash = sha256_files(&vectors_paths);
        fs::write(out_dir.join("vectors_hash.txt"), &vectors_hash).expect("write vectors_hash");

	        let meta = json!({
	            "run_id": out_dir.file_name().and_then(|s| s.to_str()).unwrap_or(""),
	            "generated_at_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
	            "git_commit": cmd_output(&workspace_root(), "git", &["rev-parse", "HEAD"]),
	            "rustc": cmd_output(&workspace_root(), "rustc", &["-V"]),
	            "cargo": cmd_output(&workspace_root(), "cargo", &["-V"]),
            "foundry": {
                "anvil": cmd_output(&workspace_root(), "anvil", &["--version"]),
                "forge": cmd_output(&workspace_root(), "forge", &["--version"]),
                "cast": cmd_output(&workspace_root(), "cast", &["--version"]),
	            },
	            "prove_sorting": PROVE_SORTING,
	            "candidate_order_mode": if PROVE_SORTING { "sort_proven_in_circuit" } else { "canonical_sorted_input" },
	            "k": K,
	            "n_steps": n_steps,
	            "policy": {
                "top_k": top_k,
                "top_p_q16": top_p_q16,
                "t_q16": t_q16,
                "max_tokens": max_tokens,
                "hash_fn_id": HASH_FN_ID,
                "exp_approx_id": EXP_APPROX_ID
            },
            "commitments": {
                "policy_hash_field": fr_hex(&policy_hash_field),
                "seed_commit_field": fr_hex(&seed_commit_field),
            },
            "request_id": {
                "request_id_lo": fr_hex(&request_id_lo),
                "request_id_hi": fr_hex(&request_id_hi),
            }
        });
        fs::write(out_dir.join("meta.json"), serde_json::to_string_pretty(&meta).expect("json")).expect("write meta");

        let public_inputs = json!({
            "request_id_lo": fr_hex(&request_id_lo),
            "request_id_hi": fr_hex(&request_id_hi),
            "top_k": top_k,
            "top_p_q16": top_p_q16,
            "t_q16": t_q16,
            "max_tokens": max_tokens,
            "policy_hash_field": fr_hex(&policy_hash_field),
            "seed_commit_field": fr_hex(&seed_commit_field),
        });
        fs::write(
            out_dir.join("public_inputs.json"),
            serde_json::to_string_pretty(&public_inputs).expect("json"),
        )
        .expect("write public_inputs");

        let mut folding = NovaK::<K, PROVE_SORTING>::init(&nova_params, f_circuit.clone(), z_0.clone())?;

        let mut h_prev = h0;
        let fold_start = Instant::now();
        for (step_idx, row) in vectors.iter().take(n_steps).enumerate() {
            let mut token_id: [u32; K] = row.token_id.clone().try_into().expect("token_id length");
            let mut logit_q16: [i32; K] = row.logit_q16.clone().try_into().expect("logit_q16 length");
            if !PROVE_SORTING {
                protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16, t_q16);
            }

            let u_t =
                protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx as u32);
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

            let ext = StepExternalInputs::<K> {
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

            h_prev = h_new;
            folding.prove_step(&mut rng, ext, None)?;
        }
        let fold_s = fold_start.elapsed().as_secs_f64();
        eprintln!("[pipeline] folding done: {:.2}s", fold_s);

        let ivc_proof = folding.ivc_proof();
        cache::write_compressed(&out_dir.join("nova").join("ivc_proof.bin"), &ivc_proof)?;

        fs::write(
            out_dir.join("receipt.json"),
            serde_json::to_string_pretty(&json!({"h0": fr_hex(&h0), "hN": fr_hex(&h_prev)})).expect("json"),
        )
        .expect("write receipt");

        (folding, z_0_for_wrap, receipt_h0, h_prev, fold_s)
    };

    let mut wrapped_metrics = json!({
        "nova_preprocess_time_s": nova_preprocess_s,
        "nova_fold_time_s": fold_s,
    });

    if skip_wrap || only_fold {
        eprintln!("[pipeline] skip wrap (skip_wrap={} only_fold={})", skip_wrap, only_fold);
        fs::write(
            out_dir.join("wrapped").join("wrapped_metrics.json"),
            serde_json::to_string_pretty(&wrapped_metrics).expect("json"),
        )
        .expect("write wrapped_metrics");
        return Ok(());
    }

    // Fast sanity: DeciderEth expects the "incoming" committed instance `u_i` to be non-relaxed,
    // i.e. its error commitment must be the identity (cmE == 0). If this is violated, the
    // DeciderEthCircuit will be unsatisfied and Groth16 wrapping will panic or fail after long setup.
    let u_i_comm_pre = folding.u_i.get_commitments();
    if u_i_comm_pre.get(1).is_some_and(|cm_e| !cm_e.is_zero()) {
        eprintln!("[pipeline] sanity: incoming instance u_i has non-zero cmE; cannot wrap with DeciderEth");
        return Err(Error::NotIncomingCommittedInstance);
    }

    // Fast sanity: cyclefold committed instance must match Pedersen commitments of its witness.
    // If this fails, the DeciderEthCircuit will be unsatisfied during the pedersen checks.
    {
        let cm_w = Pedersen::<G2>::commit(&folding.cf_cs_pp, &folding.cf_W_i.W, &folding.cf_W_i.rW)?;
        if cm_w != folding.cf_U_i.cmW {
            eprintln!("[pipeline] sanity: cyclefold cmW mismatch vs Pedersen(commit(W))");
            return Err(Error::CommitmentVerificationFail);
        }
        let e_all_zero = folding.cf_W_i.E.iter().all(|e| e.is_zero());
        let cm_e = if e_all_zero {
            G2::zero()
        } else {
            Pedersen::<G2>::commit(&folding.cf_cs_pp, &folding.cf_W_i.E, &folding.cf_W_i.rE)?
        };
        if cm_e != folding.cf_U_i.cmE {
            eprintln!("[pipeline] sanity: cyclefold cmE mismatch vs Pedersen(commit(E))");
            return Err(Error::CommitmentVerificationFail);
        }
    }

    eprintln!("[pipeline] sanity: build DeciderEthCircuit and check satisfiable...");
    let decider_circuit = DeciderEthCircuit::<G1, G2>::try_from(folding.clone())?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    decider_circuit.generate_constraints(cs.clone())?;
    let sat = cs.is_satisfied().map_err(|e| Error::SynthesisError(e))?;
    if !sat {
        if let Ok(Some(label)) = cs.which_is_unsatisfied() {
            eprintln!("[pipeline] sanity: first unsatisfied constraint: {label}");
        }
        return Err(Error::NotSatisfied);
    }
    eprintln!(
        "[pipeline] sanity: DeciderEthCircuit satisfied (constraints={})",
        cs.num_constraints()
    );

    wrapped_metrics["decider_circuit_satisfied"] = json!(true);
    wrapped_metrics["decider_circuit_constraints"] = json!(cs.num_constraints());
    if decider_sanity_only {
        fs::write(
            out_dir.join("wrapped").join("wrapped_metrics.json"),
            serde_json::to_string_pretty(&wrapped_metrics).expect("json"),
        )
        .expect("write wrapped_metrics");
        return Ok(());
    }

    if force {
        let wrapped_dir = out_dir.join("wrapped");
        if wrapped_dir.exists() {
            let _ = fs::remove_dir_all(&wrapped_dir);
        }
        fs::create_dir_all(&wrapped_dir)?;
    }

    let pp_hash = nova_params.1.pp_hash()?;
    let pp_hash_hex = fr_hex(&pp_hash);
    let decider_cache_prefix = format!(
        "decider_eth_{}_{}_pphash{}",
        cache_prefix,
        DECIDER_CIRCUIT_VERSION,
        &pp_hash_hex[..16]
    );
    let g16_pk_cache = cache_dir.join(format!("{decider_cache_prefix}_g16_pk.bin"));
    let decider_vp_cache = cache_dir.join(format!("{decider_cache_prefix}_vp.bin"));

    eprintln!("[pipeline] decider groth16 preprocess...");
    let groth16_preprocess_start = Instant::now();
    let (g16_pk, decider_vp) = if !no_cache && g16_pk_cache.exists() && decider_vp_cache.exists() {
        let g16_pk: Groth16Pk = cache::read_compressed(&g16_pk_cache)?;
        let decider_vp: DeciderVerifierParam<K, PROVE_SORTING> = cache::read_compressed(&decider_vp_cache)?;
        if decider_vp.pp_hash != pp_hash {
            let (decider_pp, decider_vp) =
                DeciderK::<K, PROVE_SORTING>::preprocess(&mut rng, (nova_params.clone(), state_len))?;
            if !no_cache {
                cache::write_compressed(&g16_pk_cache, &decider_pp.0)?;
                cache::write_compressed(&decider_vp_cache, &decider_vp)?;
            }
            (decider_pp.0, decider_vp)
        } else {
            (g16_pk, decider_vp)
        }
    } else {
        let (decider_pp, decider_vp) =
            DeciderK::<K, PROVE_SORTING>::preprocess(&mut rng, (nova_params.clone(), state_len))?;
        if !no_cache {
            cache::write_compressed(&g16_pk_cache, &decider_pp.0)?;
            cache::write_compressed(&decider_vp_cache, &decider_vp)?;
        }
        (decider_pp.0, decider_vp)
    };
    let decider_pp = (g16_pk, nova_params.0.cs_pp.clone());
    let groth16_preprocess_s = groth16_preprocess_start.elapsed().as_secs_f64();
    eprintln!("[pipeline] decider groth16 preprocess done: {:.2}s", groth16_preprocess_s);

    let i = folding.i;
    let z_i = folding.z_i.clone();
    let u_i = folding.u_i.clone();
    let u_i_comm = u_i.get_commitments();
    let u_big_i = folding.U_i.clone();
    let u_big_i_comm = u_big_i.get_commitments();

    eprintln!("[pipeline] wrapping (DeciderEth::prove)...");
    let wrap_start = Instant::now();
    let proof = DeciderK::<K, PROVE_SORTING>::prove(&mut rng, decider_pp, folding)?;
    let wrap_s = wrap_start.elapsed().as_secs_f64();
    eprintln!("[pipeline] wrapping done: {:.2}s", wrap_s);

    eprintln!("[pipeline] verifying wrapped proof (Rust)...");
    let verify_start = Instant::now();
    let verified = DeciderK::<K, PROVE_SORTING>::verify(
        decider_vp.clone(),
        i,
        z_0_for_wrap.clone(),
        z_i.clone(),
        &u_big_i_comm,
        &u_i_comm,
        &proof,
    )?;
    assert!(verified, "wrapped proof must verify");
    let verify_s = verify_start.elapsed().as_secs_f64();
    eprintln!("[pipeline] wrapped verify done: {:.2}s", verify_s);

    let calldata: Vec<u8> = prepare_calldata_for_nova_cyclefold_verifier(
        NovaVerificationMode::Explicit,
        i,
        z_0_for_wrap,
        z_i,
        &u_big_i,
        &u_i,
        &proof,
    )?;

    let vk = NovaCycleFoldVerifierKey::from((decider_vp, f_circuit.state_len()));
    let solidity_code = get_decider_template_for_cyclefold_decider(vk);

    fs::write(out_dir.join("wrapped").join("verifier.sol"), solidity_code.as_bytes()).expect("write verifier.sol");
    fs::write(out_dir.join("wrapped").join("calldata.bin"), calldata.as_slice()).expect("write calldata");
    cache::write_compressed(&out_dir.join("wrapped").join("proof.bin"), &proof)?;
    eprintln!("[pipeline] wrote wrapped artifacts (calldata_bytes={})", calldata.len());

    wrapped_metrics["groth16_preprocess_time_s"] = json!(groth16_preprocess_s);
    wrapped_metrics["wrap_time_s"] = json!(wrap_s);
    wrapped_metrics["verify_time_s"] = json!(verify_s);
    wrapped_metrics["calldata_bytes"] = json!(calldata.len());
    if let Some(h0) = receipt_h0 {
        wrapped_metrics["receipt_h0"] = json!(fr_hex(&h0));
    }
    wrapped_metrics["receipt_hN"] = json!(fr_hex(&h_prev));

    fs::write(
        out_dir.join("wrapped").join("wrapped_metrics.json"),
        serde_json::to_string_pretty(&wrapped_metrics).expect("json"),
    )
    .expect("write wrapped_metrics");

    Ok(())
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();

    let k = parse_arg_usize(&args, "--k").unwrap_or(64);
    let n_steps = parse_arg_usize(&args, "--n").unwrap_or(1);
    let top_k = parse_arg_u32(&args, "--top-k").unwrap_or(k as u32);
    let top_p_q16 = parse_arg_u32(&args, "--top-p-q16").unwrap_or(0x0001_0000u32);
    let t_q16 = parse_arg_u32(&args, "--t-q16").unwrap_or(0x0001_0000u32);
    let max_tokens = parse_arg_u32(&args, "--max-tokens").unwrap_or(n_steps as u32);
    let skip_wrap = has_flag(&args, "--skip-wrap");
    let only_fold = has_flag(&args, "--only-fold");
    let only_wrap = has_flag(&args, "--only-wrap");
    let prove_sorting_flag = has_flag(&args, "--prove-sorting");
    let decider_sanity_only = has_flag(&args, "--decider-sanity-only");
    if only_fold && only_wrap {
        panic!("use at most one of --only-fold / --only-wrap");
    }
    let verify_anvil = has_flag(&args, "--verify-anvil");
    let only_verify_anvil = has_flag(&args, "--only-verify-anvil");
    let rpc_url = args
        .iter()
        .position(|a| a == "--rpc-url")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let no_start_anvil = has_flag(&args, "--no-start-anvil");

    let artifact_dir_arg = args
        .iter()
        .position(|a| a == "--artifact-dir")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let out_dir = if let Some(p) = artifact_dir_arg {
        PathBuf::from(p)
    } else {
        let run_id = args
            .iter()
            .position(|a| a == "--run-id")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(mk_run_id);
        workspace_root().join("eval").join("artifacts").join(run_id)
    };
    let force = has_flag(&args, "--force");
    let cache_dir = args
        .iter()
        .position(|a| a == "--cache-dir")
        .and_then(|i| args.get(i + 1))
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| workspace_root().join("eval").join("cache"));
    let no_cache = has_flag(&args, "--no-cache");

    if only_verify_anvil {
        if !out_dir.exists() {
            eprintln!("artifact directory does not exist for --only-verify-anvil: {}", out_dir.display());
            return Ok(());
        }
        let script = workspace_root().join("eval").join("chain").join("verify_anvil.py");
        let mut cmd = Command::new("python3");
        cmd.current_dir(workspace_root())
            .arg(script)
            .arg("--artifact-dir")
            .arg(&out_dir)
            .arg("--rpc-url")
            .arg(&rpc_url);
        if no_start_anvil {
            cmd.arg("--no-start-anvil");
        }
        let status = cmd.status().expect("run verify_anvil.py");
        if !status.success() {
            eprintln!("local chain verification failed (anvil); see eval/chain/verify_anvil.py");
        }
        println!("{}", out_dir.display());
        return Ok(());
    }

    if only_wrap {
        if !out_dir.exists() {
            eprintln!("artifact directory does not exist for --only-wrap: {}", out_dir.display());
            return Ok(());
        }
    } else {
        if out_dir.exists() && !force {
            eprintln!(
                "artifact directory already exists; rerun with --force to overwrite: {}",
                out_dir.display()
            );
            println!("{}", out_dir.display());
            return Ok(());
        }
        if out_dir.exists() && force {
            let _ = fs::remove_dir_all(&out_dir);
        }
    }

    let prove_sorting = if only_wrap && !prove_sorting_flag {
        // When wrapping an existing IVC proof, infer the circuit variant from meta.json if present.
        let meta_path = out_dir.join("meta.json");
        fs::read(&meta_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("prove_sorting").and_then(|x| x.as_bool()))
            .unwrap_or(false)
    } else {
        prove_sorting_flag
    };

    match k {
        16 => {
            if prove_sorting {
                run_for_k::<16, true>(
                    n_steps,
                    top_k,
                    top_p_q16,
                    t_q16,
                    max_tokens,
                    &out_dir,
                    skip_wrap,
                    only_fold,
                    only_wrap,
                    decider_sanity_only,
                    force,
                    &cache_dir,
                    no_cache,
                )?
            } else {
                run_for_k::<16, false>(
                    n_steps,
                    top_k,
                    top_p_q16,
                    t_q16,
                    max_tokens,
                    &out_dir,
                    skip_wrap,
                    only_fold,
                    only_wrap,
                    decider_sanity_only,
                    force,
                    &cache_dir,
                    no_cache,
                )?
            }
        }
        32 => {
            if prove_sorting {
                run_for_k::<32, true>(
                    n_steps,
                    top_k,
                    top_p_q16,
                    t_q16,
                    max_tokens,
                    &out_dir,
                    skip_wrap,
                    only_fold,
                    only_wrap,
                    decider_sanity_only,
                    force,
                    &cache_dir,
                    no_cache,
                )?
            } else {
                run_for_k::<32, false>(
                    n_steps,
                    top_k,
                    top_p_q16,
                    t_q16,
                    max_tokens,
                    &out_dir,
                    skip_wrap,
                    only_fold,
                    only_wrap,
                    decider_sanity_only,
                    force,
                    &cache_dir,
                    no_cache,
                )?
            }
        }
        64 => {
            if prove_sorting {
                run_for_k::<64, true>(
                    n_steps,
                    top_k,
                    top_p_q16,
                    t_q16,
                    max_tokens,
                    &out_dir,
                    skip_wrap,
                    only_fold,
                    only_wrap,
                    decider_sanity_only,
                    force,
                    &cache_dir,
                    no_cache,
                )?
            } else {
                run_for_k::<64, false>(
                    n_steps,
                    top_k,
                    top_p_q16,
                    t_q16,
                    max_tokens,
                    &out_dir,
                    skip_wrap,
                    only_fold,
                    only_wrap,
                    decider_sanity_only,
                    force,
                    &cache_dir,
                    no_cache,
                )?
            }
        }
        _ => panic!("unsupported --k (expected 16/32/64)"),
    }

    if verify_anvil {
        let script = workspace_root().join("eval").join("chain").join("verify_anvil.py");
        let mut cmd = Command::new("python3");
        cmd.current_dir(workspace_root())
            .arg(script)
            .arg("--artifact-dir")
            .arg(&out_dir)
            .arg("--rpc-url")
            .arg(&rpc_url);
        if no_start_anvil {
            cmd.arg("--no-start-anvil");
        }
        let status = cmd.status().expect("run verify_anvil.py");
        if !status.success() {
            eprintln!("local chain verification failed (anvil); see eval/chain/verify_anvil.py");
        }
    }

    println!("{}", out_dir.display());
    Ok(())
}
