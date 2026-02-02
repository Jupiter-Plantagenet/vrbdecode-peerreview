use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_serialize::{CanonicalSerialize, Compress, Validate};
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{decider_eth::Decider as DeciderEth, IVCProof, Nova, PreprocessorParam};
use folding_schemes::folding::traits::CommittedInstanceOps;
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, Error, FoldingScheme};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;
use serde_json::json;
use solidity_verifiers::calldata::{prepare_calldata_for_nova_cyclefold_verifier, NovaVerificationMode};
use solidity_verifiers::verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider;
use solidity_verifiers::NovaCycleFoldVerifierKey;

use vrbdecode_zk::{cache, poseidon_params_bn254_rate8, StepFCircuit};

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

const PROTOCOL_VERSION: &str = "1";
const DECIDER_CIRCUIT_VERSION: &str = "pedersen_safe_v1";

#[derive(Debug, Deserialize, Clone)]
struct Meta {
    k: usize,
    n_steps: usize,
    #[serde(default)]
    prove_sorting: Option<bool>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Option<T> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn protocol_version_of(run_dir: &Path) -> Option<String> {
    fs::read_to_string(run_dir.join("protocol_version.txt"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn list_run_dirs(artifact_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(it) = fs::read_dir(artifact_root) else {
        return out;
    };
    for entry in it.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn wrap_one<const K: usize, const PROVE_SORTING: bool>(
    run_dir: &Path,
    meta: &Meta,
    cache_dir: &Path,
    no_cache: bool,
    force: bool,
) -> Result<serde_json::Value, Error> {
    let f_circuit = StepFCircuit::<K, PROVE_SORTING>::new_default()?;
    let state_len = f_circuit.state_len();
    let cache_prefix = format!("k{}_state{}_v{}_prove_sorting{}", K, state_len, PROTOCOL_VERSION, PROVE_SORTING as u8);

    let nova_pp_cache = cache_dir.join(format!("nova_{}_pp.bin", cache_prefix));
    let nova_vp_cache = cache_dir.join(format!("nova_{}_vp.bin", cache_prefix));
    let fc_params = poseidon_params_bn254_rate8();

    let transcript_cfg = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::seed_from_u64(123456789u64);

    let preprocess_start = Instant::now();
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

    let proof_path = run_dir.join("nova").join("ivc_proof.bin");
    let ivc_proof: IVCProof<G1, G2> = cache::read_compressed(&proof_path)?;
    let z_0_for_wrap = ivc_proof.z_0.clone();
    let h_prev = ivc_proof.z_i.last().cloned().unwrap_or_else(|| Fr::from(0u64));

    let folding = NovaK::<K, PROVE_SORTING>::from_ivc_proof(ivc_proof, fc_params.clone(), nova_params.clone())?;

    let wrapped_dir = run_dir.join("wrapped");
    if force && wrapped_dir.exists() {
        let _ = fs::remove_dir_all(&wrapped_dir);
    }
    fs::create_dir_all(&wrapped_dir)?;

    let pp_hash = nova_params.1.pp_hash()?;
    let mut pp_hash_bytes = Vec::new();
    pp_hash.serialize_compressed(&mut pp_hash_bytes)?;
    let pp_hash_hex = hex::encode(pp_hash_bytes);
    let decider_cache_prefix = format!(
        "decider_eth_{}_{}_pphash{}",
        cache_prefix,
        DECIDER_CIRCUIT_VERSION,
        &pp_hash_hex[..16]
    );
    let g16_pk_cache = cache_dir.join(format!("{decider_cache_prefix}_g16_pk.bin"));
    let decider_vp_cache = cache_dir.join(format!("{decider_cache_prefix}_vp.bin"));

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
    let groth16_preprocess_s = groth16_preprocess_start.elapsed().as_secs_f64();

    let i = folding.i;
    let z_i = folding.z_i.clone();
    let u_i = folding.u_i.clone();
    let u_i_comm = u_i.get_commitments();
    let u_big_i = folding.U_i.clone();
    let u_big_i_comm = u_big_i.get_commitments();

    let decider_pp = (g16_pk, nova_params.0.cs_pp.clone());

    let wrap_start = Instant::now();
    let proof = DeciderK::<K, PROVE_SORTING>::prove(&mut rng, decider_pp, folding)?;
    let wrap_s = wrap_start.elapsed().as_secs_f64();

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

    let calldata: Vec<u8> = prepare_calldata_for_nova_cyclefold_verifier(
        NovaVerificationMode::Explicit,
        i,
        z_0_for_wrap,
        z_i,
        &u_big_i,
        &u_i,
        &proof,
    )?;

    let vk = NovaCycleFoldVerifierKey::from((decider_vp, state_len));
    let solidity_code = get_decider_template_for_cyclefold_decider(vk);

    fs::write(wrapped_dir.join("verifier.sol"), solidity_code.as_bytes())?;
    fs::write(wrapped_dir.join("calldata.bin"), calldata.as_slice())?;
    cache::write_compressed(&wrapped_dir.join("proof.bin"), &proof)?;

    let h_prev_hex = hex::encode({
        let mut b = Vec::new();
        h_prev.serialize_compressed(&mut b).expect("serialize h_prev");
        b
    });
    let metrics = json!({
        "k": meta.k,
        "n_steps": meta.n_steps,
        "nova_preprocess_time_s": nova_preprocess_s,
        "groth16_preprocess_time_s": groth16_preprocess_s,
        "wrap_time_s": wrap_s,
        "verify_time_s": verify_s,
        "calldata_bytes": calldata.len(),
        "receipt_hN_field_compressed_hex": h_prev_hex,
    });
    fs::write(
        wrapped_dir.join("wrapped_metrics.json"),
        serde_json::to_string_pretty(&metrics).expect("json"),
    )?;

    Ok(metrics)
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let artifact_root = args
        .iter()
        .position(|a| a == "--artifact-root")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("eval").join("artifacts"));
    let cache_dir = args
        .iter()
        .position(|a| a == "--cache-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("eval").join("cache"));
    let no_cache = args.iter().any(|a| a == "--no-cache");
    let force = args.iter().any(|a| a == "--force");
    let json_only = args.iter().any(|a| a == "--json");
    let prove_sorting_flag = args.iter().any(|a| a == "--prove-sorting");

    let mut run_ids: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--run-id" {
            if let Some(v) = args.get(i + 1) {
                run_ids.push(v.clone());
            }
            i += 2;
            continue;
        }
        i += 1;
    }

    let run_dirs: Vec<PathBuf> = if run_ids.is_empty() {
        list_run_dirs(&artifact_root)
    } else {
        run_ids
            .into_iter()
            .map(|id| artifact_root.join(id))
            .collect()
    };

    let mut results: Vec<serde_json::Value> = Vec::new();

    for run_dir in run_dirs {
        let Some(proto) = protocol_version_of(&run_dir) else {
            continue;
        };
        if proto != PROTOCOL_VERSION {
            continue;
        }
        let Some(meta) = read_json::<Meta>(&run_dir.join("meta.json")) else {
            continue;
        };
        if !run_dir.join("nova").join("ivc_proof.bin").exists() {
            continue;
        }

        let inferred = meta.prove_sorting.unwrap_or(false);
        let prove_sorting = if prove_sorting_flag { true } else { inferred };
        let r = match meta.k {
            16 => {
                if prove_sorting {
                    wrap_one::<16, true>(&run_dir, &meta, &cache_dir, no_cache, force)?
                } else {
                    wrap_one::<16, false>(&run_dir, &meta, &cache_dir, no_cache, force)?
                }
            }
            32 => {
                if prove_sorting {
                    wrap_one::<32, true>(&run_dir, &meta, &cache_dir, no_cache, force)?
                } else {
                    wrap_one::<32, false>(&run_dir, &meta, &cache_dir, no_cache, force)?
                }
            }
            64 => {
                if prove_sorting {
                    wrap_one::<64, true>(&run_dir, &meta, &cache_dir, no_cache, force)?
                } else {
                    wrap_one::<64, false>(&run_dir, &meta, &cache_dir, no_cache, force)?
                }
            }
            _ => continue,
        };
        results.push(r);
    }

    if json_only {
        println!("{}", serde_json::to_string(&results).expect("json"));
        return Ok(());
    }

    let out_dir = workspace_root().join("eval").join("wrapped_proofs");
    fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join("wrapped_results.json");
    fs::write(&out_path, serde_json::to_string_pretty(&results).expect("json"))?;
    println!("wrote {}", out_path.display());
    Ok(())
}
