use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as Projective2;
use ark_serialize::CanonicalSerialize;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen};
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::FoldingScheme;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;

use vrbdecode_zk::{protocol, StepExternalInputs, StepFCircuit};

type NovaK<const K: usize, const PROVE_SORTING: bool> = Nova<
    Projective,
    Projective2,
    StepFCircuit<K, PROVE_SORTING>,
    KZG<'static, Bn254>,
    Pedersen<Projective2>,
    false,
>;

const HASH_FN_ID: u32 = 1;
const EXP_APPROX_ID: u32 = 1;

fn proc_status_kb(key: &str) -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let v = rest
                .split_whitespace()
                .next()
                .and_then(|t| t.parse::<u64>().ok());
            if v.is_some() {
                return v;
            }
        }
    }
    None
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
    if d <= 0 { return 0; }
    if n >= 0 { n / d } else { -((-n + d - 1) / d) }
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
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
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
        if slog_native[i] != slog_native[j] { return slog_native[j].cmp(&slog_native[i]); }
        token_id[i].cmp(&token_id[j])
    });
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);
    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.Candidates.v1" { elems.push(Fr::from(b as u64)); }
    for &idx in &perm {
        elems.push(Fr::from(token_id[idx] as u64));
        elems.push(Fr::from(logit_q16[idx] as u32 as u64));
    }
    sponge.absorb(&elems);
    sponge.squeeze_native_field_elements(1)[0]
}

fn receipt_update(
    h_prev: Fr, request_id_lo: Fr, request_id_hi: Fr, policy_hash_lo: Fr, policy_hash_hi: Fr,
    seed_commit_lo: Fr, seed_commit_hi: Fr, step_idx: u32, cand_hash: Fr, y: u32, ws: u64, r: u64,
) -> Fr {
    let params = poseidon_params_bn254_rate8();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);
    let mut elems: Vec<Fr> = Vec::new();
    for &b in b"VRBDecode.Receipt.v1" { elems.push(Fr::from(b as u64)); }
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

const Q30: u64 = 1 << 30;
const Z_MIN_Q16: i64 = -(12 << 16);
const E_Q30: [u64; 13] = [1073741824,395007542,145315154,53458458,19666268,7234816,2661540,979126,360200,132510,48748,17933,6597];

fn mul_q30_i64(a: i64, b: i64) -> i64 { ((a as i128 * b as i128) >> 30) as i64 }

fn exp_poly5_q16_16_to_q30(r_q16: i64) -> u64 {
    let r_q30: i64 = r_q16 << 14;
    let r2 = mul_q30_i64(r_q30, r_q30);
    let r3 = mul_q30_i64(r2, r_q30);
    let r4 = mul_q30_i64(r3, r_q30);
    let r5 = mul_q30_i64(r4, r_q30);
    let p: i128 = Q30 as i128
        + r_q30 as i128
        + (r2 as i128) / 2
        + floor_div_i128(r3 as i128, 6)
        + (r4 as i128) / 24
        + floor_div_i128(r5 as i128, 120);
    if p <= 0 { return 0; }
    if p >= Q30 as i128 { return Q30; }
    p as u64
}

fn decode_step_native(k: usize, top_k: usize, top_p_q16: u32, t_q16: u32, token_id: &[u32], logit_q16: &[i32], u_t: u64) -> (u32, u64, u64) {
    let t_clamped = t_q16.max(1);
    let mut items: Vec<(u32, i64)> = Vec::with_capacity(k);
    for i in 0..k {
        let num = (logit_q16[i] as i128) << 16;
        let s = floor_div_i128(num, t_clamped as i128) as i64;
        items.push((token_id[i], s));
    }
    items.sort_by(|a, b| { if a.1 != b.1 { return b.1.cmp(&a.1); } a.0.cmp(&b.0) });
    let m = items[0].1;
    let mut w: Vec<u64> = vec![0; k];
    for i in 0..top_k {
        let mut z = items[i].1 - m;
        if z < Z_MIN_Q16 { z = Z_MIN_Q16; }
        let neg_z = -z;
        let mut n = (neg_z >> 16) as i64;
        if n < 0 { n = 0; }
        if n > 12 { n = 12; }
        let r = z + (n << 16);
        let p = exp_poly5_q16_16_to_q30(r);
        w[i] = ((E_Q30[n as usize] as u128 * p as u128) >> 30) as u64;
    }
    let mut wk: u64 = 0;
    for i in 0..top_k { wk = wk.wrapping_add(w[i]); }
    let th = ((top_p_q16 as u128 * wk as u128) >> 16) as u64;
    let mut prefix: u64 = 0;
    let mut s: usize = 1;
    for i in 0..top_k { prefix = prefix.wrapping_add(w[i]); if prefix >= th { s = i + 1; break; } }
    let mut ws: u64 = 0;
    for i in 0..s { ws = ws.wrapping_add(w[i]); }
    let r = (((u_t as u128) * (ws as u128)) >> 64) as u64;
    let mut prefix2: u64 = 0;
    let mut j: usize = 0;
    for i in 0..s { prefix2 = prefix2.wrapping_add(w[i]); if prefix2 > r { j = i; break; } }
    (items[j].0, ws, r)
}

#[derive(Debug, Deserialize, Clone)]
struct Vector {
    #[serde(rename = "K")] k: usize,
    top_k: usize,
    top_p_q16: u32,
    #[serde(rename = "T_q16")] t_q16: u32,
    token_id: Vec<u32>,
    logit_q16: Vec<i32>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn load_jsonl(path: &PathBuf) -> Vec<Vector> {
    let f = File::open(path).expect("open vectors file");
    let r = BufReader::new(f);
    r.lines().filter_map(|l| l.ok()).filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Vector>(&l).expect("parse")).collect()
}

fn vectors_k16() -> Vec<Vector> {
    let root = workspace_root().join("vectors");
    let mut rows: Vec<Vector> = Vec::new();
    rows.extend(load_jsonl(&root.join("golden.jsonl")));
    rows.extend(load_jsonl(&root.join("random.jsonl")));
    rows.into_iter().filter(|v| v.k == 16).collect()
}

fn vectors_k<const K: usize>() -> Vec<Vector> {
    let root = workspace_root().join("vectors");
    let mut rows: Vec<Vector> = Vec::new();
    rows.extend(load_jsonl(&root.join("golden.jsonl")));
    rows.extend(load_jsonl(&root.join("random.jsonl")));
    rows.into_iter().filter(|v| v.k == K).collect()
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
    let mut token_id: [u32; K] = row.token_id.clone().try_into().unwrap();
    let mut logit_q16: [i32; K] = row.logit_q16.clone().try_into().unwrap();
    protocol::canonicalize_candidates_in_place(&mut token_id, &mut logit_q16, t_q16);

    let u_t = protocol::prf_u_t(request_id_lo, request_id_hi, policy_hash_field, seed_commit_field, step_idx);
    let (y, ws, r) = decode_step_native(
        K,
        top_k as usize,
        top_p_q16,
        t_q16,
        &row.token_id,
        &row.logit_q16,
        u_t,
    );
    let lo = ((u_t as u128) * (ws as u128)) as u64;

    let cand_hash = protocol::candidate_hash::<K>(&token_id, &logit_q16, t_q16);
    let h_new = protocol::receipt_update(
        h_prev,
        request_id_lo,
        request_id_hi,
        policy_hash_field,
        seed_commit_field,
        step_idx,
        cand_hash,
        y,
        ws,
        r,
    );

    StepExternalInputs {
        seed_lo,
        seed_hi,
        token_id,
        logit_q16,
        expected_y: y,
        expected_ws: ws,
        expected_r: r,
        expected_lo: lo,
        h_new,
    }
}

#[derive(Debug, Clone, Serialize)]
struct BenchRow {
    n_steps: usize,
    avg_step_time_s: f64,
    total_fold_time_s: f64,
    proof_size_bytes: usize,
    verify_time_s: f64,
    peak_rss_kb: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchOutput {
    preprocess_time_s: f64,
    prove_sorting: bool,
    results: Vec<BenchRow>,
}

fn bench_nova_n<const K: usize, const PROVE_SORTING: bool>(
    num_steps: usize,
    params: &(
        <NovaK<K, PROVE_SORTING> as FoldingScheme<Projective, Projective2, StepFCircuit<K, PROVE_SORTING>>>::ProverParam,
        <NovaK<K, PROVE_SORTING> as FoldingScheme<Projective, Projective2, StepFCircuit<K, PROVE_SORTING>>>::VerifierParam,
    ),
    vectors: &[Vector],
    verbose: bool,
    progress: bool,
) -> Result<BenchRow, folding_schemes::Error> {
    assert!(vectors.len() >= num_steps, "Need {} K={} vectors", num_steps, K);

    let request_id_lo = Fr::from(0u64);
    let request_id_hi = Fr::from(0u64);
    let top_k: u32 = K as u32;
    let top_p_q16: u32 = 0x0001_0000u32;
    let t_q16: u32 = 0x0001_0000u32;
    let max_tokens: u32 = num_steps as u32;

    let policy_hash_field =
        protocol::policy_hash_field(K as u32, top_k, top_p_q16, t_q16, max_tokens, HASH_FN_ID, EXP_APPROX_ID);

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

    let f_circuit = StepFCircuit::<K, PROVE_SORTING>::new_default()?;

    let mut ext_inputs: Vec<StepExternalInputs<K>> = Vec::with_capacity(num_steps);
    let mut h_prev = h0;
    for (step_idx, row) in vectors.iter().take(num_steps).enumerate() {
        let ext = mk_external_inputs::<K>(
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

    let mut rng = StdRng::seed_from_u64(123456789u64 + num_steps as u64);
    let mut folding = NovaK::<K, PROVE_SORTING>::init(params, f_circuit, initial_state)?;

    if verbose {
        println!("  Folding {} steps...", num_steps);
    }
    if progress {
        eprintln!("Folding {} steps...", num_steps);
    }
    let fold_start = Instant::now();
    for ext in ext_inputs.iter() {
        folding.prove_step(&mut rng, ext.clone(), None)?;
    }
    let total_fold_time = fold_start.elapsed().as_secs_f64();
    let avg_step_time = total_fold_time / num_steps as f64;

    let proof = folding.ivc_proof();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).expect("serialize proof");
    let proof_size = proof_bytes.len();

    if verbose {
        println!("  Verifying...");
    }
    if progress {
        eprintln!("Verifying...");
    }
    let verify_start = Instant::now();
    NovaK::<K, PROVE_SORTING>::verify(params.1.clone(), proof)?;
    let verify_time = verify_start.elapsed().as_secs_f64();
    let peak_rss_kb = proc_status_kb("VmHWM:");

    Ok(BenchRow {
        n_steps: num_steps,
        avg_step_time_s: avg_step_time,
        total_fold_time_s: total_fold_time,
        proof_size_bytes: proof_size,
        verify_time_s: verify_time,
        peak_rss_kb,
    })
}

fn run_for_k<const K: usize, const PROVE_SORTING: bool>(step_counts: Vec<usize>, json_only: bool, progress: bool) {
    let verbose = !json_only;

    if verbose {
        println!(
            "=== VRBDecode Nova Folding Benchmarks (K={}, mode={}) ===\n",
            K,
            if PROVE_SORTING { "prove_sorting" } else { "assume_canonical_sorted" }
        );
    }

    let vectors = vectors_k::<K>();
    let max_n = *step_counts.iter().max().unwrap_or(&0);
    assert!(
        vectors.len() >= max_n,
        "Need at least {} K={} vectors (golden+random), found {}",
        max_n,
        K,
        vectors.len()
    );

    if verbose {
        println!("Preprocessing (once)...");
    }
    if progress {
        eprintln!("Preprocessing (once)...");
    }
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let f_circuit = StepFCircuit::<K, PROVE_SORTING>::new_default().expect("fcircuit");
    let mut rng = StdRng::seed_from_u64(123456789u64);
    let pp = PreprocessorParam::new(poseidon_config, f_circuit);
    let preprocess_start = Instant::now();
    let params = NovaK::<K, PROVE_SORTING>::preprocess(&mut rng, &pp).expect("preprocess");
    let preprocess_time_s = preprocess_start.elapsed().as_secs_f64();

    let mut results: Vec<BenchRow> = Vec::new();

    if !json_only {
        println!(
            "\n{:<8} {:>14} {:>14} {:>12} {:>14}",
            "N steps", "Avg Step (s)", "Total (s)", "Proof (B)", "Verify (s)"
        );
        println!("{}", "-".repeat(66));
    }

    for &n in &step_counts {
        if verbose {
            println!("\nBenchmarking N={}...", n);
        }
        if progress {
            eprintln!("Benchmarking N={}...", n);
        }
        let row = bench_nova_n::<K, PROVE_SORTING>(n, &params, &vectors, verbose, progress).expect("bench");
        if verbose {
            println!(
                "{:<8} {:>14.3} {:>14.3} {:>12} {:>14.4}",
                row.n_steps, row.avg_step_time_s, row.total_fold_time_s, row.proof_size_bytes, row.verify_time_s
            );
        }
        results.push(row);
    }

    let out = BenchOutput {
        preprocess_time_s,
        prove_sorting: PROVE_SORTING,
        results,
    };

    if json_only {
        println!("{}", serde_json::to_string(&out).expect("json"));
        return;
    }

    println!("\nPreprocess time: {:.2}s", preprocess_time_s);
    println!("\n=== Summary for Table 1 ===");
    println!("Run complete. See above for detailed metrics.");
}

fn main() {
    let args_vec: Vec<String> = std::env::args().collect();
    let json_only = args_vec.iter().any(|a| a == "--json");
    let progress = args_vec.iter().any(|a| a == "--progress") || std::env::var("VRBDECODE_BENCH_PROGRESS").is_ok();
    let prove_sorting = args_vec.iter().any(|a| a == "--prove-sorting")
        || matches!(
            std::env::var("VRBDECODE_PROVE_SORTING").ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
        );
    let mut k: usize = 16;

    let mut step_counts: Vec<usize> = vec![32, 64, 128, 256];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--k" {
            if let Some(v) = args.next() {
                k = v.parse::<usize>().expect("parse k");
            }
        }
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

    match k {
        16 => {
            if prove_sorting {
                run_for_k::<16, true>(step_counts, json_only, progress)
            } else {
                run_for_k::<16, false>(step_counts, json_only, progress)
            }
        }
        32 => {
            if prove_sorting {
                run_for_k::<32, true>(step_counts, json_only, progress)
            } else {
                run_for_k::<32, false>(step_counts, json_only, progress)
            }
        }
        64 => {
            if prove_sorting {
                run_for_k::<64, true>(step_counts, json_only, progress)
            } else {
                run_for_k::<64, false>(step_counts, json_only, progress)
            }
        }
        _ => panic!("unsupported k"),
    }
}
