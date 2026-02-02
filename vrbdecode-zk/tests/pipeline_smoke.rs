use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ark_bn254::{Fr, G1Projective as G1};
use ark_grumpkin::Projective as G2;
use folding_schemes::folding::nova::IVCProof;

use vrbdecode_zk::cache;

fn mk_tmp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("vrbdecode_{}_{}_{}", name, std::process::id(), 123456789u64));
    p
}

#[test]
#[ignore]
fn pipeline_writes_fold_artifacts_and_serializes_ivc_proof() {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_pipeline"));

    let out_root = mk_tmp_dir("pipeline_smoke_artifacts_root");
    let cache_root = mk_tmp_dir("pipeline_smoke_cache_root");
    let _ = fs::remove_dir_all(&out_root);
    let _ = fs::remove_dir_all(&cache_root);
    fs::create_dir_all(&out_root).expect("mkdir out_root");
    fs::create_dir_all(&cache_root).expect("mkdir cache_root");

    let out_dir = out_root.join("run");
    let cache_dir = cache_root.join("cache");

    let status = Command::new(exe)
        .arg("--k")
        .arg("16")
        .arg("--n")
        .arg("1")
        .arg("--only-fold")
        .arg("--artifact-dir")
        .arg(&out_dir)
        .arg("--cache-dir")
        .arg(&cache_dir)
        .status()
        .expect("run pipeline");
    assert!(status.success(), "pipeline exited nonzero");

    assert!(out_dir.join("protocol_version.txt").exists());
    assert!(out_dir.join("meta.json").exists());
    assert!(out_dir.join("public_inputs.json").exists());
    assert!(out_dir.join("receipt.json").exists());
    assert!(out_dir.join("vectors_hash.txt").exists());
    assert!(out_dir.join("nova").join("ivc_proof.bin").exists());
    assert!(out_dir.join("wrapped").join("wrapped_metrics.json").exists());

    let proof: IVCProof<G1, G2> = cache::read_compressed(&out_dir.join("nova").join("ivc_proof.bin"))
        .expect("deserialize ivc_proof.bin");
    assert_eq!(proof.z_0.len(), 9, "z_0 length");
    assert_eq!(proof.z_i.len(), 9, "z_i length");
    assert!(proof.i >= Fr::from(1u64), "i should be >= 1 for N=1 fold");

    let _ = fs::remove_dir_all(&out_root);
    let _ = fs::remove_dir_all(&cache_root);
}
