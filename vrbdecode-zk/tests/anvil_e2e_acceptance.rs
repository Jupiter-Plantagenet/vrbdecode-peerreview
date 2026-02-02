use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn mk_tmp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("vrbdecode_{}_{}_{}", name, std::process::id(), 123456789u64));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("mkdir tmp");
    p
}

fn require_tool(tool: &str) {
    let ok = Command::new(tool)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if ok {
        return;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let candidate = PathBuf::from(home).join(".foundry").join("bin").join(tool);
    let ok = Command::new(candidate)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    assert!(ok, "missing required tool: {} (install Foundry)", tool);
}

#[test]
#[ignore]
fn anvil_e2e_pipeline_wrap_and_verify_acceptance() {
    if std::env::var("VRBDECODE_RUN_EVM_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping (set VRBDECODE_RUN_EVM_TESTS=1 to enable)");
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!(
            "skipping in debug mode (run `VRBDECODE_RUN_EVM_TESTS=1 cargo test -p vrbdecode-zk --release -- --ignored anvil_e2e_pipeline_wrap_and_verify_acceptance`)"
        );
        return;
    }

    require_tool("anvil");
    require_tool("forge");
    require_tool("cast");

    let pipeline_exe = PathBuf::from(env!("CARGO_BIN_EXE_pipeline"));
    let root = workspace_root();
    let verifier_script = root.join("eval").join("chain").join("verify_anvil.py");
    assert!(verifier_script.exists());

    let out_root = mk_tmp_dir("anvil_acceptance_artifacts");
    let cache_root = mk_tmp_dir("anvil_acceptance_cache");
    let out_dir = out_root.join("run");
    let cache_dir = cache_root.join("cache");

    // Generate wrapped artifacts (N must be >= 2 for the CycleFold decider).
    let status = Command::new(&pipeline_exe)
        .current_dir(&root)
        .arg("--k")
        .arg("16")
        .arg("--n")
        .arg("2")
        .arg("--artifact-dir")
        .arg(&out_dir)
        .arg("--cache-dir")
        .arg(&cache_dir)
        .status()
        .expect("run pipeline");
    assert!(status.success(), "pipeline failed");

    // Verify on Anvil (script asserts return=true and tx status==1).
    let mut cmd = Command::new("python3");
    cmd.env("FOUNDRY_BIN", PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".foundry").join("bin"))
        .current_dir(&root)
        .arg(&verifier_script)
        .arg("--artifact-dir")
        .arg(&out_dir)
        ;
    let status = cmd.status().expect("run verify_anvil.py");
    assert!(status.success(), "verify_anvil.py failed");

    let _ = fs::remove_dir_all(&out_root);
    let _ = fs::remove_dir_all(&cache_root);
}
