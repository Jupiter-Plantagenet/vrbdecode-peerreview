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
fn anvil_precompile_gas_probe_acceptance() {
    if std::env::var("VRBDECODE_RUN_EVM_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping (set VRBDECODE_RUN_EVM_TESTS=1 to enable)");
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!(
            "skipping in debug mode (run `VRBDECODE_RUN_EVM_TESTS=1 cargo test -p vrbdecode-zk --release -- --ignored anvil_precompile_gas_probe_acceptance`)"
        );
        return;
    }

    require_tool("anvil");
    require_tool("forge");
    require_tool("cast");

    let root = workspace_root();
    let script = root.join("eval").join("chain").join("probe_precompile_gas_anvil.py");
    assert!(script.exists());

    let out_root = mk_tmp_dir("precompile_probe");
    let out_dir = out_root.join("out");

    let home = std::env::var("HOME").unwrap_or_default();
    let foundry_bin = PathBuf::from(home).join(".foundry").join("bin");

    let status = Command::new("python3")
        .env("FOUNDRY_BIN", &foundry_bin)
        .current_dir(&root)
        .arg(&script)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--n")
        .arg("20")
        .status()
        .expect("run probe_precompile_gas_anvil.py");
    assert!(status.success(), "precompile probe script failed");

    let probe_path = out_dir.join("probe_call.json");
    let doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&probe_path).expect("read probe_call.json"))
            .expect("parse json");
    let ecmul_gas = doc
        .get("ecmul_gas")
        .and_then(|v| v.as_u64())
        .expect("ecmul_gas u64");
    let ecadd_gas = doc
        .get("ecadd_gas")
        .and_then(|v| v.as_u64())
        .expect("ecadd_gas u64");

    // Sanity thresholds: these should be comfortably exceeded if precompiles are priced realistically.
    // If Anvil/EVM is undercharging BN254 precompiles, these can come out unexpectedly low.
    assert!(
        ecmul_gas >= 50_000,
        "unexpectedly low ECMUL gas delta ({}): BN254 precompile pricing may be wrong on this node",
        ecmul_gas
    );
    assert!(
        ecadd_gas >= 1_000,
        "unexpectedly low ECADD gas delta ({}): BN254 precompile pricing may be wrong on this node",
        ecadd_gas
    );

    let _ = fs::remove_dir_all(&out_root);
}

