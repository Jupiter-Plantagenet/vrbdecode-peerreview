use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use serde::Deserialize;

use vrbdecode_core::decode_step;

#[derive(Debug, Deserialize)]
struct Expected {
    y: u32,
    #[serde(rename = "Ws")]
    ws: u64,
    #[serde(rename = "R")]
    r: u64,
}

#[derive(Debug, Deserialize)]
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
    u_t: u64,
    expected: Expected,
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

fn assert_vectors(path: PathBuf) {
    let rows = load_jsonl(&path);
    assert!(!rows.is_empty());

    for row in rows {
        let res = decode_step(
            row.k,
            row.top_k,
            row.top_p_q16,
            row.t_q16,
            &row.token_id,
            &row.logit_q16,
            row.u_t,
        );

        assert_eq!(res.y, row.expected.y);
        assert_eq!(res.ws, row.expected.ws);
        assert_eq!(res.r, row.expected.r);
    }
}

#[test]
fn golden_vectors_match_python_reference() {
    let path = workspace_root().join("vectors").join("golden.jsonl");
    assert_vectors(path);
}

#[test]
fn randomized_vectors_match_python_reference() {
    let path = workspace_root().join("vectors").join("random.jsonl");
    assert_vectors(path);
}
