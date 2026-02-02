use serde::{Deserialize, Serialize};

const Q16: i64 = 1 << 16;
const Q30: u64 = 1 << 30;
const T_MIN_Q16: u32 = 1;
const Z_MIN_Q16: i64 = -(12 << 16);

const E_Q30: [u64; 13] = [
    1073741824,
    395007542,
    145315154,
    53458458,
    19666268,
    7234816,
    2661540,
    979126,
    360200,
    132510,
    48748,
    17933,
    6597,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeStepResult {
    pub y: u32,
    pub ws: u64,
    pub r: u64,
}

fn floor_div_i128(n: i128, d: i128) -> i128 {
    if d <= 0 {
        panic!("denominator must be positive");
    }
    if n >= 0 {
        n / d
    } else {
        -((-n + d - 1) / d)
    }
}

fn mul_q30_i64(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) >> 30) as i64
}

fn exp_poly5_q16_16_to_q30(r_q16: i64) -> u64 {
    let r_q30: i64 = r_q16 << 14;

    let r2: i64 = mul_q30_i64(r_q30, r_q30);
    let r3: i64 = mul_q30_i64(r2, r_q30);
    let r4: i64 = mul_q30_i64(r3, r_q30);
    let r5: i64 = mul_q30_i64(r4, r_q30);

    let mut p: i128 = Q30 as i128;
    p += r_q30 as i128;
    p += (r2 as i128) / 2;
    p += floor_div_i128(r3 as i128, 6);
    p += (r4 as i128) / 24;
    p += floor_div_i128(r5 as i128, 120);

    if p <= 0 {
        return 0;
    }
    if p >= Q30 as i128 {
        return Q30;
    }
    p as u64
}

pub fn decode_step(
    k: usize,
    top_k: usize,
    top_p_q16: u32,
    t_q16: u32,
    token_id: &[u32],
    logit_q16: &[i32],
    u_t: u64,
) -> DecodeStepResult {
    if k == 0 {
        panic!("K must be positive");
    }
    if token_id.len() != k || logit_q16.len() != k {
        panic!("token_id and logit_q16 must have length K");
    }
    if top_k == 0 || top_k > k {
        panic!("top_k must satisfy 1 <= top_k <= K");
    }
    if top_p_q16 == 0 || top_p_q16 > Q16 as u32 {
        panic!("top_p_q16 must satisfy 0 < top_p_q16 <= 1.0");
    }

    let t_clamped = t_q16.max(T_MIN_Q16);

    let mut items: Vec<(u32, i64)> = Vec::with_capacity(k);
    for i in 0..k {
        let num = (logit_q16[i] as i128) << 16;
        let s = floor_div_i128(num, t_clamped as i128) as i64;
        items.push((token_id[i], s));
    }

    items.sort_by(|a, b| {
        let slog_a = a.1;
        let slog_b = b.1;
        if slog_a != slog_b {
            return slog_b.cmp(&slog_a);
        }
        a.0.cmp(&b.0)
    });

    let mut sid: Vec<u32> = Vec::with_capacity(k);
    let mut slog: Vec<i64> = Vec::with_capacity(k);
    for (tid, s) in items {
        sid.push(tid);
        slog.push(s);
    }

    let m = slog[0];

    let mut w: Vec<u64> = vec![0; k];
    for i in 0..top_k {
        let mut z = slog[i] - m;
        if z < Z_MIN_Q16 {
            z = Z_MIN_Q16;
        }

        let neg_z = -z;
        let mut n = (neg_z >> 16) as i64;
        if n < 0 {
            n = 0;
        }
        if n > 12 {
            n = 12;
        }

        let r = z + (n << 16);

        let p = exp_poly5_q16_16_to_q30(r);
        let wi = ((E_Q30[n as usize] as u128 * p as u128) >> 30) as u64;
        w[i] = wi;
    }

    let mut wk: u64 = 0;
    for i in 0..top_k {
        wk = wk.wrapping_add(w[i]);
    }

    let th = ((top_p_q16 as u128 * wk as u128) >> 16) as u64;

    let mut prefix: u64 = 0;
    let mut s: usize = 1;
    for i in 0..top_k {
        prefix = prefix.wrapping_add(w[i]);
        if prefix >= th {
            s = i + 1;
            break;
        }
    }

    let mut ws: u64 = 0;
    for i in 0..s {
        ws = ws.wrapping_add(w[i]);
    }

    let u = u_t;
    let r = (((u as u128) * (ws as u128)) >> 64) as u64;

    let mut prefix2: u64 = 0;
    let mut j: usize = 0;
    for i in 0..s {
        prefix2 = prefix2.wrapping_add(w[i]);
        if prefix2 > r {
            j = i;
            break;
        }
    }

    DecodeStepResult {
        y: sid[j],
        ws,
        r,
    }
}
