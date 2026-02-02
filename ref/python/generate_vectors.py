from __future__ import annotations

import argparse
import json
import os
import random
import sys
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from decoding_ref import Q16, decode_step


def _q16(x: float) -> int:
    return int(x * Q16)


def _make_case(rng: random.Random, *, K: int, top_k: int, top_p_q16: int, T_q16: int, mode: str) -> Dict:
    token_ids = rng.sample(range(1, 10_000_000), K)

    logits: List[int] = []
    for _ in range(K):
        v = rng.randint(-(2 << 16), (2 << 16))
        logits.append(int(v))

    if mode == "ties":
        if K >= 4:
            logits[0] = logits[1]
            logits[2] = logits[3]
    elif mode == "zclip":
        mx = max(logits)
        for i in range(min(3, K)):
            logits[i] = mx
        for i in range(3, K):
            logits[i] = mx - (13 << 16)

    U_choices = [0, 1, (1 << 63), (1 << 64) - 1, rng.getrandbits(64)]
    U_t = int(rng.choice(U_choices))

    res = decode_step(
        K=K,
        top_k=top_k,
        top_p_q16=top_p_q16,
        T_q16=T_q16,
        token_id=token_ids,
        logit_q16=logits,
        U_t=U_t,
    )

    return {
        "K": K,
        "top_k": top_k,
        "top_p_q16": int(top_p_q16),
        "T_q16": int(T_q16),
        "token_id": [int(x) for x in token_ids],
        "logit_q16": [int(x) for x in logits],
        "U_t": int(U_t),
        "expected": {"y": int(res.y), "Ws": int(res.Ws), "R": int(res.R)},
    }


def _write_jsonl(path: str, rows: List[Dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":"), sort_keys=True))
            f.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--golden", type=int, default=50)
    ap.add_argument("--random", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rng = random.Random(args.seed)

    golden_modes = ["ties", "zclip", "plain"]
    Ks = [16, 32, 64]
    top_ps = [_q16(0.5), _q16(0.9), _q16(0.99), _q16(1.0)]
    Ts = [0, 1, _q16(0.25), _q16(1.0), _q16(2.0), _q16(10.0)]

    golden: List[Dict] = []

    K0 = 16
    token_ids0 = list(range(1, K0 + 1))
    logits0 = [0, 0, 0, 0] + [-(12 << 16)] * (K0 - 4)
    base_row = {
        "tag": "policy_sensitive_v1",
        "K": K0,
        "top_k": 4,
        "top_p_q16": _q16(0.75),
        "T_q16": _q16(1.0),
        "token_id": token_ids0,
        "logit_q16": logits0,
        "U_t": (1 << 64) - 1,
    }
    res0 = decode_step(
        K=base_row["K"],
        top_k=base_row["top_k"],
        top_p_q16=base_row["top_p_q16"],
        T_q16=base_row["T_q16"],
        token_id=base_row["token_id"],
        logit_q16=base_row["logit_q16"],
        U_t=base_row["U_t"],
    )
    base_row["expected"] = {"y": int(res0.y), "Ws": int(res0.Ws), "R": int(res0.R)}
    golden.append(base_row)

    while len(golden) < args.golden:
        K = int(rng.choice(Ks))
        top_k = int(rng.choice([1, K, max(1, K // 2)]))
        top_p_q16 = int(rng.choice(top_ps))
        T_q16 = int(rng.choice(Ts))
        mode = str(rng.choice(golden_modes))

        golden.append(
            _make_case(
                rng,
                K=K,
                top_k=top_k,
                top_p_q16=top_p_q16,
                T_q16=T_q16,
                mode=mode,
            )
        )

    randomized: List[Dict] = []
    for _ in range(args.random):
        K = int(rng.choice(Ks))
        top_k = int(rng.randint(1, K))
        top_p_q16 = int(rng.randint(1, Q16))
        T_q16 = int(rng.randint(0, _q16(10.0)))
        randomized.append(
            _make_case(
                rng,
                K=K,
                top_k=top_k,
                top_p_q16=top_p_q16,
                T_q16=T_q16,
                mode="plain",
            )
        )

    _write_jsonl(os.path.join(args.out_dir, "golden.jsonl"), golden)
    _write_jsonl(os.path.join(args.out_dir, "random.jsonl"), randomized)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
