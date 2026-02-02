# Purechain (EVM testnet) notes

This repo treats **Purechain verification as a paper requirement** (see `TESTING.md`).

## What Purechain is (as observed)

From `web3_clientVersion` on the provided RPC (`http://3.34.161.207:8548`):
- Execution client: `Geth/PureChain-Validator-Hub/v1.13.14-stable-2bd6bd01/...`
- `rpc_modules` includes `clique`, indicating a **Clique PoA**-style chain.

Operationally this means (for our verifier tooling):
- **No EIP-1559 tx support** (or it is disabled): we send **legacy** transactions (`--legacy`).
- **Gas price is effectively 0**: we send with `--gas-price 0` (and priority fee 0).
- The node appears **pre-Shanghai** (rejects `PUSH0`), so Solidity compilation must target an older EVM:
  - We compile verifier contracts with `evm_version = 'paris'` in Foundry.

These constraints are enforced by:
- `eval/chain/verify_purechain_wrapped.py`
- `eval/chain/verify_purechain_groth16.py`
- The shared verifier logic in `eval/chain/verify_anvil.py` / `eval/chain/verify_groth16_anvil.py`

## Why `http://purechainnode:8548` was unreachable

In this environment, `purechainnode` is not a resolvable hostname (DNS), so the TCP connection never
gets attempted. The public IP-based RPC works.

## External “what is Purechain” references

We did not find an authoritative chain spec/site during quick web search. The only public “docs”
we found are SDK/package pages claiming:
- chainId `900520900520`
- gas price 0 (“free”)

See: PyPI `purechainlib` project page.

