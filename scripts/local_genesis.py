#!/usr/bin/env python3
"""Build a local EIP-8141 genesis: ethrex's Hegota fixture plus Lamport accounts.

Usage: local_genesis.py <ethrex-repo> <alloc.json> <out-genesis.json>
alloc.json maps address -> {"code": "0x..", "balance": "0x..", "storage"?: {...}, "nonce"?: "0x.."}
(runtime code and storage read from anvil).
Adds the EIP-8250 NONCE_MANAGER stub (0x...8250, code 0x60006000fd) if missing.
Local test chain only: these accounts are placed in genesis because the local node does not
produce blocks; on a devnet they are deployed by a transaction (docs/DEVNET_RUNBOOK.md).
"""
import json
import sys

repo, alloc_path, out = sys.argv[1:4]
with open(f"{repo}/fixtures/genesis/l1-hegota.json") as f:
    g = json.load(f)
with open(alloc_path) as f:
    extra = json.load(f)
nm = "0x0000000000000000000000000000000000008250"
if not any(k.lower() == nm for k in g["alloc"]):
    g["alloc"][nm] = {"code": "0x60006000fd", "storage": {}, "balance": "0x0", "nonce": "0x1"}
for addr, acct in extra.items():
    has_code = acct["code"] not in ("", "0x")
    nonce = acct.get("nonce", "0x1" if has_code else "0x0")
    g["alloc"][addr.lower()] = {"code": acct["code"], "storage": acct.get("storage", {}), "balance": acct["balance"], "nonce": nonce}
with open(out, "w") as f:
    json.dump(g, f, indent=1)
print(f"genesis with {len(g['alloc'])} accounts, chain id {g['config']['chainId']}")
