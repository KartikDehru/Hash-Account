#!/usr/bin/env bash
# Key rotation on the LOCAL chain (needs ETHREX_REPO and SIDECAR_DIR, after local_devnet.sh prepare):
# 1. register a new key tree as epoch 1 with a transaction signed by the epoch-0 key
# 2. pay with the epoch-1 key; show that an unregistered epoch (2) is refused
# Writes raw responses to results/local/rotation/ and results/local/rotation/summary.json.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
L="$ROOT/.local"
OUT="$ROOT/results/local/rotation"
RPC=http://127.0.0.1:8545
BUNDLER=http://127.0.0.1:14337/rpc/
export PATH="$HOME/.foundry/bin:$PATH"
cd "$ROOT"
rm -rf "$OUT" && mkdir -p "$OUT"
./scripts/local_devnet.sh down
./scripts/local_devnet.sh up
.venv/bin/python scripts/local_blocks.py 1 > /dev/null

ACCOUNT=$(jq -r .accountA "$L/accounts.json")
cli() { (cd "$ROOT/signer" && bun run src/cli.ts "$@"); }
relay_and_block() {
  curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"debug_bundler_sendBundleNow","params":[]}' $BUNDLER > /dev/null
  .venv/bin/python scripts/local_blocks.py 1
}

# New key trees for epoch 1 and epoch 2 (epoch 2 is never registered)
for e in 1 2; do
  [ -f "$L/key-a-e$e.json" ] || cli keygen --epoch $e --account "$ACCOUNT" --chain-id 9 --out "$L/key-a-e$e.json" > /dev/null
done

# 1. rotation, signed by the epoch-0 key
cli rotate --key "$L/key-a.json" --new-key "$L/key-a-e1.json" --rpc $RPC --bundler $BUNDLER --results-dir results/local/rotation > "$OUT/rotate-cli.json"
BLOCK_ROTATE=$(relay_and_block)
LAST=$(cast storage --rpc-url $RPC "$ACCOUNT" 0x8000000000000000000000000000000000000000000000000000000000000000)
SLOT1=$(cast storage --rpc-url $RPC "$ACCOUNT" 1)

# 2. payment with the epoch-1 key
cli send --key "$L/key-a-e1.json" --rpc $RPC --bundler $BUNDLER --to 0x000000000000000000000000000000000000bEEF \
  --value 1000000000000000 --results-dir results/local/rotation > "$OUT/send-epoch1-cli.json"
BLOCK_PAY=$(relay_and_block)

# 3. payment with an unregistered epoch-2 key (must be refused)
cli send --key "$L/key-a-e2.json" --rpc $RPC --bundler $BUNDLER --to 0x000000000000000000000000000000000000bEEF \
  --value 1000000000000000 --results-dir results/local/rotation > "$OUT/send-epoch2-cli.json" || true

"$ROOT/.venv/bin/python" - "$OUT" "$ACCOUNT" "$LAST" "$SLOT1" "$BLOCK_ROTATE" "$BLOCK_PAY" "$L" "$RPC" <<'PY'
import glob, json, sys, urllib.request
out, account, last, slot1, b_rot, b_pay, local, rpc = sys.argv[1:9]
def call(m, p):
    r = urllib.request.Request(rpc, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(), headers={"content-type": "application/json"})
    return json.load(urllib.request.urlopen(r)).get("result")
recs = {}
for f in glob.glob(f"{out}/*-20*.json"):
    d = json.load(open(f))
    recs[(d["kind"], d["epoch"])] = d
from Crypto.Hash import keccak
k1 = json.load(open(f"{local}/key-a-e1.json"))
expected = "0x" + keccak.new(digest_bits=256, data=bytes.fromhex(k1["seed"][2:]) + bytes.fromhex(k1["root"][2:])).hexdigest()
def receipt(d):
    h = (d.get("response") or {}).get("result")
    return (call("eth_getTransactionReceipt", [h]) or {}).get("status") if h else None
rot, pay, bad = recs.get(("rotate", 0)), recs.get(("send", 1)), recs.get(("send", 2))
summary = {
    "scope": "LOCAL ethrex eip8141-tracer + local sidecar + local block driver, not the public devnet",
    "account": account,
    "rotation": {"leafUsed": rot["leaf"], "sidecar": rot["response"], "block": json.loads(b_rot), "receiptStatus": receipt(rot),
                 "lastEpochAfter": int(last, 16), "slot1": slot1, "slot1Expected": expected, "slot1Matches": slot1.lower() == expected.lower()},
    "paymentEpoch1": {"leaf": pay["leaf"], "sidecar": pay["response"], "block": json.loads(b_pay), "receiptStatus": receipt(pay),
                      "verifyGas": int(pay["simulation"]["result"]["frames"][0]["gasUsed"], 16)},
    "paymentUnregisteredEpoch2": {"simulation": (bad or {}).get("simulation", {}).get("result", {}).get("executionError"),
                                  "sidecar": (bad or {}).get("response")},
}
json.dump(summary, open(f"{out}/summary.json", "w"), indent=1)
print(json.dumps(summary, indent=1))
PY
