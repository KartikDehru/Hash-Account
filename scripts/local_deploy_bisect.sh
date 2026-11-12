#!/usr/bin/env bash
# Finds the state gas a deploy frame needs to create the Profile A account (deploy + self_verify
# in one transaction), by bisecting the deploy frame's state limit on the local ethrex simulation.
# Writes results/local/deploy_state.json. LOCAL result.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/signer"
ok() {
  bun run src/probe.ts deploy --local "$ROOT/.local" --deploy-state "$1" 2>/dev/null \
    | python3 -c "import sys,json;r=json.load(sys.stdin)['simulation']['result'];f=r.get('frames') or [];print(1 if f and f[0]['succeeded'] else 0)"
}
lo=500000; hi=6000000
[ "$(ok $hi)" = 1 ] || { echo "deploy fails even at $hi" >&2; exit 1; }
[ "$(ok $lo)" = 0 ] || { echo "deploy fits in $lo" >&2; }
while [ $((hi - lo)) -gt 1000 ]; do
  mid=$(((lo + hi) / 2))
  if [ "$(ok $mid)" = 1 ]; then hi=$mid; else lo=$mid; fi
done
ok $hi > /dev/null   # leave probe-deploy.json at a succeeding deploy for the record
python3 - "$lo" "$hi" "$ROOT" <<'PY'
import json, sys
lo, hi, root = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
acc = json.load(open(f"{root}/.local/accounts.json"))
alloc = json.load(open(f"{root}/.local/alloc.json"))
code_bytes = (len(alloc[acc["accountA"]]["code"]) - 2) // 2
rules = json.load(open(f"{root}/simulator/rules.json"))
out = {"scope": "LOCAL ethrex eip8141-tracer simulation", "deployStateGasFails": lo, "deployStateGasSucceeds": hi,
       "accountRuntimeBytes": code_bytes, "costPerStateByte": 1530, "runtimeBytesTimesCpsb": code_bytes * 1530,
       "publicMaxVerifyStateGas": rules["MAX_VERIFY_STATE_GAS"]["value"],
       "verdict": "deploy + self_verify cannot pass the public state-gas cap" if lo > rules["MAX_VERIFY_STATE_GAS"]["value"] else "fits"}
json.dump(out, open(f"{root}/results/local/deploy_state.json", "w"), indent=1)
print(json.dumps(out, indent=1))
PY
