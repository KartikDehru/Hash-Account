#!/usr/bin/env bash
# Inclusion experiments on the LOCAL chain (needs ETHREX_REPO and SIDECAR_DIR, after local_devnet.sh prepare).
# 1. keyed and legacy Profile A payments through the sidecar, included by the local block driver,
#    then reuse attempts (results/local/inclusion-{keyed,legacy}.json)
# 2. Profile B sent to a node with --mempool.max-verify-gas 1,000,000 and included
#    (results/local/inclusion-xmss-raised-node-budget.json), and refused by a node with the default
#    budget (results/local/node-xmss-default-budget.json)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
L="$ROOT/.local"
cd "$ROOT"
./scripts/local_devnet.sh down
./scripts/local_devnet.sh up
.venv/bin/python scripts/local_blocks.py 1 > /dev/null
(cd signer && bun run src/inclusion.ts --local "$L" --mode keyed)
(cd signer && bun run src/inclusion.ts --local "$L" --mode legacy)
./scripts/local_devnet.sh down
MAX_VERIFY_GAS=1000000 SIDECAR_DIR= ./scripts/local_devnet.sh up
.venv/bin/python scripts/local_blocks.py 1 > /dev/null
(cd signer && bun run src/inclusion.ts --local "$L" --mode xmss)
cp results/local/inclusion-xmss-raised-node-budget.json "$L/xmss-raised.json"
./scripts/local_devnet.sh down
SIDECAR_DIR= ./scripts/local_devnet.sh up
(cd signer && bun run src/inclusion.ts --local "$L" --mode xmss) || true
mv results/local/inclusion-xmss-raised-node-budget.json results/local/node-xmss-default-budget.json
cp "$L/xmss-raised.json" results/local/inclusion-xmss-raised-node-budget.json
python3 - "$ROOT/results/local/node-xmss-default-budget.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["scope"] = "LOCAL ethrex with the default --mempool.max-verify-gas (100,000), Profile B sent to the node directly (no sidecar)."
json.dump(d, open(sys.argv[1], "w"), indent=1)
PY
./scripts/local_devnet.sh down
SIDECAR_DIR="${SIDECAR_DIR:-}" ./scripts/local_devnet.sh up
.venv/bin/python scripts/local_report.py > /dev/null
