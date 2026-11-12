#!/usr/bin/env bash
# Runs every local experiment against a chain started by local_devnet.sh up.
# Writes raw responses to results/local/ and a summary to results/local/summary.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
L="$ROOT/.local"
RPC=http://127.0.0.1:8545
BUNDLER=http://127.0.0.1:14337/rpc/
mkdir -p "$ROOT/results/local"
rm -f "$ROOT/results/local/"*.json
cd "$ROOT/signer"
run() { echo "== $1"; shift; "$@" || echo "(command failed; see output above)"; }
run "calibrate keyed" bun run src/probe.ts calibrate --mode keyed --n 48 --rpc $RPC --local "$L"
run "calibrate legacy" bun run src/probe.ts calibrate --mode legacy --n 48 --rpc $RPC --local "$L"
"$ROOT/.venv/bin/python" "$ROOT/scripts/verify_gas_model.py"
run "Profile A payment (keyed nonce)" bun run src/cli.ts send --key "$L/key-a.json" --rpc $RPC --bundler $BUNDLER \
  --to 0x000000000000000000000000000000000000dEaD --value 1000000000000000 --results-dir results/local
run "Profile A payment (legacy nonce)" bun run src/cli.ts send --key "$L/key-l.json" --rpc $RPC --bundler $BUNDLER \
  --to 0x000000000000000000000000000000000000dEaD --value 1000000000000000 --results-dir results/local
run "Profile B payment (over the public cap by design)" bun run src/cli.ts send --profile b --key "$L/key-b.json" \
  --chain-id 9 --rpc $RPC --bundler $BUNDLER --to 0x000000000000000000000000000000000000dEaD --value 1000000000000000 \
  --allow-over-cap --results-dir results/local
for p in control control-legacy banned bigsig deploy; do run "probe $p" bun run src/probe.ts $p --rpc $RPC --bundler $BUNDLER --local "$L"; done
run "deploy state-gas bisection" "$ROOT/scripts/local_deploy_bisect.sh"
"$ROOT/.venv/bin/python" "$ROOT/scripts/local_report.py"
