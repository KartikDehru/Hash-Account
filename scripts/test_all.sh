#!/usr/bin/env bash
# Runs every check and regenerates every number in results/.
#   ./scripts/test_all.sh          quick: 1,000 differential cases
#   FULL=1 ./scripts/test_all.sh   full: 10,000 differential cases (about 6 minutes)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.foundry/bin:$PATH"
PY="$ROOT/.venv/bin/python"
cd "$ROOT"

echo "== generated account builds are up to date"
"$PY" scripts/gen_account.py --check

echo "== Python reference and simulator tests"
(cd reference && "$PY" -m pytest -q)
(cd simulator && "$PY" -m pytest -q tests)

echo "== Foundry tests (vectors, mutation, account, gas)"
(cd contracts && forge test --no-match-contract DifferentialTest -q)

echo "== Differential test, Python reference against Solidity"
if [ "${FULL:-0}" = "1" ]; then
  (cd contracts && FOUNDRY_PROFILE=diff forge test --match-contract DifferentialTest --fuzz-seed 0x4c414d50 2>&1 \
    | grep -E "PASS|FAIL|Suite result" \
    | { echo "# FOUNDRY_PROFILE=diff forge test --match-contract DifferentialTest --fuzz-seed 0x4c414d50 (100 runs x 100 cases = 10,000)"; cat; } \
    | tee "$ROOT/results/differential_10000.txt")
else
  (cd contracts && forge test --match-contract DifferentialTest -q)
fi

echo "== TypeScript signer: type check and tests"
(cd signer && bunx tsc --noEmit && bun test)

echo "== Gas report, gas model, frontier, attack view"
"$PY" scripts/gas_report.py --no-run > /dev/null
"$PY" scripts/verify_gas_model.py > /dev/null
"$PY" scripts/frontier.py
"$PY" scripts/attack_view.py > /dev/null
"$PY" scripts/demo_page.py
