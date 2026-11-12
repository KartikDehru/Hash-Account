#!/usr/bin/env bash
# The proposed rule fix, shown locally: a sidecar whose validation budget is configurable
# (patches/sidecar-configurable-verify-budget.patch) admits and relays Profile B, and the block
# includes it. Needs ETHREX_REPO and SIDECAR_DIR (sidecar with the patch applied and rebuilt):
#   (cd "$SIDECAR_DIR" && git apply /path/to/Lamp/patches/sidecar-configurable-verify-budget.patch && bun run build)
# Writes results/local/inclusion-xmss-patched-sidecar.json. LOCAL + PATCHED result.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
grep -q SKANDHA_MAX_VERIFY_GAS "$SIDECAR_DIR/packages/executor/src/services/UserOpValidation/utils/validationPrefix.ts" \
  || { echo "sidecar is not patched; apply patches/sidecar-configurable-verify-budget.patch and rebuild" >&2; exit 1; }
./scripts/local_devnet.sh down
# Second fix: the sidecar's precompile allow-list is empty by default, so validation code that
# calls a precompile (XMSS uses SHA-256 at 0x02) is refused as "un-deployed contract". EIP-8141
# allows precompiles. List the standard ones (0x01 to 0x11, P256VERIFY at 0x100).
PRE=$(python3 -c "print(','.join(['0x%040x' % i for i in range(1, 0x12)] + ['0x%040x' % 0x100]))")
SKANDHA_PRECOMPILES="$PRE" SKANDHA_MAX_VERIFY_GAS=1000000 MAX_VERIFY_GAS=1000000 ./scripts/local_devnet.sh up
.venv/bin/python scripts/local_blocks.py 1 > /dev/null
(cd signer && bun run src/inclusion.ts --local "$ROOT/.local" --mode xmss-sidecar)
./scripts/local_devnet.sh down
