#!/usr/bin/env bash
# Called by Foundry tests through vm.ffi. Prints packed random cases as hex.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/reference"
exec "$ROOT/.venv/bin/python" -m lamport.cli batch "$@"
