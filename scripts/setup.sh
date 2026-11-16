#!/usr/bin/env bash
# Installs the toolchain for HashAccount. Foundry goes into .local/ inside the repository so an
# existing ~/.foundry install is left alone.
# Foundry and solc come from GitHub release assets, because foundry.paradigm.xyz and
# binaries.soliditylang.org may be blocked in some sandboxes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FOUNDRY_VERSION=v1.5.1   # pinned: gas figures in results/ were measured with this version
FOUNDRY_BIN="$ROOT/.local/foundry-${FOUNDRY_VERSION#v}"
SOLC="$HOME/.svm/0.8.37/solc-0.8.37"  # where forge looks for solc 0.8.37

PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then echo "Python 3.10 or newer is required (python3 here is $(python3 --version 2>&1))"; exit 1; fi

if [ ! -x "$FOUNDRY_BIN/forge" ] || ! "$FOUNDRY_BIN/forge" --version | grep -q "${FOUNDRY_VERSION#v}"; then
  mkdir -p "$FOUNDRY_BIN"
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  plat=linux_amd64 ;;
    Linux-aarch64) plat=linux_arm64 ;;
    Darwin-arm64)  plat=darwin_arm64 ;;
    Darwin-x86_64) plat=darwin_amd64 ;;
    *) echo "unsupported platform"; exit 1 ;;
  esac
  curl -sSL "https://github.com/foundry-rs/foundry/releases/download/$FOUNDRY_VERSION/foundry_${FOUNDRY_VERSION}_${plat}.tar.gz" \
    | tar xz -C "$FOUNDRY_BIN"
fi
if [ ! -x "$SOLC" ]; then
  mkdir -p "$(dirname "$SOLC")"
  case "$(uname -s)" in
    Linux)  asset=solc-static-linux ;;
    Darwin) asset=solc-macos ;;
    *) echo "unsupported OS"; exit 1 ;;
  esac
  curl -sSL -o "$SOLC" "https://github.com/ethereum/solidity/releases/download/v0.8.37/$asset"
  chmod +x "$SOLC"
fi
if [ ! -d "$ROOT/contracts/lib/forge-std/src" ]; then
  git clone -q --depth 1 --branch v1.9.7 https://github.com/foundry-rs/forge-std "$ROOT/contracts/lib/forge-std"
fi
if [ -x "$ROOT/.venv/bin/python" ] && ! "$ROOT/.venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "replacing .venv: it uses Python older than 3.10"; rm -rf "$ROOT/.venv"
fi
if [ ! -d "$ROOT/.venv" ]; then
  "$PY" -m venv "$ROOT/.venv"
fi
"$ROOT/.venv/bin/pip" -q install -r "$ROOT/reference/requirements.txt"
if command -v bun >/dev/null; then (cd "$ROOT/signer" && bun install --frozen-lockfile); else echo "install Bun (https://bun.sh) for the signer"; fi
echo "setup done. The scripts use $FOUNDRY_BIN; to run forge by hand: export PATH=\"$FOUNDRY_BIN:\$PATH\""
