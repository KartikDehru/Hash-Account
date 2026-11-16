#!/usr/bin/env bash
# Local EIP-8141 chain (ethrex eip8141-tracer) and alt-mempool sidecar, for real-opcode runs
# when the public devnet is out of reach. Results from it are LOCAL, not public-devnet results.
#
#   ETHREX_REPO=/path/to/forshtat-ethrex SIDECAR_DIR=/path/to/mempool-workshop-sidecar \
#     ./scripts/local_devnet.sh prepare|up|down|status
#
# prepare: test keys (chain id 9), account runtime code via anvil, genesis in .local/
# up:      ethrex (no block production: Hegota dev blocks are not supported by its dev
#          producer at 9aa3645) on :8545 and the sidecar on :14337 (manual bundling)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$ROOT/.local/foundry-1.5.1:$HOME/.foundry/bin:$PATH"
L="$ROOT/.local"
ETHREX_REPO="${ETHREX_REPO:?set ETHREX_REPO to a forshtat/ethrex eip8141-tracer checkout}"
ETHREX_BIN="${ETHREX_BIN:-$ETHREX_REPO/target/release/ethrex}"
SIDECAR_DIR="${SIDECAR_DIR:-}"
MAX_VERIFY_GAS="${MAX_VERIFY_GAS:-100000}"
mkdir -p "$L"
# macOS has no setsid. nohup keeps the node alive after this script exits.
if command -v setsid >/dev/null 2>&1; then DETACH=(setsid); else DETACH=(nohup); fi
if [ ! -s "$L/jwt.hex" ]; then openssl rand -hex 32 > "$L/jwt.hex"; fi

cli() { (cd "$ROOT/signer" && bun run src/cli.ts "$@"); }

case "${1:-}" in
  prepare)
    (cd "$ROOT/contracts" && forge build -q)
    [ -f "$L/key-a.json" ] || cli keygen --out "$L/key-a.json" --chain-id 9 > /dev/null
    [ -f "$L/key-b.json" ] || cli keygen --profile b --out "$L/key-b.json" > /dev/null
    [ -f "$L/key-c.json" ] || cli keygen --out "$L/key-c.json" --chain-id 9 > /dev/null   # deploy-in-frame probe only
    [ -f "$L/key-l.json" ] || cli keygen --out "$L/key-l.json" --chain-id 9 --nonce-mode legacy > /dev/null
    A=$(cli address --key "$L/key-a.json")
    B=$(cli address --profile b --key "$L/key-b.json")
    anvil --port 8599 --silent & APID=$!
    trap 'kill $APID 2>/dev/null || true' EXIT
    until cast chain-id --rpc-url http://127.0.0.1:8599 >/dev/null 2>&1; do sleep 0.2; done
    K=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80  # anvil's public test key 0
    send() { cast send --rpc-url http://127.0.0.1:8599 --private-key $K "$1" "$2" > /dev/null; }
    send "$(jq -r .verifier.deployTo <<<"$B")" "$(jq -r .verifier.deployData <<<"$B")"
    send "$(jq -r .deployTo <<<"$A")" "$(jq -r .deployData <<<"$A")"
    send "$(jq -r .deployTo <<<"$B")" "$(jq -r .deployData <<<"$B")"
    code() { cast code --rpc-url http://127.0.0.1:8599 "$1"; }
    slot0() { cast storage --rpc-url http://127.0.0.1:8599 "$1" 0; }   # Profile A key commitment (epoch 0)
    VA=$(jq -r .address <<<"$A"); VB=$(jq -r .address <<<"$B"); VV=$(jq -r .verifier.address <<<"$B")
    VC=$(cli address --key "$L/key-c.json" | jq -r .address)   # funded, no code: deployed inside a frame
    LA=$(cli address --key "$L/key-l.json")
    send "$(jq -r .deployTo <<<"$LA")" "$(jq -r .deployData <<<"$LA")"
    VL=$(jq -r .address <<<"$LA")
    jq -n --arg a "$VA" --arg ca "$(code $VA)" --arg b "$VB" --arg cb "$(code $VB)" --arg v "$VV" --arg cv "$(code $VV)" --arg c "$VC" \
      --arg sa "$(slot0 $VA)" \
      '{($a): {code: $ca, balance: "0x56bc75e2d63100000", storage: {"0x0000000000000000000000000000000000000000000000000000000000000000": $sa}}, ($b): {code: $cb, balance: "0x56bc75e2d63100000"}, ($v): {code: $cv, balance: "0x0"},
        ($c): {code: "0x", balance: "0x56bc75e2d63100000"},
        "0x000000000000000000000000000000000000c0de": {code: "0x60035f5faa", balance: "0x56bc75e2d63100000"},
        "0x000000000000000000000000000000000000b4d0": {code: "0x425060035f5faa", balance: "0x56bc75e2d63100000"}}' \
      > "$L/alloc.json"
    # Legacy-mode account, plus 48 copies of its code with nonces 101..148 for gas calibration
    # (each copy is used once, at its own nonce, so every leaf is still signed only once).
    CL=$(code $VL)
    SL=$(slot0 $VL)
    python3 - "$L/alloc.json" "$VL" "$CL" "$SL" <<'PY'
import json, sys
path, addr, code, slot = sys.argv[1:5]
a = json.load(open(path))
a[addr] = {"code": code, "balance": "0x56bc75e2d63100000", "storage": {"0x0000000000000000000000000000000000000000000000000000000000000000": slot}}
for k in range(48):
    a["0x%040x" % (0xca1b0000 + k)] = {"code": code, "balance": "0x56bc75e2d63100000", "nonce": hex(k + 101), "storage": {"0x0000000000000000000000000000000000000000000000000000000000000000": slot}}
json.dump(a, open(path, "w"), indent=1)
PY
    python3 "$ROOT/scripts/local_genesis.py" "$ETHREX_REPO" "$L/alloc.json" "$L/genesis.json"
    jq -n --arg a "$VA" --arg b "$VB" --arg v "$VV" --arg c "$VC" --arg l "$VL" '{accountA: $a, accountALegacy: $l, accountB: $b, xmssVerifier: $v, deployProbe: $c, chainId: 9}' > "$L/accounts.json"
    cat "$L/accounts.json"
    ;;
  up)
    rm -rf "$L/ethrex-data"
    "${DETACH[@]}" "$ETHREX_BIN" --network "$L/genesis.json" --datadir "$L/ethrex-data" \
      --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3,ethrex,debug \
      --authrpc.port 8551 --authrpc.jwtsecret "$L/jwt.hex" --syncmode full --p2p.disabled --mempool.max-verify-gas "$MAX_VERIFY_GAS" \
      < /dev/null > "$L/ethrex.log" 2>&1 & echo $! > "$L/ethrex.pid"
    until curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:8545 | grep -q result; do
      kill -0 "$(cat "$L/ethrex.pid")" 2>/dev/null || { tail -20 "$L/ethrex.log"; exit 1; }
      sleep 0.5
    done
    echo "ethrex up (max verify gas $MAX_VERIFY_GAS)"
    if [ -n "$SIDECAR_DIR" ]; then
      if curl -s --max-time 2 http://127.0.0.1:14337/rpc/ > /dev/null; then echo "port 14337 is busy: run down first" >&2; exit 1; fi
      jq -n '{entryPoints: ["0x00000000000000000000000000000000000000aa"], canonicalEntryPoint: "0x00000000000000000000000000000000000000aa",
              standardMempoolId: "QmcFZKUX9qoo3StwVycJTAhwdiqbEjcwNvQVK246p3z1rk",
              supportedMempools: [{mempoolId: "QmcFZKUX9qoo3StwVycJTAhwdiqbEjcwNvQVK246p3z1rk", entryPoint: "0x00000000000000000000000000000000000000aa"}],
              relayers: [$k], rpcEndpoint: "http://127.0.0.1:8545"}' \
        --arg k "$(head -1 "$ETHREX_REPO/fixtures/keys/private_keys_l1.txt")" > "$L/sidecar.json"
      rm -rf "$L/skandha-db"
      pushd "$SIDECAR_DIR" > /dev/null
      "${DETACH[@]}" ./skandha standalone --configFile "$L/sidecar.json" --dataDir "$L/skandha-db" \
        --executor.bundlingMode manual < /dev/null > "$L/sidecar.log" 2>&1 &
      echo $! > "$L/sidecar.pid"
      popd > /dev/null
      until curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:14337/rpc/ | grep -q result; do
        kill -0 "$(cat "$L/sidecar.pid")" 2>/dev/null || { tail -30 "$L/sidecar.log"; exit 1; }
        sleep 1
      done
      echo "sidecar up on :14337"
    fi
    ;;
  down)
    for p in sidecar ethrex; do [ -f "$L/$p.pid" ] && kill "$(cat "$L/$p.pid")" 2>/dev/null || true; rm -f "$L/$p.pid"; done
    # The sidecar runs as bash -> bun; match both by their config path so nothing survives.
    pkill -f -- "--configFile $L/sidecar.json" 2>/dev/null || true
    pkill -f -- "--network $L/genesis.json" 2>/dev/null || true
    sleep 1
    ;;
  status)
    curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:8545; echo
    ;;
  *) echo "usage: $0 prepare|up|down|status" >&2; exit 2 ;;
esac
