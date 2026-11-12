# Devnet runbook

**No devnet transaction has been sent from this repository yet.** Nothing in `results/` is a public admission until a raw response is saved under `results/devnet/`. EIP-8141 is not on mainnet. The signer follows ethrex `eip8141-tracer` at 9aa3645, which disagrees with the current EIP text (`docs/SPEC_FACTS.md`), so a newer frames devnet can reject these transactions until the encoding is updated.

Use test keys only. Devnet faucet funds are worthless and a devnet can reset.

## 0. Prerequisites
From this repository:
```sh
./scripts/setup.sh                 # Foundry, solc 0.8.37, Python venv
export PATH="$HOME/.foundry/bin:$PATH"
(cd signer && bun install)
./scripts/test_all.sh              # everything must pass before touching the devnet
```

## 1. Endpoints
Public devnet (from the sidecar README, checked 2026-10-24; confirm the endpoints are still current before sending):
```sh
export RPC=https://altmempool.forshtat.com          # confirm this is the ethrex RPC, not only the bundler
export BUNDLER=https://altmempool.forshtat.com/rpc/
export EXPLORER=https://altmempoolexplorer.forshtat.com
cast chain-id --rpc-url $RPC                         # expect 1337
curl -s $BUNDLER -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
```
If `cast chain-id` fails, read `deploy/devnet/devnet-readme.md` in github.com/forshtat/mempool-workshop-sidecar for the RPC path, and put the working URLs in the variables above.

## 2. Check the devnet build matches what the code assumes
```sh
cast storage 0x0000000000000000000000000000000000008250 0x0 --rpc-url $RPC   # NONCE_MANAGER exists (any value)
cast code 0x4e59b44847b379578588920ca78fbf26c0b4956c --rpc-url $RPC        # deterministic deployment proxy: must not be 0x
```

## 3. Make a test key and the account address
```sh
cd signer
bun run src/cli.ts keygen --out keys/test-key.json --chain-id 1337 --nonce-mode legacy   # or keyed (default); see DECISIONS
bun run src/cli.ts address --key keys/test-key.json     # prints address, deployTo, deployData
```

## 4. Fund a throwaway EOA from the faucet, then deploy and fund the account
The account has no ECDSA key. A throwaway EOA only pays for the deployment transaction; it has no authority over the account.
```sh
export DEPLOYER_KEY=0x...            # fresh throwaway key, funded from the devnet faucet
ADDR=$(bun run src/cli.ts address --key keys/test-key.json | jq -r .address)
DATA=$(bun run src/cli.ts address --key keys/test-key.json | jq -r .deployData)
cast send 0x4e59b44847b379578588920ca78fbf26c0b4956c $DATA --private-key $DEPLOYER_KEY --rpc-url $RPC
cast code $ADDR --rpc-url $RPC | head -c 20          # must not be 0x
cast send $ADDR --value 0.05ether --private-key $DEPLOYER_KEY --rpc-url $RPC
```
(Deploying inside the frame transaction, shape `deploy + self_verify`, is possible but its deploy limit counts toward the 100,000 cap; we deploy separately first. See docs/DECISIONS.md.)

## 5. Dry run, then send the first Profile A transaction
```sh
bun run src/cli.ts send --key keys/test-key.json --rpc $RPC --bundler $BUNDLER \
  --to 0x000000000000000000000000000000000000dEaD --value 1000000000000000 --dry-run
bun run src/cli.ts send --key keys/test-key.json --rpc $RPC --bundler $BUNDLER \
  --to 0x000000000000000000000000000000000000dEaD --value 1000000000000000
```
The second command signs with the lowest leaf whose NONCE_MANAGER slot is zero, saves `results/devnet/send-<time>.json` (estimate and send response, unedited) and prints the transaction hash or the refusal.

## 6. Check spent-once (test 7 in docs/TESTS.md; already shown on the local chain, results/local/inclusion-*.json)
```sh
cast storage 0x0000000000000000000000000000000000008250 \
  $(cast keccak $(cast concat-hex $(cast to-uint256 $ADDR) $(cast to-uint256 0x4c414d5000000000000000000000000000000000000000000000000000000000))) --rpc-url $RPC
# expect 0x...01 after the first transaction is included (leaf 0 used)
```
Then send again: the signer must pick leaf 1, not leaf 0.

## 7. Profile B (XMSS, alt mempool)
```sh
bun run src/cli.ts keygen --profile b --out keys/xmss-key.json          # about a minute
B=$(bun run src/cli.ts address --profile b --key keys/xmss-key.json)
cast send $(jq -r .verifier.deployTo <<<"$B") $(jq -r .verifier.deployData <<<"$B") --private-key $DEPLOYER_KEY --rpc-url $RPC
cast send $(jq -r .deployTo <<<"$B") $(jq -r .deployData <<<"$B") --private-key $DEPLOYER_KEY --rpc-url $RPC
cast send $(jq -r .address <<<"$B") --value 0.05ether --private-key $DEPLOYER_KEY --rpc-url $RPC
bun run src/cli.ts send --profile b --key keys/xmss-key.json --chain-id 1337 --rpc $RPC --bundler $BUNDLER \
  --to 0x000000000000000000000000000000000000dEaD --value 1000000000000000 --allow-over-cap
```
Expected from the code we read (sidecar fcb4885): refused with rule "structure" (MAX_VERIFY_GAS 100,000). If the devnet admits it, the devnet runs a different setting: paste the response, it answers OPEN_QUESTIONS Q3.

## 8. Local chain (no public devnet needed)
```sh
git clone --branch eip8141-tracer https://github.com/forshtat/ethrex ../ethrex
(cd ../ethrex && cargo build --release -p ethrex --bin ethrex)          # 30 to 60 minutes
git clone https://github.com/forshtat/mempool-workshop-sidecar ../sidecar
(cd ../sidecar && bun install && bun run build)
export ETHREX_REPO=$PWD/../ethrex SIDECAR_DIR=$PWD/../sidecar
./scripts/local_devnet.sh prepare && ./scripts/local_devnet.sh up
./scripts/local_experiments.sh      # writes results/local/*.json
./scripts/local_inclusion.sh        # blocks via the Engine API, inclusion and reuse attempts
(cd ../sidecar && git apply ../Lamp/patches/sidecar-configurable-verify-budget.patch && bun run build)
./scripts/local_alt_budget.sh       # Profile B through the patched sidecar (docs/RULE_FINDINGS.md)
./scripts/local_devnet.sh down
```
Local results show real EIP-8141 execution and the sidecar's verdicts; they are not public-devnet admissions.

## What to paste back
1. Output of steps 1 and 2 (chain id, NONCE_MANAGER and proxy code present).
2. The account address from step 3 and the deployment transaction hash from step 4.
3. The full JSON printed by step 5 (both `estimate` and `response`), and the file under `results/devnet/`.
4. The explorer link for the transaction (or the admission report with the rule that refused it).
5. The storage value from step 6.

If any step fails, paste the error unedited. I will not report an admission result I have not seen.
