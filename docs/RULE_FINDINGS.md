# Rule findings and proposed fixes

Found while building HashAccount. Each finding names the code or text it comes from and the result file that shows it. "LOCAL" results come from our own ethrex `eip8141-tracer` (9aa3645) and sidecar (fcb4885) runs, not the public devnet. Re-check against the current builds before relying on them.

## 1. The alt-mempool sidecar applies the public 100,000 budget to every transaction
- **Where:** forshtat/mempool-workshop-sidecar @fcb4885, `packages/executor/src/services/UserOpValidation/utils/validationPrefix.ts`: `MAX_VERIFY_GAS = BigInt(100_000)` is a constant used by `validateStructuralRules` (explorer rule "structure"). It does not depend on staking or reputation.
- **Effect:** a transaction that needs more validation gas, such as a post-quantum signature check, is refused by the alternative mempool for the same reason as the public mempool. The alternative mempool is the path described for validation above 100,000 gas. The sidecar we read applies 100,000 to every transaction.
- **Evidence (LOCAL):** Profile B (XMSS, VERIFY 690,937 to 812,757 gas on the 16 Nov 2026 runs) is refused with "validation prefix execution gas sum ... exceeds MAX_VERIFY_GAS 100000" (`results/local/send-b-*.json`).
- **Proposed fix:** make the budget a setting of the alternative mempool, keeping 100,000 as the default. Our 26-line patch: `patches/sidecar-configurable-verify-budget.patch` (`SKANDHA_MAX_VERIFY_GAS`; values below 100,000 are rejected). A fuller fix would tie a larger budget to stake, in the spirit of ERC-7562.
- **Evidence the fix works (LOCAL + PATCHED):** with the patch and fix 2 below, the sidecar accepts Profile B, relays it, and it is included (status 1, its nonce key consumed): `results/local/inclusion-xmss-patched-sidecar.json`.

## 2. The sidecar's precompile allow-list is empty by default
- **Where:** same commit, `packages/executor/src/config.ts` (`precompiles: []` default, setting `SKANDHA_PRECOMPILES`) and `validators/frameTx.ts` (rule "code access"): any address with code size at most 2 that is not listed is treated as an "un-deployed contract".
- **Effect:** validation code that calls a precompile is refused. EIP-8141's trace rules allow calls to precompiles ("an address that is neither an existing contract nor a precompile"). Signature schemes need precompiles: XMSS uses SHA-256 (0x02); P-256 and BLS checks use others.
- **Evidence (LOCAL):** with only fix 1 applied, Profile B is refused with "payer accesses un-deployed contract address 0x0000000000000000000000000000000000000002 with opcode STATICCALL" (seen during the run of `scripts/local_alt_budget.sh` before the setting was added).
- **Proposed fix:** default the list to the precompiles active in the fork (0x01 to 0x11 and 0x100 on this build), or ask the node. Our local run sets `SKANDHA_PRECOMPILES` (see `scripts/local_alt_budget.sh`).

## 3. The keyed-nonce charge counts against the validation budget
- **Where:** EIP-8250 (`KEYED_NONCE_ACCESS_COST = COLD_STORAGE_ACCESS + STORAGE_WRITE` per key) as implemented by ethrex: the charge lands in the execution gas of the frame that approves payment, which is a VERIFY frame.
- **Effect:** each keyed transaction loses 20,000 of the 100,000 public budget to protocol bookkeeping, which the account cannot avoid or control. Single-use keys (nullifiers, one-time signature leaves) are the use case EIP-8250 itself names.
- **Evidence (LOCAL):** the same one-line account uses 107 gas in VERIFY with the legacy nonce and 20,107 with a keyed nonce (`results/local/probe-control*.json`). HashAccount's keyed VERIFY frame peaks at 77,396 against 57,356 in legacy mode (`results/local/calibration_*.json`, 16 Nov 2026).
- **Proposed fix:** count the keyed-nonce access cost as intrinsic cost, like the signature verification cost, and leave it out of the sum checked against MAX_VERIFY_GAS (it is fixed and known before simulation). Alternatively raise the budget by `len(nonce_keys) * KEYED_NONCE_ACCESS_COST`.

## 4. `deploy + self_verify` cannot carry a realistic account under the state-gas cap
- **Where:** EIP-8141 public-mempool rule 6 (`MAX_VERIFY_STATE_GAS = 500,000`) with EIP-8037 state pricing (1,530 gas per state byte on this build).
- **Effect:** code deposit alone costs 1,530 per byte, so a deploy frame can install at most about 326 bytes of code within the cap, before any other state. HashAccount is 1,190 bytes and needs about 1.92M state gas (`results/local/deploy_state.json`). Accounts must therefore be deployed in a separate transaction, paid by some other key, which weakens "an account that never had an ECDSA key" in practice.
- **Proposed fix:** allow a larger state budget for a recognised deterministic deploy (for example, a deploy frame whose factory is a canonical CREATE2 proxy and whose result is checked by code hash), or price code deposit in the deploy frame separately from MAX_VERIFY_STATE_GAS.

## 5. Signature bytes do not count toward the validation budget (keep it so)
- **Evidence (LOCAL):** a Profile A transaction with an extra unused 30,000-byte ARBITRARY signature entry is accepted (`results/local/probe-bigsig.json`). This is what makes hash-based signatures (2 to 9 kB) possible in the public mempool at all. The EIP text supports it (rule 6 counts the verification cost, 100 per ARBITRARY entry, not the bytes); we suggest stating it explicitly in the EIP.

## 6. The devnet build differs from the EIP text in the signed hash
- ethrex @9aa3645 replaces elided signature bytes with empty bytes (the EIP says: their length), has three fee fields (the EIP: two), adds recent-root references to the payload, rejects `nonce_seq = 2^64 - 1` (EIP-8250's single-use marker) and puts NONCE_MANAGER at 0x...8250. Wallets that follow the EIP text will produce signatures the devnet rejects. Details: docs/SPEC_FACTS.md.
