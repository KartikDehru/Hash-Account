# Open questions and how to settle them

| # | Question | Settle by experiment | Ask |
|---|---|---|---|
| Q1 | Does signature calldata (ARBITRARY entries) count toward MAX_VERIFY_GAS or only intrinsic gas? | Send a transaction with a large ARBITRARY signature and a trivial VERIFY frame; read the admission report. | Alt-mempool implementers |
| Q2 | Does the default signature hash cover fee fields and the payer frame? Can an explicit digest exclude them? | Build two transactions that differ only in fees; check whether the default hash changes and whether an explicit digest is accepted. | EF engineers |
| Q3 | Maximum validation gas on a public frames devnet? Stake and budget model in practice? | Send transactions with rising VERIFY gas; read the refusal rule. | Client and mempool implementers |
| Q4 | Does nonce key = leaf index work as read (spent-once at payment approval, no SSTORE in VERIFY)? | Send two transactions with the same key; the second must be refused. | EF engineers |
| Q5 | How should the sender pass the leaf index and path to VERIFY: in the signature bytes or frame data? | Try both; use whichever the simulator and devnet accept. | EF engineers |
| Q6 | Is Winternitz w=16 verification under 100,000 gas? | Measure in Foundry per phase. | none: measure |
| Q7 | Does a deploy frame plus self_verify accept a code-derived account with no ECDSA key? | Try on the devnet. | EF engineers |

If an answer contradicts the design, record it in docs/DECISIONS.md and change the design, not the question.

## Status after reading the source text (24 Oct 2026)
- Q1: partly settled by text. Rule 6 counts declared `limits.execution` of the validation prefix plus 100 gas per ARBITRARY entry; the signature bytes are priced in a separate intrinsic term. Still confirm on a devnet. See docs/SPEC_FACTS.md.
- Q2: settled by text. The canonical hash covers fees and all frames. An explicit digest is allowed but the EIP warns against approving execution on it. Design changed: docs/DECISIONS.md "D5 revised".
- Q4: EIP-8250 now has single-use keys (`nonce_seq == MAX_NONCE_SEQ`), which fit the leaf-index design better than read before. Still confirm on a devnet.
- Q5: EIP-8141 says bespoke witness bytes that sign the canonical hash must go in an ARBITRARY entry, not frame data. Design uses the ARBITRARY entry.
- Q3 update: the sidecar at fcb4885 enforces MAX_VERIFY_GAS = 100,000 for every transaction (docs/SPEC_FACTS.md, last section). Unless the devnets differ, Profile B cannot be admitted by the alt mempool either. This is the first question to confirm on a public devnet.

## Status after the local ethrex runs (first 24 Oct 2026; re-run 12 Nov 2026 on ethrex 9aa3645 and sidecar fcb4885; local build, not the public devnet)
- Q1: settled for ethrex 9aa3645 + sidecar fcb4885: signature bytes do not count (results/local/probe-bigsig.json).
- Q3: still open for the devnets. Locally the sidecar refuses Profile B at 100,000; a node with a raised budget includes it.
- Q4: settled locally: a leaf is spent once at inclusion; reuse is refused by node, sidecar, account and signer (results/local/inclusion-*.json).
- Q5: settled: the signature travels in an ARBITRARY entry and the leaf in its first 4 bytes, checked against the nonce.
- Q6: settled: real VERIFY frame 81,790 to 95,356 gas (keyed nonce) and 62,095 to 76,294 (legacy nonce) over 48 samples each, re-measured 12 Nov 2026; under the cap, with the keyed mode close to it.
- Q7: settled locally: deploy + self_verify needs about 2.74M state gas for this account, over the 500,000 cap. Deploy in an earlier transaction.
