# How HashAccount differs from wallets described as quantum-proof

Read 12 Nov 2026. This repository does not use the words quantum-proof or audited. The signatures are hash-based, believed to resist known quantum attacks. The code is unaudited research code. Gas figures below for HashAccount come from scripts in this repository. Gas figures for other projects are not repeated here, because this repository did not measure them.

The contracts and the nonce tag still say Lamport. That is the one-time signature family, and those bytes are already in the measured artifacts.

## Four approaches in use

**A fresh ECDSA address that has never signed.** The public key stays hidden until the first signature. A later quantum break of secp256k1 can spend the account once that signature is public. The signature scheme is still ECDSA.

**Quip Accounts.** A smart contract on the chain the user already uses, through ERC-4337, so it works before EIP-8141. On EVM chains the Quip signature guide requires both the owner's ECDSA signature and a SHRINCS signature. SHRINCS (ePrint 2025/2203) has a cheap one-time path, at most 4,096 signatures in `hashsigs-rs`, and a stateless SPHINCS+C path for recovery. Quip's account docs say the chain verifies the signature and does not record which slot was used. The signer does. A restored backup can sign with a spent slot. An ERC-1271 check does not consume a slot.

**A lattice signature in a contract wallet** (ML-DSA or Falcon). Security rests on lattice problems. HashAccount does not implement those schemes.

**A library labelled quantum-proof.** A verifier library is not an account. Nothing in this repository is on Ethereum mainnet. The frame-transaction results are local. Nothing here is deployed on a public network.

## What HashAccount does

- There is no ECDSA owner. Authorization is the hash-based signature alone. A flaw in that verifier is a flaw in the only authorization path. Quip keeps an ECDSA signature as a second check.
- On the frame-transaction account, after inclusion the chain spends the leaf. Keyed mode binds leaf `i` to nonce key `LAMP + (epoch << 16) + i` at sequence 0. Local inclusion runs recorded the node refusing a second use (`results/local/inclusion-keyed.json`). Before broadcast, the signer still has to refuse a second signature: the journal is written before the signature is returned (`docs/SECURITY.md`).
- Rotation adds the next tree of 1,024 leaves and needs a live leaf. There is no stateless recovery path.
- Profile A is measured against the draft 100,000-gas public cap. The largest keyed VERIFY frame on local ethrex is 95,356 gas (12 Nov 2026). The signer refuses a message whose step count would not fit. Profile B (Skale XMSS, vendored unchanged) is far above the cap.
- EIP-8141 is a draft scheduled for Hegotá. ethereum.org, updated 16 October 2026, expects that upgrade in the second quarter of 2027, with no confirmed date. The FAQ at eip8141.io says it is not on mainnet.

## Related work

| Work | What it is, as the project describes it |
|---|---|
| Quip Network `hashsigs-solidity`, `hashsigs-rs`, `quip-solidity` | Testnet verifiers, a reference signer, wallet contracts, test vectors. SHRINCS adds a stateless SPHINCS+C recovery path to a bounded stateful path. |
| Riva Labs, Ephemeral Keys Protocol | FORS+C. Quip and Riva both keep a constant account address and rotate key material every transaction. |
| poqeth | Solidity verifiers for XMSS, SPHINCS+ and MAYO. |
| QRL | Operational experience with XMSS wallets and one-time-signature state. |
| ZKNox and EIP-8052 | Lattice verifier work, a different security assumption from hash-based signatures. |
| leanEthereum, machine-checked XMSS and SPHINCS+ (ePrint 2022/778) | Protocol and proof precedent. |

## Quip Accounts

Sources: [Quip Accounts](https://developers.quip.network/docs/quip-interlock-protocol/quip-accounts) and [Post-quantum signature schemes for blockchains](https://developers.quip.network/docs/guides/post-quantum-signatures-for-blockchains). SHRINCS is described as the two-path construction in [ePrint 2025/2203](https://eprint.iacr.org/2025/2203).

- The account is a smart contract on the chain the user already uses, reached through ERC-4337. It works before EIP-8141.
- On EVM chains, Quip's signature guide says each owner operation is gated by both the owner's ECDSA signature and a SHRINCS signature. An attacker has to break both. The ECDSA key still exists.
- SHRINCS has a cheap stateful path (a budget of one-time leaves, at most 4,096 in `hashsigs-rs`) and a stateless SPHINCS+C path for recovery and rotation. The stateless path needs no record of used slots.
- The account docs say the chain verifies signatures and does not manage signing state. The signer records spent slots, and must write that record before broadcast. A restored old backup can sign with a slot that was already used.
- ERC-1271 checks do not consume a slot. A signature checked that way stays valid while the key stays installed. Quip documents this as a deliberate choice.

## What can be checked here

1. Chain-enforced one-time use. Some failures the chain detects after inclusion; others only the signer can stop before broadcast. An included HashAccount leaf is in the first group (`results/local/inclusion-*.json`).
2. A measured verification-gas frontier against the draft 100,000 cap, produced by scripts, for the parameter sets an account would actually ship (`results/frontier.md`). A scheme that cannot be validated under the cap cannot enter the public mempool.
3. Where frame transactions stand. EIP-8141 is not on mainnet, and every frame-transaction result here comes from a local ethrex build.
