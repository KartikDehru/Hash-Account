# Security argument (informal) and operating rules

HashAccount is **unaudited research code**. The code and the nonce tag still use the name Lamport. Its signatures are **hash-based, believed to resist known quantum attacks**. Nothing here is a proof. Figures marked *estimate* are standard generic bounds, not measurements.

## 1. The construction in one page
Encoding details: `reference/SPEC.md`.
- Hash: keccak256, output n = 32 bytes.
- Tweakable hash: every hash call is `H(seed || ADRS || input)`, where `seed` is a random 32-byte public value unique to the account and `ADRS` is a 32-byte address word holding (type, chain id, leaf, chain index, step) or (type, chain id, tree level, node index). This is the "simple" tweakable-hash instantiation used by SPHINCS+ (and close to XMSS's addressing), with keccak in place of SHA-2/SHAKE.
- One-time key: Winternitz with w = 16, 64 message chains plus 3 checksum chains (67), each chain 15 steps long. The leaf's public key is the hash of the 67 chain ends.
- Message: the account signs `d = H(seed || ADRS(MSG, leaf) || m)`, where `m` is the EIP-8141 canonical signature hash (`TXPARAM(0x08)`), which covers sender, chain id, nonce, all frames and fees.
- Many-time key: 1,024 one-time keys in a Merkle tree of height 10; tree nodes are tweakable hashes bound to (level, index). The account stores `keccak256(seed || root)` of each registered tree (epoch) in its storage; the signature carries seed and root, and the account checks them against the commitment for the epoch the nonce selects.
- Key rotation: a transaction signed by a current tree registers the next tree (epoch + 1) through a SENDER frame of the account calling itself. Only the account can call the rotation entry, so only a valid one-time signature can add a tree. Each tree has its own random seed, so trees never share hash inputs.
- Each leaf is accepted once: the leaf is tied to the transaction nonce (keyed mode: nonce key `LAMP + leaf` at sequence 0; legacy mode: leaf = account nonce), and the chain refuses a second transaction for the same nonce (shown in `results/local/inclusion-*.json`).

## 2. Why a forgery should be hard (informal)
To sign a new message with leaf L without the secret key, an attacker who has seen at most one signature from L must produce, for each of the 67 chains, a value at a position at or below the digit of the new digest. The checksum makes it impossible for all 67 digits to be at or above those of the signed digest unless the digests are equal in every digit. So the attacker must invert a chain step somewhere (find a preimage of a keccak call with a known, unique address word) or find a message whose digest equals the signed one in all digits (a second preimage of the message hash).
- **Multi-target attacks:** every hash call has its own (seed, ADRS) prefix, so an attacker cannot attack all chain values of all leaves and accounts at once; each target is a different function. This is the reason for the address word and the public seed (same defence as XMSS and SPHINCS+).
- **Domain separation:** chain steps, leaf compression, tree nodes and message digests use different ADRS types, so a value from one role cannot be replayed in another. The chain id is in every address word; the account address is in `m`.
- **Generic security, *estimate*:** for 256-bit outputs, finding a preimage costs about 2^256 classical and about 2^128 quantum hash calls (Grover). Collisions cost about 2^128 classically and about 2^85 with the BHT quantum algorithm; Lamport's message hashing is deterministic (no randomiser), so an attacker who could make the account sign messages of its choice would face this collision bound. Here the account only signs its own transaction hashes.
- **Toy demonstration:** `results/attack.md` shows the effect of reuse with 16-bit digits: two signatures from one key are forged every time (median 17 attempts), one signature far less easily.

## 3. What is not established
- No formal proof that this exact construction (keccak tweakable hash, this ADRS layout, this checksum encoding, no randomiser) meets a stated security definition. It follows published designs but is not one of them.
- keccak is treated as a random function; no analysis of keccak in this mode beyond that.
- The Solidity and Yul verifiers are hand-written assembly. They agree with the Python reference on 10,000 random valid and mutated cases (`results/differential_10000.txt`), on saved vectors, and on mutation tests. That is testing, not verification.
- The TypeScript signer matches the Python vectors byte for byte; key generation uses `crypto.getRandomValues`. No side-channel review.
- Profile B uses Skale's XMSS verifier, formally checked against RFC 8391 but not audited; Lamport's wrapper around it is not formally checked.

## 4. Operating rules (the scheme is stateful)
1. **Never sign twice with one leaf.** The signer reads spent leaves from the chain (NONCE_MANAGER storage or the account nonce), checks the mempool, and keeps an append-only journal written before a signature is returned. Any of the three refuses the leaf.
2. **No fee bumps.** A replacement would need a second signature on the same leaf. Set a generous `max_fee` instead (only the actual cost is collected).
3. **Legacy mode: rebroadcast, never re-sign.** If a signed transaction is dropped, send the same saved transaction again; the signer does this and never signs that leaf again.
4. **Backups.** Restoring an old journal is safe for any signature that reached the chain or the mempool (read from the network). A signature that was produced but never sent and whose journal entry is lost must be destroyed.
5. **Key exhaustion and rotation.** Each tree signs 1,024 transactions (one of them can be the rotation itself). Rotate before the last leaf (`cli rotate`; the CLI warns from leaf 1,000). Rotation adds a tree and does not revoke older ones; their remaining leaves stay usable by whoever holds their secret seed, so treat old key files as live secrets until their leaves are spent, and move funds to a new account if a seed leaks.
6. **Test keys only.** Key files hold the secret seed in plain JSON (`signer/keys/`, `.local/`, both ignored by git).

## 5. Other properties
- **Malleability:** the signature bytes are elided from the signature hash, so the verifier must accept exactly one encoding. It checks the exact length; chain values and the path are fully determined by the message and leaf, so there is one valid signature per (leaf, message).
- **Fee exposure:** fees are inside the signed hash, so nobody can raise the fee the account pays.
- **Deployment:** the account is deployed by an ordinary transaction from any funded key. That key has no authority over the account; the account's code and root are fixed by its CREATE2 address.
- **Out of scope:** legacy EOAs, mempool and builder visibility of transactions, quantum risk to consensus and to other contracts, lost-key recovery.
