# Winternitz signature encoding (reference for Python and Solidity)

The Python package is named `lamport`. The scheme below is Winternitz, not the original Lamport one-time signature.

Unaudited research code. Hash-based, believed to resist known quantum attacks.

## Parameters
- `n = 32` bytes, hash `H = keccak256`.
- `logW` in {1, 2, 4, 8}, `w = 2^logW`. Profile A: `logW = 4` (w = 16).
- `len1 = msg_bits / logW` (msg_bits = 256 on chain; smaller only in the toy attack).
- `len2 = floor(log2(len1 * (w - 1)) / logW) + 1`; `len = len1 + len2`.
- Tree height `h` (Profile A: 10, so 1,024 one-time keys).

| logW | w | len1 | len2 | len |
|---|---|---|---|---|
| 1 | 2 | 256 | 9 | 265 |
| 2 | 4 | 128 | 5 | 133 |
| 4 | 16 | 64 | 3 | 67 |
| 8 | 256 | 32 | 2 | 34 |

## Address word (ADRS, 32 bytes, big-endian)
| bytes | field |
|---|---|
| 0 | type: 1 CHAIN, 2 LEAF_PK, 3 TREE, 4 MSG |
| 1..8 | chain id (uint64) |
| 9..12 | a (uint32) |
| 13..16 | b (uint32) |
| 17..20 | c (uint32) |
| 21..31 | zero |

As an integer: `type<<248 | chainId<<184 | a<<152 | b<<120 | c<<88`.

## Hashes (`seed` is the account's 32-byte public seed)
- Chain step from position `0` to `1` of chain `i` of leaf `L`: `x' = H(seed || ADRS(CHAIN, a=L, b=i, c=0) || x)`. This is the only step that carries the address word.
- Chain step from position `j` to `j+1` for `j > 0`: `x' = H(x)`, a single 32-byte keccak256.
- Leaf public key: `H(seed || ADRS(LEAF_PK, a=L, c=logW) || pk_0 || ... || pk_{len-1})`.
- Tree node at level `l` (1..h), index `k`: `H(seed || ADRS(TREE, a=l, b=k) || left || right)`.
- Message digest for leaf `L`: `d = H(seed || ADRS(MSG, a=L, c=logW) || m)`, where `m` is the 32-byte message (on chain: the EIP-8141 canonical signature hash).

## Digits and checksum
- Message digits: `d_i = (d >> (256 - logW*(i+1))) & (w-1)` for `i < len1` (most significant first).
- Checksum `c = sum(w - 1 - d_i)`; checksum digits `d_{len1+k} = (c >> (logW*(len2-1-k))) & (w-1)` for `k < len2`.

## Keys and signature
- Secret chain start (off-chain only): `sk_i = H("LAMPORT-SK" || sk_seed || uint32(L) || uint32(i))`.
- Chain end `pk_i` = chain from position 0 to `w-1`.
- Signature value `s_i` = chain from 0 to `d_i`. The verifier continues from `d_i` to `w-1`.

## Signature bytes
`uint32(L) || s_0 || ... || s_{len-1} || path_0 || ... || path_{h-1}`; exact length `4 + 32*(len + h)` (Profile A: 2,468 bytes). Any other length, or `L >= 2^h`, is rejected. Path element `k` is the sibling at level `k`.

## Account signature and key epochs (Profile A account)
The account's ARBITRARY signature entry is `seed || root || signature` (64 + 2,468 = 2,532 bytes), where
`signature` is the Lamport signature above. The account stores `keccak256(seed || root)` for every
registered key tree at storage slot `epoch` (epoch 0 at deployment; slot `2^255` holds the last
epoch). Key rotation registers epoch `e + 1` from a SENDER frame of the account calling itself with
`0x02 || seed || root`.
- Keyed nonce mode: nonce key `(0x4c414d50 << 224) + (epoch << 16) + leaf`, sequence 0.
- Legacy nonce mode: nonce `epoch * 1024 + leaf`.
The chain id and leaf in the hashes are unchanged; a new tree has its own random seed, so the trees
of different epochs never share a hash input.
