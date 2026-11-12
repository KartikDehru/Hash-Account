// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LamportVerifier
/// @notice Verifies Winternitz one-time signatures in a Merkle tree of one-time keys.
/// Encoding: reference/SPEC.md. Hash-based, believed to resist known quantum attacks.
/// Unaudited research code. Stateless: the caller must make sure each leaf is accepted once
/// (Lamport does this with an EIP-8250 single-use nonce key).
library LamportVerifier {
    struct Key {
        bytes32 seed; // per-account public seed bound into every hash
        bytes32 root; // Merkle root of the one-time public keys
        uint64 chainId;
        uint8 logW; // log2 of the Winternitz parameter: 1, 2, 4 or 8
        uint8 height; // tree height, at most 20
    }

    uint256 internal constant TYPE_CHAIN = 1;
    uint256 internal constant TYPE_LEAF_PK = 2;
    uint256 internal constant TYPE_TREE = 3;
    uint256 internal constant TYPE_MSG = 4;
    uint256 internal constant STEP = 1 << 88; // one step in the address word's step field

    /// @return len1 message digits, len2 checksum digits (0, 0 for an unsupported logW)
    function lengths(uint256 logW) internal pure returns (uint256 len1, uint256 len2) {
        if (logW == 4) return (64, 3);
        if (logW == 1) return (256, 9);
        if (logW == 2) return (128, 5);
        if (logW == 8) return (32, 2);
    }

    function signatureLength(uint256 logW, uint256 height) internal pure returns (uint256) {
        (uint256 len1, uint256 len2) = lengths(logW);
        return 4 + 32 * (len1 + len2 + height);
    }

    function leafIndex(bytes memory sig) internal pure returns (uint256 leaf) {
        assembly ("memory-safe") {
            leaf := shr(224, mload(add(sig, 32)))
        }
    }

    /// @notice Full verification. Returns false for any malformed input; never reverts.
    function verify(Key memory key, bytes32 message, bytes memory sig) internal pure returns (bool) {
        (uint256 len1, uint256 len2) = lengths(key.logW);
        if (len1 == 0 || key.height > 20) return false;
        if (sig.length != 4 + 32 * (len1 + len2 + key.height)) return false;
        uint256 leaf = leafIndex(sig);
        if (leaf >> key.height != 0) return false;
        bytes32 digest = messageDigest(key, leaf, message);
        bytes32 node = leafFromSignature(key, leaf, digest, sig, len1, len2);
        return rootFromPath(key, leaf, node, sig, len1 + len2) == key.root;
    }

    /// @notice Phase 1: d = H(seed || ADRS(MSG, leaf, logW) || message).
    function messageDigest(Key memory key, uint256 leaf, bytes32 message) internal pure returns (bytes32 d) {
        bytes32 seed = key.seed;
        uint256 a = (TYPE_MSG << 248) | (uint256(key.chainId) << 184) | (leaf << 152) | (uint256(key.logW) << 88);
        assembly ("memory-safe") {
            let s := mload(0x40)
            mstore(s, seed)
            mstore(add(s, 32), a)
            mstore(add(s, 64), message)
            d := keccak256(s, 96)
        }
    }

    /// @notice Phase 2: walk every chain to its end and compress the ends into the leaf node.
    /// Assumes sig.length was checked by the caller.
    function leafFromSignature(
        Key memory key,
        uint256 leaf,
        bytes32 digest,
        bytes memory sig,
        uint256 len1,
        uint256 len2
    ) internal pure returns (bytes32 node) {
        bytes32 seed = key.seed;
        uint256 chainId = key.chainId;
        uint256 logW = key.logW;
        assembly ("memory-safe") {
            let s := mload(0x40) // F input: seed | adrs | x
            let buf := add(s, 96) // compression input: seed | adrs | end_0 .. end_{len-1}
            mstore(s, seed)
            mstore(buf, seed)
            mstore(add(buf, 32), or(or(shl(248, TYPE_LEAF_PK), shl(184, chainId)), or(shl(152, leaf), shl(88, logW))))
            let adrsSlot := add(s, 32)
            let xSlot := add(s, 64)
            let mask := sub(shl(logW, 1), 1)
            let top := sub(256, logW)
            // chain index i sits at bit 120; with off = 32 * i that is off << 115
            let adrsLeaf := or(or(shl(248, TYPE_CHAIN), shl(184, chainId)), shl(152, leaf))
            let values := add(sig, 36)
            let ends := add(buf, 64)

            // Message chains: digits are read from the top of the digest.
            let sum := 0
            let dg := digest
            let limit := shl(5, len1)
            for { let off := 0 } lt(off, limit) { off := add(off, 32) } {
                let d := shr(top, dg)
                dg := shl(logW, dg)
                sum := add(sum, d)
                let n := sub(mask, d)
                let x := mload(add(values, off))
                let ad := or(or(adrsLeaf, shl(115, off)), shl(88, d))
                // n chain steps, unrolled in blocks of 16, 8, 4, 2 and 1 (about 40% cheaper than a loop)
                for { } gt(n, 15) { n := sub(n, 16) } {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 8) {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 4) {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 2) {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 1) { mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP) }
                mstore(add(ends, off), x)
            }

            // Checksum chains: checksum = sum of (w - 1 - d_i), written in len2 base-w digits.
            dg := shl(sub(256, mul(len2, logW)), sub(mul(len1, mask), sum))
            limit := shl(5, add(len1, len2))
            for { let off := shl(5, len1) } lt(off, limit) { off := add(off, 32) } {
                let d := shr(top, dg)
                dg := shl(logW, dg)
                let n := sub(mask, d)
                let x := mload(add(values, off))
                let ad := or(or(adrsLeaf, shl(115, off)), shl(88, d))
                // n chain steps, unrolled in blocks of 16, 8, 4, 2 and 1 (about 40% cheaper than a loop)
                for { } gt(n, 15) { n := sub(n, 16) } {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 8) {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 4) {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 2) {
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                    mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP)
                }
                if and(n, 1) { mstore(adrsSlot, ad) mstore(xSlot, x) x := keccak256(s, 96) ad := add(ad, STEP) }
                mstore(add(ends, off), x)
            }
            node := keccak256(buf, add(64, limit))
        }
    }

    /// @notice Phase 3: walk the authentication path from the leaf node to the root.
    function rootFromPath(Key memory key, uint256 leaf, bytes32 node, bytes memory sig, uint256 len)
        internal
        pure
        returns (bytes32)
    {
        bytes32 seed = key.seed;
        uint256 height = key.height;
        uint256 base = (TYPE_TREE << 248) | (uint256(key.chainId) << 184);
        assembly ("memory-safe") {
            let s := mload(0x40) // seed | adrs | left | right
            mstore(s, seed)
            let path := add(add(sig, 36), shl(5, len))
            for { let l := 1 } iszero(gt(l, height)) { l := add(l, 1) } {
                let sibling := mload(add(path, shl(5, sub(l, 1))))
                mstore(add(s, 32), or(base, or(shl(152, l), shl(120, shr(l, leaf)))))
                switch and(shr(sub(l, 1), leaf), 1)
                case 0 {
                    mstore(add(s, 64), node)
                    mstore(add(s, 96), sibling)
                }
                default {
                    mstore(add(s, 64), sibling)
                    mstore(add(s, 96), node)
                }
                node := keccak256(s, 128)
            }
        }
        return node;
    }
}
