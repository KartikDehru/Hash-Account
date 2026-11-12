// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LamportVerifier} from "../src/LamportVerifier.sol";

/// Measures gas per verification phase with gasleft(). The signature arrives as calldata and
/// is copied to memory with CALLDATACOPY, whose gas formula EIP-8141 also uses for SIGDATACOPY.
contract GasProbe {
    struct Phases {
        uint256 copy;
        uint256 digest;
        uint256 chains;
        uint256 path;
        uint256 total;
        bool ok;
    }

    function phases(LamportVerifier.Key calldata keyIn, bytes32 message, bytes calldata sigIn)
        external
        view
        returns (Phases memory r)
    {
        LamportVerifier.Key memory key = keyIn;
        (uint256 len1, uint256 len2) = LamportVerifier.lengths(key.logW);
        uint256 g0 = gasleft();
        bytes memory sig = sigIn;
        uint256 g1 = gasleft();
        uint256 leaf = LamportVerifier.leafIndex(sig);
        bytes32 digest = LamportVerifier.messageDigest(key, leaf, message);
        uint256 g2 = gasleft();
        bytes32 node = LamportVerifier.leafFromSignature(key, leaf, digest, sig, len1, len2);
        uint256 g3 = gasleft();
        bytes32 root = LamportVerifier.rootFromPath(key, leaf, node, sig, len1 + len2);
        r.ok = root == key.root;
        uint256 g4 = gasleft();
        r.copy = g0 - g1;
        r.digest = g1 - g2;
        r.chains = g2 - g3;
        r.path = g3 - g4;
        r.total = g0 - g4;
        r.ok = r.ok && sig.length == LamportVerifier.signatureLength(key.logW, key.height);
    }

    /// Gas of the complete library call, including the copy and all checks.
    function full(LamportVerifier.Key calldata keyIn, bytes32 message, bytes calldata sigIn)
        external
        view
        returns (uint256 used, bool ok)
    {
        LamportVerifier.Key memory key = keyIn;
        uint256 g0 = gasleft();
        bytes memory sig = sigIn;
        ok = LamportVerifier.verify(key, message, sig);
        used = g0 - gasleft();
    }
}
