// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {XMSS} from "./xmss/XMSS.sol";

/// @title LamportXmssVerifier
/// @notice Profile B: decodes a packed XMSS signature and calls Skale's verifier (vendored,
/// unchanged; formally checked against RFC 8391, not audited). Stateless and storage-free, so
/// an account's VERIFY frame may STATICCALL it. Leaf reuse is refused by the account's nonce key.
/// Signature layout: uint32 leaf | r | wots[67] | auth[h]  (4 + 32 * (68 + h) bytes).
contract LamportXmssVerifier {
    function verify(bytes32 root, bytes32 seed, uint256 height, bytes32 digest, bytes calldata sig)
        external
        view
        returns (bool)
    {
        if (height == 0 || height > 20 || sig.length != 4 + 32 * (68 + height)) return false;
        XMSS.Signature memory s;
        s.leafIdx = uint32(bytes4(sig[0:4]));
        s.r = bytes32(sig[4:36]);
        for (uint256 i; i < 67; i++) {
            s.wotsSig[i] = bytes32(sig[36 + 32 * i:68 + 32 * i]);
        }
        s.authPath = new bytes32[](height);
        uint256 off = 36 + 32 * 67;
        for (uint256 i; i < height; i++) {
            s.authPath[i] = bytes32(sig[off + 32 * i:off + 32 * i + 32]);
        }
        return XMSS.verify(digest, s, XMSS.PublicKey(root, seed), height);
    }
}
