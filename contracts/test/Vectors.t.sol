// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LamportVerifier} from "../src/LamportVerifier.sol";

/// Full-tree vectors written by `python -m lamport.cli vectors` (reference/vectors/).
contract VectorsTest is Test {
    function _check(string memory file) internal view {
        string memory json = vm.readFile(string.concat("../reference/vectors/", file));
        LamportVerifier.Key memory key = LamportVerifier.Key({
            seed: vm.parseJsonBytes32(json, ".seed"),
            root: vm.parseJsonBytes32(json, ".root"),
            chainId: uint64(vm.parseJsonUint(json, ".chainId")),
            logW: uint8(vm.parseJsonUint(json, ".logW")),
            height: uint8(vm.parseJsonUint(json, ".height"))
        });
        uint256 n;
        for (; vm.keyExistsJson(json, string.concat(".signatures[", vm.toString(n), "]")); n++) {
            string memory k = string.concat(".signatures[", vm.toString(n), "]");
            bytes32 message = vm.parseJsonBytes32(json, string.concat(k, ".message"));
            bytes memory sig = vm.parseJsonBytes(json, string.concat(k, ".signature"));
            assertEq(LamportVerifier.leafIndex(sig), vm.parseJsonUint(json, string.concat(k, ".leaf")));
            assertTrue(LamportVerifier.verify(key, message, sig), file);
            // Every single-bit change of the signature must be rejected (sampled positions).
            for (uint256 pos = 0; pos < sig.length; pos += 97) {
                sig[pos] = bytes1(uint8(sig[pos]) ^ 0x01);
                assertFalse(LamportVerifier.verify(key, message, sig), "bit flip accepted");
                sig[pos] = bytes1(uint8(sig[pos]) ^ 0x01);
            }
            assertFalse(LamportVerifier.verify(key, bytes32(uint256(message) ^ 1), sig), "other message accepted");
        }
        assertGt(n, 0);
    }

    function test_profileA_h10() public view { _check("profile_a_h10.json"); }
    function test_w4_h4() public view { _check("w4_h4.json"); }
    function test_w256_h2() public view { _check("w256_h2.json"); }
    function test_w2_h1() public view { _check("w2_h1.json"); }

    function test_rejects_bad_parameters() public pure {
        LamportVerifier.Key memory key = LamportVerifier.Key(bytes32(0), bytes32(0), 1, 3, 10);
        assertFalse(LamportVerifier.verify(key, bytes32(0), new bytes(2468)));
        key.logW = 4;
        key.height = 21;
        assertFalse(LamportVerifier.verify(key, bytes32(0), new bytes(4 + 32 * (67 + 21))));
        key.height = 10;
        assertFalse(LamportVerifier.verify(key, bytes32(0), new bytes(2467)));
        bytes memory sig = new bytes(2468);
        sig[2] = 0x04; // leaf 1024, out of range for height 10
        assertFalse(LamportVerifier.verify(key, bytes32(0), sig));
    }
}
