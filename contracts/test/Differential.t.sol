// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LamportVerifier} from "../src/LamportVerifier.sol";
import {Packed} from "./Packed.sol";

/// Python reference against Solidity on random keys, messages, w and heights.
/// Each fuzz run checks 100 cases: the valid signature must verify and a mutated one
/// (byte flip in values, path or leaf index; changed message, root, seed, chain id or length)
/// must fail in both implementations. `FOUNDRY_PROFILE=diff` runs 100 x 100 = 10,000 cases.
contract DifferentialTest is Test {
    uint256 internal constant PER_RUN = 100;

    function testFuzz_differential(uint64 runSeed) public {
        Packed.Case[] memory cases = Packed.fetch(vm.toString(abi.encodePacked(runSeed)), PER_RUN, 0, -1);
        assertEq(cases.length, PER_RUN);
        for (uint256 i; i < cases.length; i++) {
            Packed.Case memory c = cases[i];
            assertTrue(LamportVerifier.verify(c.key, c.message, c.sig), "valid signature rejected");
            assertFalse(LamportVerifier.verify(c.badKey, c.badMessage, c.badSig), "mutated signature accepted");
        }
    }
}
