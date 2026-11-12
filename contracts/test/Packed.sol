// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {LamportVerifier} from "../src/LamportVerifier.sol";

/// Reads the packed cases printed by `python -m lamport.cli batch` (see pack_case in cli.py).
library Packed {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct Case {
        LamportVerifier.Key key;
        bytes32 message;
        bytes sig;
        LamportVerifier.Key badKey;
        bytes32 badMessage;
        bytes badSig;
    }

    function uintAt(bytes memory b, uint256 off, uint256 n) internal pure returns (uint256 v) {
        require(off + n <= b.length, "packed: out of range");
        assembly ("memory-safe") {
            v := shr(sub(256, mul(8, n)), mload(add(add(b, 32), off)))
        }
    }

    function slice(bytes memory b, uint256 off, uint256 n) internal pure returns (bytes memory out) {
        require(off + n <= b.length, "packed: out of range");
        out = new bytes(n);
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(add(b, 32), off), n)
        }
    }

    function fetch(string memory seedHex, uint256 count, uint256 logW, int256 height)
        internal
        returns (Case[] memory cases)
    {
        return fetchChain(seedHex, count, logW, height, -1);
    }

    /// Same as fetch, with a fixed chain id for every case (chainId < 0: random per case).
    function fetchChain(string memory seedHex, uint256 count, uint256 logW, int256 height, int256 chainId)
        internal
        returns (Case[] memory cases)
    {
        uint256 argc = 3 + (logW != 0 ? 2 : 0) + (height >= 0 ? 2 : 0) + (chainId >= 0 ? 2 : 0);
        string[] memory cmd = new string[](argc);
        cmd[0] = "../scripts/ffi_batch.sh";
        cmd[1] = seedHex;
        cmd[2] = vm.toString(count);
        uint256 k = 3;
        if (logW != 0) {
            cmd[k++] = "--log-w";
            cmd[k++] = vm.toString(logW);
        }
        if (height >= 0) {
            cmd[k++] = "--height";
            cmd[k++] = vm.toString(uint256(height));
        }
        if (chainId >= 0) {
            cmd[k++] = "--chain-id";
            cmd[k++] = vm.toString(uint256(chainId));
        }
        bytes memory blob = vm.ffi(cmd);
        uint256 n = uintAt(blob, 0, 4);
        cases = new Case[](n);
        uint256 off = 4;
        for (uint256 i; i < n; i++) {
            uint256 size = uintAt(blob, off, 4);
            cases[i] = decode(slice(blob, off + 4, size));
            off += 4 + size;
        }
    }

    function decode(bytes memory c) internal pure returns (Case memory r) {
        uint8 logW = uint8(uintAt(c, 0, 1));
        uint8 height = uint8(uintAt(c, 1, 1));
        r.key = LamportVerifier.Key(bytes32(uintAt(c, 10, 32)), bytes32(uintAt(c, 42, 32)), uint64(uintAt(c, 2, 8)), logW, height);
        r.message = bytes32(uintAt(c, 74, 32));
        r.badKey = LamportVerifier.Key(bytes32(uintAt(c, 114, 32)), bytes32(uintAt(c, 146, 32)), uint64(uintAt(c, 106, 8)), logW, height);
        r.badMessage = bytes32(uintAt(c, 178, 32));
        uint256 sigLen = uintAt(c, 210, 2);
        r.sig = slice(c, 212, sigLen);
        uint256 badLen = uintAt(c, 212 + sigLen, 2);
        r.badSig = slice(c, 214 + sigLen, badLen);
    }
}
