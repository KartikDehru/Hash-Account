// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FrameContextMock} from "./FrameContextMock.sol";
import {LamportXmssVerifier} from "../src/LamportXmssVerifier.sol";

/// Profile B account on the test build (context from FrameContextMock) and the bench build
/// (context from calldata), with Skale's h = 10 XMSS vectors.
contract LamportXmssAccountTest is Test {
    address internal constant CTX = 0x00000000000000000000000000000000008141C0;
    uint256 internal constant LMPB_BASE = uint256(0x4c4d5042) << 224;
    bytes32 internal constant APPROVED_3 = bytes32(uint256(0xaa) << 248 | 3);

    FrameContextMock internal ctx;
    LamportXmssVerifier internal verifier;
    string internal json;
    bytes32 internal root;
    bytes32 internal seed;

    function _deploy(string memory file) internal returns (address a) {
        bytes memory init = abi.encodePacked(
            vm.parseBytes(vm.trim(vm.readFile(file))), uint256(uint160(address(verifier))), root, seed
        );
        assembly {
            a := create(0, add(init, 0x20), mload(init))
        }
        require(a != address(0), "deploy failed");
    }

    function setUp() public {
        vm.etch(CTX, type(FrameContextMock).runtimeCode);
        ctx = FrameContextMock(payable(CTX));
        verifier = new LamportXmssVerifier();
        json = vm.readFile("test/vectors/xmss/xmss_h10.json");
        root = vm.parseJsonBytes32(json, ".root");
        seed = vm.parseJsonBytes32(json, ".seed");
    }

    function _vector(uint256 i) internal view returns (uint256 leaf, bytes32 message, bytes memory sig) {
        string memory k = string.concat(".vectors[", vm.toString(i), "]");
        leaf = vm.parseJsonUint(json, string.concat(k, ".idx"));
        message = vm.parseJsonBytes32(json, string.concat(k, ".msg"));
        sig = abi.encodePacked(
            uint32(leaf),
            vm.parseJsonBytes32(json, string.concat(k, ".r")),
            vm.parseJsonBytes32Array(json, string.concat(k, ".wotsSig")),
            vm.parseJsonBytes32Array(json, string.concat(k, ".auth"))
        );
    }

    function _context(uint256 leaf, bytes32 message, bytes memory sig) internal {
        ctx.setTx(0x0E, 1);
        ctx.setTx(0x01, 0);
        ctx.setTx(0x10, LMPB_BASE + leaf);
        ctx.setTx(0x08, uint256(message));
        ctx.setSig(0, 0, sig);
    }

    function test_verifier_contract() public view {
        (, bytes32 message, bytes memory sig) = _vector(0);
        assertEq(sig.length, 2500);
        assertTrue(verifier.verify(root, seed, 10, message, sig));
        assertFalse(verifier.verify(root, seed, 10, bytes32(uint256(message) ^ 1), sig));
        assertFalse(verifier.verify(root, seed, 9, message, sig));
    }

    function test_approves_valid_and_rejects_bad() public {
        address account = _deploy("account/LamportXmssAccountMock.initcode.hex");
        for (uint256 i; i < 4; i++) {
            (uint256 leaf, bytes32 message, bytes memory sig) = _vector(i);
            _context(leaf, message, sig);
            (bool ok, bytes memory ret) = account.staticcall(hex"0100");
            assertTrue(ok, "valid XMSS signature rejected");
            assertEq(bytes32(ret), APPROVED_3);
        }
        (uint256 l, bytes32 m, bytes memory s) = _vector(1);
        bool bad;
        _context(l, m, s);
        ctx.setTx(0x10, LMPB_BASE + l + 1);
        (bad,) = account.staticcall(hex"0100");
        assertFalse(bad, "key of other leaf");
        _context(l, m, s);
        ctx.setTx(0x01, 1);
        (bad,) = account.staticcall(hex"0100");
        assertFalse(bad, "second use of a key");
        _context(l, bytes32(uint256(m) ^ 1), s);
        (bad,) = account.staticcall(hex"0100");
        assertFalse(bad, "other message");
        s[200] = bytes1(uint8(s[200]) ^ 1);
        _context(l, m, s);
        (bad,) = account.staticcall(hex"0100");
        assertFalse(bad, "tampered");
    }

    function test_gas_verify_frame_bench() public {
        address account = _deploy("account/LamportXmssAccountBench.initcode.hex");
        (bool warm,) = account.staticcall("");
        assertTrue(warm);
        uint256 lo = type(uint256).max;
        uint256 hi;
        uint256 sum;
        for (uint256 i; i < 4; i++) {
            (uint256 leaf, bytes32 message, bytes memory sig) = _vector(i);
            bytes memory data =
                abi.encodePacked(hex"0100", uint256(0), message, uint256(1), LMPB_BASE + leaf, uint256(0), sig.length, sig);
            uint256 g0 = gasleft();
            (bool ok, bytes memory ret) = account.staticcall(data);
            uint256 used = g0 - gasleft();
            assertTrue(ok);
            assertEq(bytes32(ret), APPROVED_3);
            if (used < lo) lo = used;
            if (used > hi) hi = used;
            sum += used;
        }
        vm.serializeUint("xbench", "samples", 4);
        vm.serializeUint("xbench", "signatureBytes", 2500);
        vm.serializeUint("xbench", "min", lo);
        vm.serializeUint("xbench", "max", hi);
        vm.serializeUint("xbench", "mean", sum / 4);
        string memory out = vm.serializeString(
            "xbench", "note", "Profile B VERIFY frame code (bench build), Skale h=10 vectors; includes the verifier STATICCALL"
        );
        vm.writeJson(out, "../results/account_xmss_bench_gas.json");
    }
}

/// Our Python XMSS test signer (reference/xmss/cli.py) against the Solidity verifier.
contract XmssSignerCrossCheck is Test {
    function test_python_signer_verifies_on_chain() public {
        LamportXmssVerifier verifier = new LamportXmssVerifier();
        string memory key = "../results/.xmss_crosscheck_key.json";
        string[] memory cmd = new string[](5);
        cmd[0] = "../.venv/bin/python";
        cmd[1] = "../reference/xmss/cli.py";
        cmd[2] = "keygen";
        cmd[3] = "4";
        cmd[4] = key;
        string memory info = string(vm.ffi(cmd));
        bytes32 root = vm.parseJsonBytes32(info, ".root");
        bytes32 seed = vm.parseJsonBytes32(info, ".seed");
        bytes32 digest = keccak256("cross check");
        string[] memory s = new string[](6);
        s[0] = "../.venv/bin/python";
        s[1] = "../reference/xmss/cli.py";
        s[2] = "sign";
        s[3] = key;
        s[4] = "9";
        s[5] = vm.toString(digest);
        bytes memory sig = vm.ffi(s);
        vm.removeFile(key);
        assertTrue(verifier.verify(root, seed, 4, digest, sig));
        assertFalse(verifier.verify(root, seed, 4, bytes32(uint256(digest) ^ 1), sig));
    }
}
