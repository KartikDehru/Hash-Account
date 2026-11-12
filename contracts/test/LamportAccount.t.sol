// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FrameContextMock} from "./FrameContextMock.sol";
import {Packed} from "./Packed.sol";
import {LamportVerifier} from "../src/LamportVerifier.sol";

/// Tests the account's VERIFY logic on the test build (account/LamportAccountMock.yul), where the
/// EIP-8141 opcodes are replaced by calls to FrameContextMock. The real build differs only in
/// those four functions (scripts/gen_account.py). Behaviour with the real opcodes needs an
/// EIP-8141 client: docs/DEVNET_RUNBOOK.md.
contract LamportAccountTest is Test {
    address internal constant CTX = 0x00000000000000000000000000000000008141C0;
    uint256 internal constant LEAF_KEY_BASE = uint256(0x4c414d50) << 224;
    bytes32 internal constant APPROVED_3 = bytes32(uint256(0xaa) << 248 | 3);
    // Regression bound for the bench build's mean VERIFY gas. Raise only with a recorded reason.
    uint256 internal constant ACCOUNT_BENCH_MEAN_LIMIT = 74_000;

    FrameContextMock internal ctx;
    address internal account;
    string internal json;
    bytes32 internal seed0;
    bytes32 internal root0;

    function _deploy(string memory file, bytes32 seed, bytes32 root, uint256 chainId) internal returns (address a) {
        return _deployMode(file, seed, root, chainId, 0);
    }

    function _deployMode(string memory file, bytes32 seed, bytes32 root, uint256 chainId, uint256 mode)
        internal
        returns (address a)
    {
        bytes memory init = abi.encodePacked(vm.parseBytes(vm.trim(vm.readFile(file))), seed, root, chainId, mode);
        assembly {
            a := create(0, add(init, 0x20), mload(init))
        }
        require(a != address(0), "deploy failed");
    }

    function setUp() public {
        vm.etch(CTX, type(FrameContextMock).runtimeCode);
        ctx = FrameContextMock(payable(CTX));
        json = vm.readFile("../reference/vectors/profile_a_h10.json");
        seed0 = vm.parseJsonBytes32(json, ".seed");
        root0 = vm.parseJsonBytes32(json, ".root");
        account = _deploy(
            "account/LamportAccountMock.initcode.hex",
            vm.parseJsonBytes32(json, ".seed"),
            vm.parseJsonBytes32(json, ".root"),
            vm.parseJsonUint(json, ".chainId")
        );
    }

    function _vector(uint256 i) internal view returns (uint256 leaf, bytes32 message, bytes memory sig) {
        string memory k = string.concat(".signatures[", vm.toString(i), "]");
        leaf = vm.parseJsonUint(json, string.concat(k, ".leaf"));
        message = vm.parseJsonBytes32(json, string.concat(k, ".message"));
        sig = vm.parseJsonBytes(json, string.concat(k, ".signature"));
    }

    /// Account signature = seed || root || Lamport signature (epoch 0 tree unless given).
    function _context(uint256 leaf, bytes32 message, bytes memory sig) internal {
        _contextTree(0, seed0, root0, leaf, message, sig);
    }

    function _contextTree(uint256 epoch, bytes32 seed, bytes32 root, uint256 leaf, bytes32 message, bytes memory sig)
        internal
    {
        ctx.setTx(0x0E, 1);
        ctx.setTx(0x01, 0);
        ctx.setTx(0x10, LEAF_KEY_BASE + (epoch << 16) + leaf);
        ctx.setTx(0x08, uint256(message));
        ctx.setSig(0, 0, abi.encodePacked(seed, root, sig));
    }

    function _verifyFrame() internal view returns (bool ok, bytes memory ret) {
        (ok, ret) = account.staticcall(hex"0100");
    }

    function test_approves_valid_signature() public {
        for (uint256 i; i < 6; i++) {
            (uint256 leaf, bytes32 message, bytes memory sig) = _vector(i);
            _context(leaf, message, sig);
            (bool ok, bytes memory ret) = _verifyFrame();
            assertTrue(ok, "verify frame reverted");
            assertEq(bytes32(ret), APPROVED_3);
        }
    }

    function test_rejects_wrong_context() public {
        (uint256 leaf, bytes32 message, bytes memory sig) = _vector(1);
        bool ok;

        _context(leaf, message, sig);
        ctx.setTx(0x10, LEAF_KEY_BASE + leaf + 1); // nonce key of another leaf
        (ok,) = _verifyFrame();
        assertFalse(ok, "key of other leaf");

        _context(leaf, message, sig);
        ctx.setTx(0x01, 1); // key already used once
        (ok,) = _verifyFrame();
        assertFalse(ok, "second use of a key");

        _context(leaf, message, sig);
        ctx.setTx(0x0E, 2); // extra nonce key
        (ok,) = _verifyFrame();
        assertFalse(ok, "two keys");

        _context(leaf, message, sig);
        ctx.setTx(0x10, leaf); // key without the LAMP base
        (ok,) = _verifyFrame();
        assertFalse(ok, "key below base");

        _context(leaf, bytes32(uint256(message) ^ 1), sig); // other transaction hash
        (ok,) = _verifyFrame();
        assertFalse(ok, "other message");

        _context(leaf, message, sig);
        ctx.setSig(0, 1, sig); // not ARBITRARY
        (ok,) = _verifyFrame();
        assertFalse(ok, "scheme");

        bytes memory longer = bytes.concat(sig, hex"00");
        _context(leaf, message, longer);
        (ok,) = _verifyFrame();
        assertFalse(ok, "length");

        sig[100] = bytes1(uint8(sig[100]) ^ 1);
        _context(leaf, message, sig);
        (ok,) = _verifyFrame();
        assertFalse(ok, "tampered");
    }

    /// Legacy nonce mode: the leaf is the legacy nonce (nonce_keys [0] on the devnet, [] in the EIP text).
    function test_legacy_nonce_mode() public {
        address legacy = _deployMode(
            "account/LamportAccountMock.initcode.hex",
            vm.parseJsonBytes32(json, ".seed"),
            vm.parseJsonBytes32(json, ".root"),
            vm.parseJsonUint(json, ".chainId"),
            1
        );
        (uint256 leaf, bytes32 message, bytes memory sig) = _vector(2);
        bool ok;
        bytes memory ret;
        // nonce_keys = [0], nonce_seq = leaf
        _context(leaf, message, sig);
        ctx.setTx(0x10, 0);
        ctx.setTx(0x01, leaf);
        (ok, ret) = legacy.staticcall(hex"0100");
        assertTrue(ok, "legacy [0] rejected");
        assertEq(bytes32(ret), APPROVED_3);
        // nonce_keys = []
        ctx.setTx(0x0E, 0);
        (ok,) = legacy.staticcall(hex"0100");
        assertTrue(ok, "legacy [] rejected");
        // nonce that is not the signed leaf
        ctx.setTx(0x01, leaf + 1);
        (ok,) = legacy.staticcall(hex"0100");
        assertFalse(ok, "other nonce accepted");
        // a keyed nonce on a legacy-mode account
        _context(leaf, message, sig);
        (ok,) = legacy.staticcall(hex"0100");
        assertFalse(ok, "keyed nonce accepted in legacy mode");
        // and the keyed-mode account refuses the legacy form
        _context(leaf, message, sig);
        ctx.setTx(0x10, 0);
        ctx.setTx(0x01, leaf);
        (ok,) = account.staticcall(hex"0100");
        assertFalse(ok, "legacy nonce accepted in keyed mode");
    }

    function test_plain_eth_transfer_accepted() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = account.call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(account.balance, 1 ether);
        (ok,) = account.call(hex"03");
        assertFalse(ok, "unknown entry");
        (ok,) = account.call(hex"02");
        assertFalse(ok, "rotate from outside");
    }

    function _rotate(address a, bytes32 seed, bytes32 root) internal returns (bool ok) {
        vm.prank(a); // a SENDER frame of the account calling itself
        (ok,) = a.call(abi.encodePacked(hex"02", seed, root));
    }

    /// Key rotation: register a second key tree as epoch 1, then sign with it.
    function test_key_rotation() public {
        Packed.Case[] memory cs = Packed.fetchChain("0x726f74", 2, 4, 10, int256(vm.parseJsonUint(json, ".chainId")));
        Packed.Case memory c = cs[0];
        uint256 leaf = uint256(uint32(bytes4(c.sig)));
        bool ok;
        bytes memory ret;

        // Only the account itself may rotate.
        (ok,) = account.call(abi.encodePacked(hex"02", c.key.seed, c.key.root));
        assertFalse(ok, "outsider rotated");
        // Epoch 1 is not registered yet.
        _contextTree(1, c.key.seed, c.key.root, leaf, c.message, c.sig);
        (ok,) = _verifyFrame();
        assertFalse(ok, "unregistered epoch accepted");

        vm.expectEmit(true, false, false, true, account);
        emit Rotated(1, c.key.seed, c.key.root);
        assertTrue(_rotate(account, c.key.seed, c.key.root), "rotation failed");

        _contextTree(1, c.key.seed, c.key.root, leaf, c.message, c.sig);
        (ok, ret) = _verifyFrame();
        assertTrue(ok, "epoch 1 signature rejected");
        assertEq(bytes32(ret), APPROVED_3);
        // The epoch-1 tree is not valid for epoch 0, nor the epoch-0 tree for epoch 1.
        _contextTree(0, c.key.seed, c.key.root, leaf, c.message, c.sig);
        (ok,) = _verifyFrame();
        assertFalse(ok, "epoch-1 tree accepted for epoch 0");
        (uint256 l0, bytes32 m0, bytes memory s0) = _vector(0);
        _contextTree(1, seed0, root0, l0, m0, s0);
        (ok,) = _verifyFrame();
        assertFalse(ok, "epoch-0 tree accepted for epoch 1");
        // Epoch 0 keeps working (rotation adds the next tree; it does not revoke).
        _context(l0, m0, s0);
        (ok,) = _verifyFrame();
        assertTrue(ok, "epoch 0 stopped working");
        // A forged commitment (other root) fails.
        _contextTree(1, c.key.seed, bytes32(uint256(c.key.root) ^ 1), leaf, c.message, c.sig);
        (ok,) = _verifyFrame();
        assertFalse(ok, "wrong root accepted");
        // Epochs only grow by one; a zero seed or root is refused.
        assertFalse(_rotate(account, bytes32(0), c.key.root), "zero seed accepted");
        assertTrue(_rotate(account, cs[1].key.seed, cs[1].key.root), "second rotation failed");
        assertEq(uint256(vm.load(account, bytes32(uint256(1) << 255))), 2);
    }

    /// Legacy mode: nonce n selects epoch n >> 10 and leaf n & 1023.
    function test_key_rotation_legacy() public {
        address legacy = _deployMode("account/LamportAccountMock.initcode.hex", seed0, root0, vm.parseJsonUint(json, ".chainId"), 1);
        Packed.Case[] memory cs = Packed.fetchChain("0x726f744c", 1, 4, 10, int256(vm.parseJsonUint(json, ".chainId")));
        Packed.Case memory c = cs[0];
        uint256 leaf = uint256(uint32(bytes4(c.sig)));
        assertTrue(_rotate(legacy, c.key.seed, c.key.root));
        _contextTree(0, c.key.seed, c.key.root, leaf, c.message, c.sig);
        ctx.setTx(0x10, 0);
        ctx.setTx(0x01, (1 << 10) + leaf);
        (bool ok, bytes memory ret) = legacy.staticcall(hex"0100");
        assertTrue(ok, "legacy epoch 1 rejected");
        assertEq(bytes32(ret), APPROVED_3);
        ctx.setTx(0x01, leaf); // same leaf index, epoch 0: other tree, must fail
        (ok,) = legacy.staticcall(hex"0100");
        assertFalse(ok, "epoch-1 signature accepted at epoch 0");
    }

    event Rotated(uint256 indexed epoch, bytes32 seed, bytes32 root);

    /// Gas of the VERIFY frame code on the test build. Includes the mock context calls
    /// (about a dozen STATICCALLs), so it is higher than the real frame would be.
    function test_gas_verify_frame_mock() public {
        (uint256 leaf, bytes32 message, bytes memory sig) = _vector(0);
        _context(leaf, message, sig);
        uint256 g0 = gasleft();
        (bool ok,) = _verifyFrame();
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        vm.serializeUint("account", "verifyFrameMockGas", used);
        string memory out = vm.serializeString(
            "account", "note", "test build with FrameContextMock; includes mock STATICCALL overhead; not the real frame gas"
        );
        vm.writeJson(out, "../results/account_mock_gas.json");
    }

    /// VERIFY frame execution gas on the bench build (context from calldata, same algorithm and
    /// memory layout as the real build). The account is warmed first, as tx.sender is warm in a
    /// frame transaction (EIP-8141 Behavior). Measured over 64 random keys and messages.
    /// Hash steps the verifier performs for this signature: sum over all 67 chains of 15 - digit.
    function _steps(LamportVerifier.Key memory key, uint256 leaf, bytes32 message) internal pure returns (uint256 steps) {
        uint256 d = uint256(LamportVerifier.messageDigest(key, leaf, message));
        uint256 sum;
        for (uint256 i; i < 64; i++) {
            uint256 digit = (d >> (252 - 4 * i)) & 15;
            sum += digit;
            steps += 15 - digit;
        }
        uint256 checksum = 960 - sum;
        for (uint256 k; k < 3; k++) steps += 15 - ((checksum >> (4 * (2 - k))) & 15);
    }

    function test_gas_verify_frame_bench() public {
        Packed.Case[] memory cases = Packed.fetch("0x62656e6368", 128, 4, 10);
        uint256 lo = type(uint256).max;
        uint256 hi;
        uint256 sum;
        uint256[] memory stepsList = new uint256[](cases.length);
        uint256[] memory gasList = new uint256[](cases.length);
        for (uint256 i; i < cases.length; i++) {
            Packed.Case memory c = cases[i];
            address a = _deploy("account/LamportAccountBench.initcode.hex", c.key.seed, c.key.root, c.key.chainId);
            uint256 leaf = uint256(uint32(bytes4(c.sig)));
            bytes memory acctSig = abi.encodePacked(c.key.seed, c.key.root, c.sig);
            bytes memory data = abi.encodePacked(
                hex"0100", uint256(0), c.message, uint256(1), LEAF_KEY_BASE + leaf, uint256(0), acctSig.length, acctSig
            );
            vm.cool(a); // the commitment slot was written at deploy in this test transaction; make it cold as on chain
            (bool warm,) = a.staticcall(""); // warm the account (not its storage) like tx.sender
            assertTrue(warm);
            uint256 g0 = gasleft();
            (bool ok, bytes memory ret) = a.staticcall(data);
            uint256 used = g0 - gasleft();
            assertTrue(ok, "bench verify reverted");
            assertEq(bytes32(ret), APPROVED_3);
            data[300] = bytes1(uint8(data[300]) ^ 1); // inside the signature
            (bool bad,) = a.staticcall(data);
            assertFalse(bad, "tampered signature approved");
            stepsList[i] = _steps(c.key, leaf, c.message);
            gasList[i] = used;
            if (used < lo) lo = used;
            if (used > hi) hi = used;
            sum += used;
        }
        vm.serializeUint("bench", "steps", stepsList);
        vm.serializeUint("bench", "gas", gasList);
        assertLt(sum / cases.length, ACCOUNT_BENCH_MEAN_LIMIT, "account VERIFY gas regression");
        vm.serializeUint("bench", "samples", cases.length);
        vm.serializeUint("bench", "min", lo);
        vm.serializeUint("bench", "max", hi);
        vm.serializeUint("bench", "mean", sum / cases.length);
        string memory out = vm.serializeString(
            "bench",
            "note",
            "VERIFY frame code of LamportAccount (bench build: context from calldata). Includes the warm STATICCALL (100). Excludes frame-level intrinsic costs."
        );
        vm.writeJson(out, "../results/account_bench_gas.json");
    }
}
