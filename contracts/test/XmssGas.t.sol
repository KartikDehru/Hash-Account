// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {XMSS} from "../src/xmss/XMSS.sol";

/// Profile B: Skale's XMSS verifier measured in the same harness and settings as Profile A.
contract XmssProbe {
    function measure(bytes32 m, XMSS.Signature calldata sigIn, XMSS.PublicKey calldata pk, uint256 h)
        external
        view
        returns (uint256 used, bool ok)
    {
        XMSS.PublicKey memory key = pk;
        uint256 g0 = gasleft();
        XMSS.Signature memory sig = sigIn;
        ok = XMSS.verify(m, sig, key, h);
        used = g0 - gasleft();
    }
}

contract XmssGasTest is Test {
    XmssProbe internal probe = new XmssProbe();

    function _load(string memory file, uint256 i)
        internal
        view
        returns (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk, uint256 h)
    {
        string memory json = vm.readFile(string.concat("test/vectors/xmss/", file));
        pk.root = vm.parseJsonBytes32(json, ".root");
        pk.seed = vm.parseJsonBytes32(json, ".seed");
        h = vm.parseJsonUint(json, ".h");
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        sig.leafIdx = uint32(vm.parseJsonUint(json, string.concat(base, ".idx")));
        sig.r = vm.parseJsonBytes32(json, string.concat(base, ".r"));
        m = vm.parseJsonBytes32(json, string.concat(base, ".msg"));
        bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(base, ".wotsSig"));
        for (uint256 k = 0; k < 67; ++k) sig.wotsSig[k] = w[k];
        sig.authPath = vm.parseJsonBytes32Array(json, string.concat(base, ".auth"));
    }

    function _measure(string memory file) internal returns (string memory out) {
        uint256 lo = type(uint256).max;
        uint256 hi;
        uint256 sum;
        uint256 h;
        for (uint256 i; i < 4; i++) {
            (bytes32 m, XMSS.Signature memory sig, XMSS.PublicKey memory pk, uint256 hh) = _load(file, i);
            h = hh;
            (uint256 used, bool ok) = probe.measure(m, sig, pk, hh);
            assertTrue(ok, "vector rejected");
            m = bytes32(uint256(m) ^ 1);
            (, bool bad) = probe.measure(m, sig, pk, hh);
            assertFalse(bad, "changed message accepted");
            if (used < lo) lo = used;
            if (used > hi) hi = used;
            sum += used;
        }
        vm.serializeUint(file, "height", h);
        vm.serializeUint(file, "samples", 4);
        vm.serializeUint(file, "signatureBytes", 4 + 32 * (68 + h));
        vm.serializeUint(file, "min", lo);
        vm.serializeUint(file, "max", hi);
        out = vm.serializeUint(file, "mean", sum / 4);
    }

    function test_xmss_gas_report() public {
        vm.serializeString("xmss", "h10", _measure("xmss_h10.json"));
        string memory out = vm.serializeString("xmss", "h20", _measure("xmss_h20.json"));
        out = vm.serializeString("xmss", "source", "skalenetwork/xmss-solidity@749593d, vendored, unchanged");
        vm.writeJson(out, "../results/xmss_gas_raw.json");
    }
}
