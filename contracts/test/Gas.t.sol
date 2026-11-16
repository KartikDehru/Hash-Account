// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LamportVerifier} from "../src/LamportVerifier.sol";
import {GasProbe} from "./GasProbe.sol";
import {Packed} from "./Packed.sol";

/// Writes measured gas per phase to ../results/gas_raw.json. Run by scripts/gas_report.py.
/// Gas depends on the message digits, so each parameter set is measured on SAMPLES random
/// messages and min, mean and max are recorded.
contract GasTest is Test {
    uint256 internal constant SAMPLES = 64;
    uint256 internal constant HEIGHT = 10;
    // Profile A regression bound for the library call (mean). Raise only with a recorded reason.
    uint256 internal constant PROFILE_A_MEAN_LIMIT = 62_000;

    GasProbe internal probe = new GasProbe();

    struct Stats {
        uint256 min;
        uint256 max;
        uint256 sum;
    }

    function _add(Stats memory s, uint256 v) internal pure {
        if (s.min == 0 || v < s.min) s.min = v;
        if (v > s.max) s.max = v;
        s.sum += v;
    }

    function _json(string memory key, Stats memory s) internal returns (string memory) {
        vm.serializeUint(key, "min", s.min);
        vm.serializeUint(key, "max", s.max);
        return vm.serializeUint(key, "mean", s.sum / SAMPLES);
    }

    function _measure(uint256 logW) internal returns (string memory out, uint256 meanFull) {
        Packed.Case[] memory cases =
            Packed.fetch(string.concat("0x6761", vm.toString(logW)), SAMPLES, logW, int256(HEIGHT));
        Stats[6] memory st;
        for (uint256 i; i < SAMPLES; i++) {
            GasProbe.Phases memory p = probe.phases(cases[i].key, cases[i].message, cases[i].sig);
            assertTrue(p.ok, "probe failed to verify");
            (uint256 used, bool ok) = probe.full(cases[i].key, cases[i].message, cases[i].sig);
            assertTrue(ok);
            _add(st[0], p.copy);
            _add(st[1], p.digest);
            _add(st[2], p.chains);
            _add(st[3], p.path);
            _add(st[4], p.total);
            _add(st[5], used);
        }
        string memory k = string.concat("logW", vm.toString(logW));
        vm.serializeUint(k, "logW", logW);
        vm.serializeUint(k, "height", HEIGHT);
        vm.serializeUint(k, "samples", SAMPLES);
        vm.serializeUint(k, "signatureBytes", cases[0].sig.length);
        vm.serializeString(k, "copy", _json(string.concat(k, "copy"), st[0]));
        vm.serializeString(k, "digest", _json(string.concat(k, "digest"), st[1]));
        vm.serializeString(k, "chains", _json(string.concat(k, "chains"), st[2]));
        vm.serializeString(k, "path", _json(string.concat(k, "path"), st[3]));
        vm.serializeString(k, "phaseSum", _json(string.concat(k, "phaseSum"), st[4]));
        out = vm.serializeString(k, "fullCall", _json(string.concat(k, "fullCall"), st[5]));
        meanFull = st[5].sum / SAMPLES;
    }

    function test_gas_report() public {
        string memory root = "gas";
        uint256[4] memory ws = [uint256(1), 2, 4, 8];
        string memory out;
        for (uint256 i; i < ws.length; i++) {
            (string memory part, uint256 meanFull) = _measure(ws[i]);
            out = vm.serializeString(root, string.concat("logW", vm.toString(ws[i])), part);
            if (ws[i] == 4) assertLt(meanFull, PROFILE_A_MEAN_LIMIT, "Profile A gas regression");
        }
        out = vm.serializeString(root, "solc", "0.8.37 via-IR, optimizer 200 runs, evm prague");
        out = vm.serializeString(root, "measuredWith", "forge test --match-test test_gas_report (GasProbe, gasleft deltas)");
        vm.writeJson(out, "../results/gas_raw.json");
    }
}
