#!/usr/bin/env python3
"""Admission simulator for EIP-8141 frame transactions.

It checks a transaction description plus a validation trace against the public-mempool
rules of the EIP-8141 draft and, where values are known, against an alternative-mempool
budget. It does not execute EVM code: gas used, opcodes and storage accesses come from a
trace (from Foundry measurements or from a client such as ethrex). Every rule value comes
from simulator/rules.json.

Input (JSON):
{
  "name": "...",
  "sender": "0x..",
  "nonceKeys": [int, ...],            # [] or omitted = legacy nonce
  "frames": [{"mode": 0|1|2, "flags": int, "target": "sender"|"0x..",
              "limits": {"execution": int, "state": int},
              "trace": {"opcodes": [...], "storageReads": ["sender"|"0x.."], "stateWrites": int}}],
  "signatures": [{"scheme": 0|1|2, "bytes": int, "msgEmpty": true}]
}
Usage: python3 simulator/admit.py case.json [--alt-budget N]
"""
import argparse
import json
import os
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
EXPIRY_VERIFIER = "0x81413f0cf12e9b6a49b1d0439e081c577d57ffff"
DEFAULT, VERIFY, SENDER = 0, 1, 2
SCHEME_GAS_KEY = {0: "SIG_GAS_ARBITRARY", 1: "SIG_GAS_SECP256K1", 2: "SIG_GAS_P256"}


def load_rules(path: str | None = None) -> dict:
    with open(path or os.path.join(HERE, "rules.json")) as f:
        return {k: v["value"] for k, v in json.load(f).items() if not k.startswith("_")}


@dataclass
class Check:
    rule: str
    ok: bool | None  # None = cannot decide (value unknown)
    detail: str


@dataclass
class Report:
    name: str
    shape: list[str]
    public: list[Check] = field(default_factory=list)
    alt: list[Check] = field(default_factory=list)

    @staticmethod
    def verdict(checks: list[Check]) -> str:
        if any(c.ok is False for c in checks):
            return "REFUSED"
        if any(c.ok is None for c in checks):
            return "UNKNOWN"
        return "ACCEPTED"

    def as_dict(self) -> dict:
        conv = lambda cs: [c.__dict__ for c in cs]  # noqa: E731
        return {"name": self.name, "shape": self.shape,
                "public": {"verdict": self.verdict(self.public), "checks": conv(self.public)},
                "alt": {"verdict": self.verdict(self.alt), "checks": conv(self.alt)}}


def is_sender(tx: dict, target) -> bool:
    return target in (None, "sender") or str(target).lower() == str(tx.get("sender", "")).lower()


def classify(tx: dict) -> tuple[list[str], int]:
    """Names of the validation-prefix frames and the index of the payment approval (-1 if none)."""
    names = []
    for i, fr in enumerate(tx["frames"]):
        scope = fr.get("flags", 0) & 3
        target = str(fr.get("target", "sender")).lower()
        if fr["mode"] == VERIFY and target == EXPIRY_VERIFIER:
            names.append("expiry_verify")
        elif fr["mode"] == DEFAULT and i == 0:
            names.append("deploy")
        elif fr["mode"] == VERIFY and is_sender(tx, fr.get("target")) and scope == 3:
            names.append("self_verify")
            return names, i
        elif fr["mode"] == VERIFY and is_sender(tx, fr.get("target")) and scope == 2:
            names.append("only_verify")
        elif fr["mode"] == VERIFY and scope & 1:
            names.append("pay")
            return names, i
        else:
            names.append(f"other(mode={fr['mode']},scope={scope})")
    return names, -1


def check(tx: dict, rules: dict, alt_budget: int | None = None) -> Report:
    names, pay_idx = classify(tx)
    prefix = tx["frames"][: pay_idx + 1] if pay_idx >= 0 else tx["frames"]
    rep = Report(tx.get("name", "tx"), names)
    shape = [n for n in names if n != "expiry_verify"]
    expiry_ok = "expiry_verify" not in names or names.index("expiry_verify") == 0

    known = [list(s) for s in rules["PUBLIC_PREFIX_SHAPES"]]
    rep.public.append(Check("prefix-shape", pay_idx >= 0 and shape in known and expiry_ok,
                            f"prefix {names}; recognised shapes {known}"))

    sig_gas = sum(rules[SCHEME_GAS_KEY[s["scheme"]]] for s in tx.get("signatures", []))
    exec_sum = sum(fr["limits"]["execution"] for fr in prefix)
    state_sum = sum(fr["limits"].get("state", 0) for fr in prefix)
    sig_bytes = sum(s.get("bytes", 0) for s in tx.get("signatures", []))
    counted = exec_sum + sig_gas
    note = "" if not rules["SIGNATURE_BYTES_COUNT_TOWARD_MAX_VERIFY_GAS"] else f" + signature bytes {sig_bytes}"
    if rules["SIGNATURE_BYTES_COUNT_TOWARD_MAX_VERIFY_GAS"]:
        counted += rules["STANDARD_TOKEN_COST"] * rules["TOKENS_PER_NONZERO_BYTE"] * sig_bytes
    rep.public.append(Check("max-verify-gas", counted <= rules["MAX_VERIFY_GAS"],
                            f"declared prefix execution limits {exec_sum} + signature verification {sig_gas}{note} "
                            f"= {counted} vs cap {rules['MAX_VERIFY_GAS']}"))
    rep.public.append(Check("max-verify-state-gas", state_sum <= rules["MAX_VERIFY_STATE_GAS"],
                            f"declared prefix state limits {state_sum} vs cap {rules['MAX_VERIFY_STATE_GAS']}"))

    banned = set(rules["PUBLIC_BANNED_OPCODES"])
    used_banned = []
    for i, fr in enumerate(prefix):
        ops = set(fr.get("trace", {}).get("opcodes", []))
        bad = ops & banned
        if names[i] == "expiry_verify":
            bad -= {"TIMESTAMP"}
        used_banned += sorted(bad)
    rep.public.append(Check("banned-opcodes", not used_banned, f"banned opcodes used: {used_banned or 'none'}"))

    outside = sorted({r for fr in prefix for r in fr.get("trace", {}).get("storageReads", []) if not is_sender(tx, r)})
    rep.public.append(Check("storage-reads", not outside, f"storage read outside tx.sender: {outside or 'none'}"))

    writes = [i for i, fr in enumerate(prefix) if fr.get("trace", {}).get("stateWrites", 0) and names[i] != "deploy"]
    rep.public.append(Check("state-writes", not writes, f"state writes outside the deploy frame in frames {writes or 'none'}"))

    gas_used = [fr.get("trace", {}).get("gasUsed") for fr in prefix]
    within = all(u is None or u <= fr["limits"]["execution"] for u, fr in zip(gas_used, prefix))
    rep.public.append(Check("frames-within-limits", within, f"traced gas used {gas_used}"))

    keys = tx.get("nonceKeys", [])
    keys_ok = (len(keys) <= rules["MAX_NONCE_KEYS"] and keys == sorted(set(keys))
               and (0 not in keys or keys == [0]))
    rep.public.append(Check("nonce-keys", keys_ok, f"{len(keys)} keys, strictly increasing and key 0 alone: {keys_ok}"))

    # Alternative mempool: same structural checks, but the validation budget is the alt budget,
    # and the shape and storage rules are replaced by staking and reputation rules we cannot see here.
    budget = alt_budget if alt_budget is not None else rules.get("ALT_MEMPOOL_MAX_VERIFY_GAS")
    rep.alt.append(Check("payer-approved", pay_idx >= 0, "a frame approves payment"))
    rep.alt.append(Check("frames-within-limits", within, f"traced gas used {gas_used}"))
    rep.alt.append(Check("nonce-keys", keys_ok, "same as public"))
    if budget is None:
        rep.alt.append(Check("alt-verify-budget", None, f"prefix needs {counted}; alt-mempool budget unknown (OPEN_QUESTIONS Q3)"))
    else:
        rep.alt.append(Check("alt-verify-budget", counted <= budget, f"prefix needs {counted} vs alt budget {budget}"))
    return rep


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    ap.add_argument("--alt-budget", type=int, default=None)
    args = ap.parse_args()
    with open(args.case) as f:
        tx = json.load(f)
    rep = check(tx, load_rules(), args.alt_budget)
    json.dump(rep.as_dict(), sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
