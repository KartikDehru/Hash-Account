import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from admit import check, load_rules  # noqa: E402

R = load_rules()
SENDER = "0x00000000000000000000000000000000000000a1"


def tx(verify_limit, opcodes=(), reads=("sender",), deploy_limit=None, keys=(7,)):
    frames = []
    if deploy_limit is not None:
        frames.append({"mode": 0, "flags": 0, "target": "0x00000000000000000000000000000000000000f0",
                       "limits": {"execution": deploy_limit, "state": 100000}, "trace": {"stateWrites": 1}})
    frames.append({"mode": 1, "flags": 3, "target": "sender", "limits": {"execution": verify_limit, "state": 0},
                   "trace": {"opcodes": list(opcodes), "storageReads": list(reads)}})
    frames.append({"mode": 2, "flags": 0, "target": SENDER, "limits": {"execution": 50000, "state": 0}})
    return {"name": "t", "sender": SENDER, "nonceKeys": list(keys), "frames": frames,
            "signatures": [{"scheme": 0, "bytes": 2468, "msgEmpty": True}]}


def verdict(rep, side="public"):
    return rep.verdict(getattr(rep, side))


def test_small_self_verify_accepted():
    rep = check(tx(80000), R)
    assert rep.shape == ["self_verify"]
    assert verdict(rep) == "ACCEPTED"


def test_cap_counts_signature_verification_cost():
    assert verdict(check(tx(99900), R)) == "ACCEPTED"
    assert verdict(check(tx(99901), R)) == "REFUSED"


def test_heavy_verify_refused_public_unknown_alt_without_budget():
    rep = check(tx(750000), R)
    assert verdict(rep) == "REFUSED"
    assert verdict(rep, "alt") == "UNKNOWN"
    assert verdict(check(tx(750000), R, alt_budget=1_000_000), "alt") == "ACCEPTED"


def test_deploy_limit_counts_toward_cap():
    assert verdict(check(tx(80000, deploy_limit=30000), R)) == "REFUSED"
    assert check(tx(60000, deploy_limit=30000), R).shape == ["deploy", "self_verify"]


def test_banned_opcode_and_foreign_storage_refused():
    assert verdict(check(tx(50000, opcodes=["TIMESTAMP"]), R)) == "REFUSED"
    assert verdict(check(tx(50000, reads=["0x00000000000000000000000000000000000000b2"]), R)) == "REFUSED"


def test_nonce_keys_rules():
    assert verdict(check(tx(50000, keys=(0, 5)), R)) == "REFUSED"
    assert verdict(check(tx(50000, keys=(5, 3)), R)) == "REFUSED"
    assert verdict(check(tx(50000, keys=tuple(range(1, 18))), R)) == "REFUSED"
