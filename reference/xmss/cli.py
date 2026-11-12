#!/usr/bin/env python3
"""Profile B test signer: XMSS keys and signatures in the layout LamportXmssVerifier reads.

  python3 cli.py keygen <height> <out.json>        random test key (TEST ONLY)
  python3 cli.py sign <key.json> <leaf> <digest>   prints hex: uint32 leaf | r | wots[67] | auth[h]

Uses the vendored Skale reference (xmss_ref.py, MIT). Leaf selection and reuse refusal are the
caller's job (signer/src/signer.ts reads spent leaves from chain); this tool signs what it is told.
"""
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xmss_ref as x  # noqa: E402


def load(path: str):
    with open(path) as f:
        k = json.load(f)
    seed, sk_seed, sk_prf = (bytes.fromhex(k[n][2:]) for n in ("seed", "skSeed", "skPrf"))
    levels = x.build_tree(k["height"], sk_seed, seed)
    if "root" in k and levels[-1][0].hex() != k["root"][2:]:
        sys.exit("key file root does not match the rebuilt tree")
    return k, seed, sk_seed, sk_prf, levels


def main() -> None:
    cmd = sys.argv[1]
    if cmd == "keygen":
        h, out = int(sys.argv[2]), sys.argv[3]
        k = {"warning": "TEST KEY ONLY. Never use with real funds.", "height": h,
             "seed": "0x" + secrets.token_bytes(32).hex(), "skSeed": "0x" + secrets.token_bytes(32).hex(),
             "skPrf": "0x" + secrets.token_bytes(32).hex()}
        levels = x.build_tree(h, bytes.fromhex(k["skSeed"][2:]), bytes.fromhex(k["seed"][2:]))
        k["root"] = "0x" + levels[-1][0].hex()
        with open(out, "w") as f:
            json.dump(k, f, indent=1)
        os.chmod(out, 0o600)
        print(json.dumps({"root": k["root"], "seed": k["seed"], "height": h}))
    elif cmd == "sign":
        k, seed, sk_seed, sk_prf, levels = load(sys.argv[2])
        idx, digest = int(sys.argv[3]), bytes.fromhex(sys.argv[4].removeprefix("0x"))
        r, ots, auth = x.sign(digest, idx, levels, sk_seed, sk_prf, seed)
        assert x.verify(digest, idx, r, ots, auth, levels[-1][0], seed)
        sys.stdout.write("0x" + (idx.to_bytes(4, "big") + r + b"".join(ots) + b"".join(auth)).hex())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
