"""Command line entry points (demo, vectors, Foundry FFI)."""
import argparse
import json
import os
import random
import sys

from .hashing import h
from .params import PROFILE_A, Params
from .tree import KeyTree, encode_signature, root_from_path, verify
from .wots import keygen_leaf, sign_leaf

MUTATIONS = ("sig_value", "sig_path", "leaf_index", "message", "root", "chain_id", "seed", "length")


def random_case(rng: random.Random, log_w: int, height: int, chain_id: int | None = None) -> dict:
    """A valid signature on a random message, with random siblings on the path.

    Path siblings are plain data to the verifier, so random siblings give the same
    coverage of the verifier as a full tree, at a fraction of the key generation cost.
    """
    p = Params(log_w=log_w, height=height)
    rb = lambda n: bytes(rng.getrandbits(8) for _ in range(n))  # noqa: E731
    sk_seed, seed, message = rb(32), rb(32), rb(32)
    chain_id = rng.getrandbits(64) if chain_id is None else chain_id
    leaf = rng.randrange(p.leaves)
    values = sign_leaf(p, sk_seed, seed, chain_id, leaf, message)
    path = [rb(32) for _ in range(height)]
    node = keygen_leaf(p, sk_seed, seed, chain_id, leaf)
    root = root_from_path(p, seed, chain_id, leaf, node, path)
    sig = encode_signature(p, leaf, values, path)
    assert verify(p, seed, root, chain_id, message, sig)
    return {"p": p, "seed": seed, "root": root, "chain_id": chain_id, "message": message, "sig": sig}


def mutate(rng: random.Random, case: dict) -> dict:
    p: Params = case["p"]
    m = dict(case)
    kind = rng.choice(MUTATIONS)
    sig = bytearray(case["sig"])
    flip = lambda b: b ^ (1 << rng.randrange(8))  # noqa: E731
    if kind == "sig_value":
        i = 4 + rng.randrange(32 * p.length)
        sig[i] = flip(sig[i])
    elif kind == "sig_path":
        if p.height == 0:
            kind = "leaf_index"
        else:
            i = 4 + 32 * p.length + rng.randrange(32 * p.height)
            sig[i] = flip(sig[i])
    if kind == "leaf_index":
        i = rng.randrange(4)
        sig[i] = flip(sig[i])
    elif kind == "message":
        msg = bytearray(case["message"])
        i = rng.randrange(32)
        msg[i] = flip(msg[i])
        m["message"] = bytes(msg)
    elif kind == "root":
        m["root"] = h(case["root"])
    elif kind == "chain_id":
        m["chain_id"] = case["chain_id"] ^ (1 << rng.randrange(64))
    elif kind == "seed":
        m["seed"] = h(case["seed"])
    elif kind == "length":
        sig = sig[:-1] if rng.random() < 0.5 else sig + b"\x00"
    m["sig"] = bytes(sig)
    m["kind"] = kind
    return m


def pack_case(case: dict, bad: dict) -> bytes:
    """Fixed layout read by contracts/test/Differential.t.sol."""
    p: Params = case["p"]
    out = bytes([p.log_w, p.height]) + case["chain_id"].to_bytes(8, "big") + case["seed"] + case["root"] + case["message"]
    out += bad["chain_id"].to_bytes(8, "big") + bad["seed"] + bad["root"] + bad["message"]
    out += len(case["sig"]).to_bytes(2, "big") + case["sig"] + len(bad["sig"]).to_bytes(2, "big") + bad["sig"]
    return out


def cmd_batch(args) -> None:
    rng = random.Random(int(args.seed, 16))
    blobs = []
    for _ in range(args.count):
        log_w = args.log_w if args.log_w else rng.choice((1, 2, 4, 4, 4, 8))
        height = args.height if args.height is not None else rng.choice((0, 1, 5, 10, 10))
        case = random_case(rng, log_w, height, args.chain_id)
        bad = mutate(rng, case)
        if verify(bad["p"], bad["seed"], bad["root"], bad["chain_id"], bad["message"], bad["sig"]):
            sys.exit(f"reference accepted a mutated signature ({bad['kind']})")
        blob = pack_case(case, bad)
        blobs.append(len(blob).to_bytes(4, "big") + blob)
    sys.stdout.write("0x" + (len(blobs).to_bytes(4, "big") + b"".join(blobs)).hex())


def tree_vector(p: Params, sk_seed: bytes, seed: bytes, chain_id: int, leaves: list[int]) -> dict:
    tree = KeyTree(p, sk_seed, seed, chain_id)
    sigs = []
    for leaf in leaves:
        message = h(b"vector message" + leaf.to_bytes(4, "big"))
        sig = tree.sign_with_leaf(leaf, message)
        assert verify(p, seed, tree.root, chain_id, message, sig)
        sigs.append({"leaf": leaf, "message": "0x" + message.hex(), "signature": "0x" + sig.hex()})
    return {
        "logW": p.log_w, "height": p.height, "chainId": chain_id,
        "skSeed": "0x" + sk_seed.hex(), "seed": "0x" + seed.hex(), "root": "0x" + tree.root.hex(),
        "signatures": sigs,
    }


def cmd_vectors(args) -> None:
    os.makedirs(args.out, exist_ok=True)
    sk_seed, seed = h(b"lamport test sk seed (public, test only)"), h(b"lamport test public seed")
    sets = {
        "profile_a_h10.json": (PROFILE_A, [0, 1, 2, 511, 512, 1023]),
        "w4_h4.json": (Params(log_w=2, height=4), [0, 7, 15]),
        "w256_h2.json": (Params(log_w=8, height=2), [0, 3]),
        "w2_h1.json": (Params(log_w=1, height=1), [0, 1]),
    }
    for name, (p, leaves) in sets.items():
        vec = tree_vector(p, sk_seed, seed, 1337, leaves)
        with open(os.path.join(args.out, name), "w") as f:
            json.dump(vec, f, indent=1)
            f.write("\n")
        print(f"wrote {name}: root {vec['root']}")


def cmd_demo(_args) -> None:
    from .attack import TOY, try_forge
    from .signer import LeafReuseError, Signer

    class DemoChainState:
        """In-process stand-in for chain state, used only by this demo. Not a network result."""
        def __init__(self) -> None:
            self.spent: set[int] = set()
        def is_spent(self, leaf: int) -> bool:
            return leaf in self.spent
        def is_pending(self, leaf: int) -> bool:
            return False

    p = Params(log_w=4, height=4)
    print(f"Key tree: w={p.w}, height={p.height} ({p.leaves} one-time keys), signature {p.sig_bytes} bytes")
    tree = KeyTree(p, os.urandom(32), os.urandom(32), 1337)
    state = DemoChainState()
    signer = Signer(tree, state)
    for i in range(3):
        message = h(b"demo transaction %d" % i)
        leaf, sig = signer.sign(message)
        ok = verify(p, tree.seed, tree.root, 1337, message, sig)
        state.spent.add(leaf)
        print(f"  signed with leaf {leaf}: verify={ok}")
    try:
        signer.sign_with_leaf(0, h(b"second message for leaf 0"))
    except LeafReuseError as e:
        print(f"  second signature on leaf 0 refused: {e}")
    toy = KeyTree(TOY, os.urandom(32), os.urandom(32), 1337)
    one = [(m, toy.sign_with_leaf(0, m)) for m in (os.urandom(32),)]
    two = one + [(m, toy.sign_with_leaf(0, m)) for m in (os.urandom(32),)]
    r1 = try_forge(TOY, toy, 0, one, 20000)
    r2 = try_forge(TOY, toy, 0, two, 20000)
    print(f"Toy parameters (16-bit digits): forgery after one signature: {r1.forged} ({r1.tries} tries)")
    print(f"Toy parameters (16-bit digits): forgery after two signatures on one leaf: {r2.forged} ({r2.tries} tries)")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="python -m lamport.cli")
    sub = ap.add_subparsers(required=True)
    b = sub.add_parser("batch", help="random valid and mutated cases for the Foundry differential test")
    b.add_argument("seed")
    b.add_argument("count", type=int)
    b.add_argument("--log-w", type=int, default=0)
    b.add_argument("--height", type=int, default=None)
    b.add_argument("--chain-id", type=int, default=None, help="fixed chain id (default: random per case)")
    b.set_defaults(fn=cmd_batch)
    v = sub.add_parser("vectors", help="write full-tree test vectors")
    v.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "vectors"))
    v.set_defaults(fn=cmd_vectors)
    d = sub.add_parser("demo", help="sign, verify, refuse reuse, toy forgery")
    d.set_defaults(fn=cmd_demo)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
