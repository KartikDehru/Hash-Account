"""Stand-in attacker: forgery after one leaf signs two messages (toy parameters).

With toy parameters (16-bit message digits) a forgery is found quickly once a leaf has
signed two different messages. The same attack applies at full size; it only needs more
tries. This is why the signer refuses to sign twice with one leaf.
"""
import os
from dataclasses import dataclass

from .hashing import message_digest
from .params import Params
from .tree import KeyTree, decode_signature, encode_signature, verify
from .wots import chain, digits

TOY = Params(log_w=4, height=0, msg_bits=16)


@dataclass
class ForgeryResult:
    forged: bool
    tries: int
    message: bytes | None = None
    signature: bytes | None = None


def known_positions(p: Params, tree: KeyTree, leaf: int, signed: list[tuple[bytes, bytes]]) -> list[tuple[int, bytes]]:
    """For each chain, the lowest position the attacker knows and its value."""
    best: list[tuple[int, bytes] | None] = [None] * p.length
    for message, sig in signed:
        _, values, _ = decode_signature(p, sig)
        ds = digits(p, message_digest(tree.seed, tree.chain_id, leaf, p.log_w, message))
        for i, (d, v) in enumerate(zip(ds, values)):
            if best[i] is None or d < best[i][0]:
                best[i] = (d, v)
    return best  # type: ignore[return-value]


def try_forge(p: Params, tree: KeyTree, leaf: int, signed: list[tuple[bytes, bytes]], max_tries: int,
              rng=os.urandom) -> ForgeryResult:
    known = known_positions(p, tree, leaf, signed)
    signed_messages = {m for m, _ in signed}
    for t in range(1, max_tries + 1):
        message = rng(32)
        if message in signed_messages:
            continue
        ds = digits(p, message_digest(tree.seed, tree.chain_id, leaf, p.log_w, message))
        if all(d >= k[0] for d, k in zip(ds, known)):
            values = [chain(tree.seed, tree.chain_id, leaf, i, v, k, d) for i, (d, (k, v)) in enumerate(zip(ds, known))]
            sig = encode_signature(p, leaf, values, tree.path(leaf))
            assert verify(p, tree.seed, tree.root, tree.chain_id, message, sig)
            return ForgeryResult(True, t, message, sig)
    return ForgeryResult(False, max_tries)
