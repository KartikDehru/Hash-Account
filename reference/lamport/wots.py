"""Winternitz one-time signatures over the tweakable hash."""
from .hashing import chain_step, h, leaf_pk, message_digest
from .params import Params


def digits(p: Params, digest: bytes) -> list[int]:
    """Message digits (most significant first) followed by checksum digits."""
    value = int.from_bytes(digest, "big")
    mask = p.w - 1
    out = [(value >> (256 - p.log_w * (i + 1))) & mask for i in range(p.len1)]
    checksum = sum(mask - d for d in out)
    out += [(checksum >> (p.log_w * (p.len2 - 1 - k))) & mask for k in range(p.len2)]
    return out


def chain(seed: bytes, chain_id: int, leaf: int, index: int, x: bytes, start: int, end: int) -> bytes:
    """Walk a chain from position `start` to `end`.

    Step 0 is the tweakable hash (seed, leaf, chain index). Every later step is
    keccak256 of the 32-byte value alone, which is what the verifier spends its
    gas on. The checksum still stops a walk to a higher digit.
    """
    for step in range(start, end):
        x = chain_step(seed, chain_id, leaf, index, 0, x) if step == 0 else h(x)
    return x


def secret_start(sk_seed: bytes, leaf: int, index: int) -> bytes:
    return h(b"LAMPORT-SK" + sk_seed + leaf.to_bytes(4, "big") + index.to_bytes(4, "big"))


def keygen_leaf(p: Params, sk_seed: bytes, seed: bytes, chain_id: int, leaf: int) -> bytes:
    """Compressed public key (tree leaf) of one-time key `leaf`."""
    ends = [
        chain(seed, chain_id, leaf, i, secret_start(sk_seed, leaf, i), 0, p.w - 1)
        for i in range(p.length)
    ]
    return leaf_pk(seed, chain_id, leaf, p.log_w, ends)


def sign_leaf(p: Params, sk_seed: bytes, seed: bytes, chain_id: int, leaf: int, message: bytes) -> list[bytes]:
    ds = digits(p, message_digest(seed, chain_id, leaf, p.log_w, message))
    return [chain(seed, chain_id, leaf, i, secret_start(sk_seed, leaf, i), 0, d) for i, d in enumerate(ds)]


def leaf_from_signature(p: Params, seed: bytes, chain_id: int, leaf: int, message: bytes, values: list[bytes]) -> bytes:
    """Recompute the compressed public key from a one-time signature."""
    if len(values) != p.length:
        raise ValueError("wrong number of chain values")
    ds = digits(p, message_digest(seed, chain_id, leaf, p.log_w, message))
    ends = [chain(seed, chain_id, leaf, i, v, d, p.w - 1) for i, (v, d) in enumerate(zip(values, ds))]
    return leaf_pk(seed, chain_id, leaf, p.log_w, ends)
