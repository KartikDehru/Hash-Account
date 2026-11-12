"""Tweakable hash with a public seed and an address word (see SPEC.md)."""
from Crypto.Hash import keccak

CHAIN = 1
LEAF_PK = 2
TREE = 3
MSG = 4


def h(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def adrs(kind: int, chain_id: int, a: int = 0, b: int = 0, c: int = 0) -> bytes:
    if not 0 <= chain_id < 1 << 64:
        raise ValueError("chain id must fit in 64 bits")
    for v in (a, b, c):
        if not 0 <= v < 1 << 32:
            raise ValueError("address field must fit in 32 bits")
    word = (kind << 248) | (chain_id << 184) | (a << 152) | (b << 120) | (c << 88)
    return word.to_bytes(32, "big")


def chain_step(seed: bytes, chain_id: int, leaf: int, chain: int, step: int, x: bytes) -> bytes:
    return h(seed + adrs(CHAIN, chain_id, leaf, chain, step) + x)


def leaf_pk(seed: bytes, chain_id: int, leaf: int, log_w: int, ends: list[bytes]) -> bytes:
    return h(seed + adrs(LEAF_PK, chain_id, leaf, 0, log_w) + b"".join(ends))


def tree_node(seed: bytes, chain_id: int, level: int, index: int, left: bytes, right: bytes) -> bytes:
    return h(seed + adrs(TREE, chain_id, level, index) + left + right)


def message_digest(seed: bytes, chain_id: int, leaf: int, log_w: int, message: bytes) -> bytes:
    if len(message) != 32:
        raise ValueError("message must be 32 bytes")
    return h(seed + adrs(MSG, chain_id, leaf, 0, log_w) + message)
