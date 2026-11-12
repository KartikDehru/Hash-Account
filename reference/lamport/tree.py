"""Merkle tree of one-time keys, signature encoding and the verifier."""
from dataclasses import dataclass, field

from .hashing import tree_node
from .params import Params
from .wots import keygen_leaf, leaf_from_signature, sign_leaf


def root_from_path(p: Params, seed: bytes, chain_id: int, leaf: int, node: bytes, path: list[bytes]) -> bytes:
    if len(path) != p.height:
        raise ValueError("wrong path length")
    for level in range(1, p.height + 1):
        sibling = path[level - 1]
        index = leaf >> level
        if (leaf >> (level - 1)) & 1:
            node = tree_node(seed, chain_id, level, index, sibling, node)
        else:
            node = tree_node(seed, chain_id, level, index, node, sibling)
    return node


def encode_signature(p: Params, leaf: int, values: list[bytes], path: list[bytes]) -> bytes:
    if len(values) != p.length or len(path) != p.height:
        raise ValueError("wrong signature shape")
    return leaf.to_bytes(4, "big") + b"".join(values) + b"".join(path)


def decode_signature(p: Params, sig: bytes) -> tuple[int, list[bytes], list[bytes]] | None:
    if len(sig) != p.sig_bytes:
        return None
    leaf = int.from_bytes(sig[:4], "big")
    if leaf >= p.leaves:
        return None
    words = [sig[4 + 32 * i: 36 + 32 * i] for i in range(p.length + p.height)]
    return leaf, words[: p.length], words[p.length:]


def verify(p: Params, seed: bytes, root: bytes, chain_id: int, message: bytes, sig: bytes) -> bool:
    decoded = decode_signature(p, sig)
    if decoded is None or len(message) != 32:
        return False
    leaf, values, path = decoded
    node = leaf_from_signature(p, seed, chain_id, leaf, message, values)
    return root_from_path(p, seed, chain_id, leaf, node, path) == root


@dataclass
class KeyTree:
    """All one-time keys of one account. Holds the secret seed: test keys only."""

    p: Params
    sk_seed: bytes
    seed: bytes
    chain_id: int
    levels: list[list[bytes]] = field(default_factory=list)

    def __post_init__(self) -> None:
        nodes = [keygen_leaf(self.p, self.sk_seed, self.seed, self.chain_id, i) for i in range(self.p.leaves)]
        self.levels = [nodes]
        for level in range(1, self.p.height + 1):
            prev = self.levels[-1]
            nodes = [
                tree_node(self.seed, self.chain_id, level, k, prev[2 * k], prev[2 * k + 1])
                for k in range(len(prev) // 2)
            ]
            self.levels.append(nodes)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def path(self, leaf: int) -> list[bytes]:
        return [self.levels[level][(leaf >> level) ^ 1] for level in range(self.p.height)]

    def sign_with_leaf(self, leaf: int, message: bytes) -> bytes:
        """Raw signing. Does not check reuse: use signer.Signer, never this, outside tests."""
        values = sign_leaf(self.p, self.sk_seed, self.seed, self.chain_id, leaf, message)
        return encode_signature(self.p, leaf, values, self.path(leaf))
