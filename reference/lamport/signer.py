"""Stateful signer that never signs twice with one leaf.

The signer keeps no counter. It asks a LeafState source (on a real network: the
EIP-8250 NONCE_MANAGER storage and the mempool) which leaves are spent or pending,
and it keeps an append-only journal of leaves it has signed with. A leaf in any of
the three is refused. The journal is written before the signature is returned.

Restoring an old backup of the journal is safe for any signature that reached the
chain or the mempool, because those are read from the network. A signature that was
produced but never broadcast and whose journal entry was lost is the one remaining
risk: such a signature must be destroyed, not kept.
"""
import json
import os
from typing import Protocol

from .tree import KeyTree


class LeafState(Protocol):
    def is_spent(self, leaf: int) -> bool: ...
    def is_pending(self, leaf: int) -> bool: ...


class LeafReuseError(Exception):
    pass


class Journal:
    """Append-only record of leaves already used for signing."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self._leaves: set[int] = set()
        if path and os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.strip():
                        self._leaves.add(json.loads(line)["leaf"])

    def __contains__(self, leaf: int) -> bool:
        return leaf in self._leaves

    def record(self, leaf: int, message: bytes) -> None:
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps({"leaf": leaf, "message": message.hex()}) + "\n")
                f.flush()
                os.fsync(f.fileno())
        self._leaves.add(leaf)


class Signer:
    def __init__(self, tree: KeyTree, state: LeafState, journal: Journal | None = None) -> None:
        self.tree = tree
        self.state = state
        self.journal = journal or Journal()

    def usable(self, leaf: int) -> bool:
        return not (leaf in self.journal or self.state.is_spent(leaf) or self.state.is_pending(leaf))

    def next_unused_leaf(self) -> int:
        for leaf in range(self.tree.p.leaves):
            if self.usable(leaf):
                return leaf
        raise LeafReuseError("all one-time keys are used; rotate to a new key tree")

    def sign_with_leaf(self, leaf: int, message: bytes) -> bytes:
        if not 0 <= leaf < self.tree.p.leaves:
            raise ValueError("leaf out of range")
        if not self.usable(leaf):
            raise LeafReuseError(f"leaf {leaf} is already used or pending; refusing to sign")
        self.journal.record(leaf, message)
        return self.tree.sign_with_leaf(leaf, message)

    def sign(self, message: bytes) -> tuple[int, bytes]:
        leaf = self.next_unused_leaf()
        return leaf, self.sign_with_leaf(leaf, message)
