import json
import os
import random

import pytest
from hypothesis import given, settings, strategies as st

from lamport.attack import TOY, try_forge
from lamport.cli import MUTATIONS, mutate, random_case
from lamport.hashing import h, message_digest
from lamport.params import LEAF_KEY_BASE, PROFILE_A, Params, epoch_of_nonce_key, leaf_of_nonce_key, nonce_key
from lamport.signer import Journal, LeafReuseError, Signer
from lamport.tree import KeyTree, verify
from lamport.wots import digits

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors")


def test_parameter_table():
    rows = {lw: (Params(log_w=lw).len1, Params(log_w=lw).len2) for lw in (1, 2, 4, 8)}
    assert rows == {1: (256, 9), 2: (128, 5), 4: (64, 3), 8: (32, 2)}
    assert PROFILE_A.length == 67
    assert PROFILE_A.sig_bytes == 4 + 32 * (67 + 10) == 2468


@pytest.mark.parametrize("log_w", [1, 2, 4, 8])
def test_round_trip_small_tree(log_w):
    p = Params(log_w=log_w, height=3)
    tree = KeyTree(p, os.urandom(32), os.urandom(32), 1)
    for leaf in range(p.leaves):
        msg = os.urandom(32)
        assert verify(p, tree.seed, tree.root, 1, msg, tree.sign_with_leaf(leaf, msg))


def test_every_mutation_kind_is_rejected():
    rng = random.Random(7)
    seen = set()
    for _ in range(400):
        case = random_case(rng, rng.choice((1, 2, 4, 8)), rng.choice((0, 3)))
        bad = mutate(rng, case)
        seen.add(bad["kind"])
        assert not verify(bad["p"], bad["seed"], bad["root"], bad["chain_id"], bad["message"], bad["sig"]), bad["kind"]
    assert seen == set(MUTATIONS)


def test_leaf_index_out_of_range_rejected():
    p = Params(log_w=4, height=2)
    tree = KeyTree(p, os.urandom(32), os.urandom(32), 1)
    msg = os.urandom(32)
    sig = bytearray(tree.sign_with_leaf(1, msg))
    sig[0:4] = (1 + p.leaves).to_bytes(4, "big")  # same low bits, out of range
    assert not verify(p, tree.seed, tree.root, 1, msg, bytes(sig))


@pytest.mark.parametrize("log_w", [1, 2, 4, 8])
@pytest.mark.parametrize("fill", [0x00, 0xFF])
def test_checksum_extremes(log_w, fill):
    """All-zero and all-maximum message digits: checksum digits take their extreme values."""
    p = Params(log_w=log_w, height=0)
    value = int.from_bytes(bytes([fill]) * 32, "big")
    mask = p.w - 1
    ds = [(value >> (256 - log_w * (i + 1))) & mask for i in range(p.len1)]
    checksum = sum(mask - d for d in ds)
    assert checksum == (p.len1 * mask if fill == 0 else 0)
    assert checksum < 1 << (p.len2 * log_w)  # fits in the checksum digits


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=32, max_size=32), st.sampled_from([1, 2, 4, 8]))
def test_raising_message_digits_lowers_checksum(digest, log_w):
    """Advancing any message chain must force some checksum chain backwards (no free forgery)."""
    p = Params(log_w=log_w, height=0)
    ds = digits(p, digest)
    msg_part, cs_part = ds[: p.len1], ds[p.len1:]
    mask = p.w - 1
    for i, d in enumerate(msg_part):
        if d < mask:
            raised = list(msg_part)
            raised[i] += 1
            checksum = sum(mask - x for x in raised)
            new_cs = [(checksum >> (log_w * (p.len2 - 1 - k))) & mask for k in range(p.len2)]
            assert any(n < o for n, o in zip(new_cs, cs_part))
            break


def test_domain_separation_changes_digest():
    seed, msg = os.urandom(32), os.urandom(32)
    base = message_digest(seed, 1, 0, 4, msg)
    assert base != message_digest(seed, 2, 0, 4, msg)
    assert base != message_digest(seed, 1, 1, 4, msg)
    assert base != message_digest(seed, 1, 0, 2, msg)
    assert base != message_digest(os.urandom(32), 1, 0, 4, msg)


class FakeChain:
    """Test double for chain state. Never used outside tests and the labelled demo."""

    def __init__(self):
        self.spent, self.pending = set(), set()

    def is_spent(self, leaf):
        return leaf in self.spent

    def is_pending(self, leaf):
        return leaf in self.pending


def test_signer_reads_chain_and_refuses_reuse(tmp_path):
    p = Params(log_w=4, height=3)
    tree = KeyTree(p, os.urandom(32), os.urandom(32), 1)
    chain = FakeChain()
    chain.spent |= {0, 1}
    chain.pending.add(2)
    signer = Signer(tree, chain, Journal(str(tmp_path / "journal")))
    leaf, sig = signer.sign(h(b"a"))
    assert leaf == 3
    with pytest.raises(LeafReuseError):
        signer.sign_with_leaf(3, h(b"b"))
    with pytest.raises(LeafReuseError):
        signer.sign_with_leaf(0, h(b"b"))
    with pytest.raises(LeafReuseError):
        signer.sign_with_leaf(2, h(b"b"))


def test_signer_after_backup_restore(tmp_path):
    """An old journal backup must not reset leaf use: the chain still reports the leaf as spent."""
    p = Params(log_w=4, height=3)
    tree = KeyTree(p, os.urandom(32), os.urandom(32), 1)
    chain = FakeChain()
    journal_path = tmp_path / "journal"
    signer = Signer(tree, chain, Journal(str(journal_path)))
    leaf, _ = signer.sign(h(b"first"))
    chain.spent.add(leaf)
    journal_path.unlink()  # restore from a backup taken before the first signature
    restored = Signer(tree, chain, Journal(str(journal_path)))
    assert restored.next_unused_leaf() != leaf
    with pytest.raises(LeafReuseError):
        restored.sign_with_leaf(leaf, h(b"second"))


def test_signer_journal_survives_restart(tmp_path):
    p = Params(log_w=4, height=2)
    tree = KeyTree(p, os.urandom(32), os.urandom(32), 1)
    path = str(tmp_path / "journal")
    leaf, _ = Signer(tree, FakeChain(), Journal(path)).sign(h(b"x"))
    with pytest.raises(LeafReuseError):
        Signer(tree, FakeChain(), Journal(path)).sign_with_leaf(leaf, h(b"y"))


def test_nonce_key_round_trip():
    assert nonce_key(0) != 0
    for leaf in (0, 1, 1023):
        assert leaf_of_nonce_key(nonce_key(leaf)) == leaf
        assert epoch_of_nonce_key(nonce_key(leaf)) == 0
        assert leaf_of_nonce_key(nonce_key(leaf, 3)) == leaf
        assert epoch_of_nonce_key(nonce_key(leaf, 3)) == 3
        assert nonce_key(leaf, 3) == LEAF_KEY_BASE + (3 << 16) + leaf
    assert leaf_of_nonce_key(0) is None
    assert epoch_of_nonce_key(0) is None


def test_toy_forgery_after_two_signatures():
    rng = random.Random(1)
    rb = lambda: bytes(rng.getrandbits(8) for _ in range(32))  # noqa: E731
    successes = 0
    for _ in range(5):
        tree = KeyTree(TOY, rb(), rb(), 1)
        signed = [(m, tree.sign_with_leaf(0, m)) for m in (rb(), rb())]
        r = try_forge(TOY, tree, 0, signed, 50000, rng=lambda n: bytes(rng.getrandbits(8) for _ in range(n)))
        successes += r.forged
    assert successes >= 4


@pytest.mark.parametrize("name", sorted(f for f in os.listdir(VECTORS) if f.endswith(".json")))
def test_saved_vectors(name):
    with open(os.path.join(VECTORS, name)) as f:
        vec = json.load(f)
    p = Params(log_w=vec["logW"], height=vec["height"])
    seed, root = bytes.fromhex(vec["seed"][2:]), bytes.fromhex(vec["root"][2:])
    for s in vec["signatures"]:
        assert verify(p, seed, root, vec["chainId"], bytes.fromhex(s["message"][2:]), bytes.fromhex(s["signature"][2:]))
