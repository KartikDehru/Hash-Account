"""Parameter sets for the Winternitz scheme."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Params:
    log_w: int = 4
    height: int = 10
    msg_bits: int = 256

    def __post_init__(self) -> None:
        if self.log_w not in (1, 2, 4, 8):
            raise ValueError("log_w must be 1, 2, 4 or 8")
        if self.msg_bits % self.log_w or not 0 < self.msg_bits <= 256:
            raise ValueError("msg_bits must be a positive multiple of log_w, at most 256")
        if not 0 <= self.height <= 20:
            raise ValueError("height must be in 0..20")

    @property
    def w(self) -> int:
        return 1 << self.log_w

    @property
    def len1(self) -> int:
        return self.msg_bits // self.log_w

    @property
    def len2(self) -> int:
        max_checksum = self.len1 * (self.w - 1)
        return (max_checksum.bit_length() - 1) // self.log_w + 1

    @property
    def length(self) -> int:
        return self.len1 + self.len2

    @property
    def leaves(self) -> int:
        return 1 << self.height

    @property
    def sig_bytes(self) -> int:
        return 4 + 32 * (self.length + self.height)


PROFILE_A = Params(log_w=4, height=10)

# EIP-8250 nonce key for a leaf: a non-zero, domain-separated key ("LAMP" tag in the top bytes).
# Key 0 is the legacy account nonce and cannot be combined with other keys.
LEAF_KEY_BASE = int.from_bytes(b"LAMP", "big") << 224
MAX_NONCE_SEQ = (1 << 64) - 1


def nonce_key(leaf: int) -> int:
    return LEAF_KEY_BASE + leaf


def leaf_of_nonce_key(key: int) -> int | None:
    leaf = key - LEAF_KEY_BASE
    return leaf if 0 <= leaf < 1 << 32 else None
