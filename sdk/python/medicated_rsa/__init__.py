"""medicated-rsa: Mediated RSA (mRSA) — an additive split of the RSA
private exponent between a member and a mediator.

Quick start:

    from medicated_rsa import core

    kp = core.generate_keypair(2048)
    member, mediator = core.split_private_key(kp)   # d = d_M + d_Z mod λ(N)

    em = core.encode_em(digest, (kp.n.bit_length() + 7) // 8)
    s_m = core.partial_sign(member, em)     # member's share
    s_z = core.partial_sign(mediator, em)    # mediator's share
    sig = core.combine(s_m, s_z, kp.n)       # byte-for-byte a standard RSA signature

    core.verify(core.PublicKey(kp.n, kp.e), em, sig)
"""

from .core import (
    KeyPair,
    KeyShare,
    PublicKey,
    combine,
    encode_em,
    generate_keypair,
    partial_sign,
    split_private_key,
    verify,
)
from .errors import MRSAError

__version__ = "0.1.0"

__all__ = [
    "KeyPair",
    "KeyShare",
    "PublicKey",
    "MRSAError",
    "combine",
    "encode_em",
    "generate_keypair",
    "partial_sign",
    "split_private_key",
    "verify",
]
