"""Mediated RSA (mRSA) core: an additive split of the RSA private exponent
between two parties that never trust each other.

A single RSA key pair (N, e) is generated centrally and the private
exponent d is split additively:

    d = d_M + d_Z  (mod λ(N))

The **member** (e.g. a Kubernetes cluster, a node, an application
instance) holds d_M, the **Mediator** holds d_Z. Each party exponentiates
the PKCS#1 v1.5 encoded message (EM) with its own share, and the product
of the two partial signatures is a byte-for-byte standard RSA signature
under the public key (N, e):

    s_M · s_Z = EM^(d_M) · EM^(d_Z) = EM^(d_M + d_Z) ≡ EM^d  (mod N)

Neither party ever holds the full private exponent d. For any
legitimately padded EM, gcd(EM, N) = 1 and Carmichael's theorem
guarantees EM^λ(N) ≡ 1 (mod N), so the additive split verifies even when
the two shares sum to d + k·λ(N).

This module is pure standard-library Python: auditable end to end, no
native dependencies, no supply-chain surface.
"""

from __future__ import annotations

import secrets
from typing import Optional

from .errors import (
    COMBINE_FAILED,
    EMPTY_INPUT,
    INVALID_INPUT,
    INVALID_KEY,
    INVALID_SHARE,
    KEY_GEN_FAILED,
    SPLIT_FAILED,
    VERIFY_FAILED,
    MRSAError,
)

# DER DigestInfo header for a SHA-256 digest (RFC 8017, section 9.2, note 1).
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
_SHA256_DIGEST_SIZE = 32


class PublicKey:
    """The shared RSA public key. Every member signs under the same
    (N, e), so verifiers see exactly one key."""

    def __init__(self, n: int, e: int):
        if n <= 0 or e <= 0:
            raise MRSAError(INVALID_KEY, "public modulus and exponent must be positive")
        self.n = n
        self.e = e


class KeyPair:
    """A freshly generated RSA key pair.

    The full private exponent ``d`` exists only here, at generation time:
    call :func:`split_private_key` immediately and discard the KeyPair so
    neither party can ever observe ``d``.
    """

    def __init__(self, n: int, e: int, d: int, p: int, q: int, lam: int):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.lam = lam  # λ(N) = lcm(p-1, q-1)


class KeyShare:
    """One party's additive share of the private exponent.

    A share is useless on its own: it cannot produce a signature that
    verifies. The split routine guarantees 0 < d_share < λ(N).
    """

    def __init__(self, n: int, e: int, d_share: int):
        if n <= 0 or e <= 0:
            raise MRSAError(INVALID_SHARE, "key share has a zero modulus or exponent")
        if d_share <= 0 or d_share >= n:
            raise MRSAError(
                INVALID_SHARE,
                "private share must be nonzero and smaller than the modulus",
            )
        self.n = n
        self.e = e
        self.d_share = d_share

    def __repr__(self) -> str:  # never reveal d_share
        return f"KeyShare(N=0x{self.n:x}…, share-of-d=[REDACTED])"


def generate_keypair(bits: int = 2048) -> KeyPair:
    """Generate a fresh RSA key pair of the given size.

    bits must be at least 2048 for production use; 1024 is accepted for
    tests only.
    """
    if bits < 1024:
        raise MRSAError(KEY_GEN_FAILED, f"key size must be at least 1024 bits, got {bits}")
    e = 65537
    while True:
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        if _gcd(e, p - 1) != 1 or _gcd(e, q - 1) != 1:
            continue
        lam = _lcm(p - 1, q - 1)
        d = pow(e, -1, lam)
        return KeyPair(n=n, e=e, d=d, p=p, q=q, lam=lam)


def split_private_key(kp: KeyPair) -> tuple[KeyShare, KeyShare]:
    """Split the private exponent into two additive shares:

        d_M (member) + d_Z (mediator) ≡ d  (mod λ(N))

    Each share is a uniform random value in [1, λ(N)); neither party can
    derive the other's share or the full exponent. Discard the KeyPair
    immediately after this returns.
    """
    if not isinstance(kp, KeyPair):
        raise MRSAError(SPLIT_FAILED, "key pair is missing; call generate_keypair first")
    while True:
        d_member = _random_below(kp.lam)
        d_mediator = (kp.d - d_member) % kp.lam
        if d_mediator != 0:  # d_member == d mod λ(N): redraw rather than hand out a zero share
            return KeyShare(kp.n, kp.e, d_member), KeyShare(kp.n, kp.e, d_mediator)


def partial_sign(share: KeyShare, em: bytes) -> bytes:
    """Compute this party's partial signature s_i = EM^(d_i) mod N.

    ``em`` is the EMSA-PKCS1-v1_5 encoded message and must be exactly as
    long as the modulus.
    """
    _validate_share(share)
    k = _modulus_len(share.n)
    if not em:
        raise MRSAError(EMPTY_INPUT, "encoded message is empty")
    if len(em) != k:
        raise MRSAError(
            INVALID_INPUT,
            f"encoded message must be exactly {k} bytes (modulus size), got {len(em)}",
        )
    em_int = int.from_bytes(em, "big")
    if em_int >= share.n:
        raise MRSAError(INVALID_INPUT, "encoded message is not smaller than the modulus")
    s = pow(em_int, share.d_share, share.n)
    return s.to_bytes(k, "big")


def combine(a: bytes, b: bytes, n: int) -> bytes:
    """Multiply two partial signatures into a full RSA signature:
    s = s_M · s_Z mod N. Both partials must be exactly modulus-sized."""
    if n <= 0:
        raise MRSAError(INVALID_INPUT, "modulus is missing or zero")
    k = _modulus_len(n)
    if not a or not b:
        raise MRSAError(EMPTY_INPUT, "a partial signature is empty")
    if len(a) != k or len(b) != k:
        raise MRSAError(
            COMBINE_FAILED,
            f"partial signatures must be exactly {k} bytes (modulus size), got {len(a)} and {len(b)}",
        )
    s_a = int.from_bytes(a, "big")
    s_b = int.from_bytes(b, "big")
    if s_a >= n or s_b >= n:
        raise MRSAError(COMBINE_FAILED, "a partial signature is not reduced modulo N")
    return (s_a * s_b % n).to_bytes(k, "big")


def verify(pub: PublicKey, em: bytes, sig: bytes) -> None:
    """Check that ``sig`` is a valid PKCS#1 v1.5 signature over ``em``.

    Raises :class:`MRSAError` with code VERIFY_FAILED if the signature does
    not verify. Verification is standard RSA — any conforming library
    produces the same result.
    """
    if not isinstance(pub, PublicKey):
        raise MRSAError(INVALID_KEY, "public key is missing or incomplete")
    k = _modulus_len(pub.n)
    if not em:
        raise MRSAError(EMPTY_INPUT, "encoded message is empty")
    if not sig:
        raise MRSAError(EMPTY_INPUT, "signature is empty")
    if len(em) != k or len(sig) != k:
        raise MRSAError(
            INVALID_INPUT,
            f"encoded message and signature must be exactly {k} bytes (modulus size), got {len(em)} and {len(sig)}",
        )
    em_int = int.from_bytes(em, "big")
    sig_int = int.from_bytes(sig, "big")
    if em_int >= pub.n:
        raise MRSAError(INVALID_INPUT, "encoded message is not smaller than the modulus")
    if sig_int >= pub.n:
        raise MRSAError(INVALID_INPUT, "signature is not reduced modulo N")
    if pow(sig_int, pub.e, pub.n) != em_int:
        raise MRSAError(
            VERIFY_FAILED,
            "signature verification failed: sig^e does not reproduce the encoded message",
        )


def encode_em(digest: bytes, em_len: int) -> bytes:
    """Build the EMSA-PKCS1-v1_5 encoded message for a SHA-256 digest
    (RFC 8017, section 9.2) with a modulus of ``em_len`` bytes:

        EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || digest,  PS = 0xFF…

    This is exactly what a stock RSA-SHA256 implementation encodes before
    the private exponentiation, so the combined mediated signature is
    byte-for-byte a standard one.
    """
    if len(digest) != _SHA256_DIGEST_SIZE:
        raise MRSAError(
            INVALID_INPUT,
            f"digest must be {_SHA256_DIGEST_SIZE} bytes (SHA-256), got {len(digest)}",
        )
    t = len(_SHA256_DIGEST_INFO_PREFIX) + len(digest)
    if em_len < t + 11:
        raise MRSAError(
            INVALID_INPUT,
            f"encoded message length {em_len} is too small for SHA-256 (needs at least {t + 11} bytes)",
        )
    ps = em_len - t - 3
    return b"\x00\x01" + b"\xff" * ps + b"\x00" + _SHA256_DIGEST_INFO_PREFIX + digest


# ---------------------------------------------------------------- internals


def _small_primes(limit: int = 2048) -> list[int]:
    sieve = bytearray([1]) * limit
    sieve[0] = 0
    primes = []
    for i in range(2, limit):
        if sieve[i]:
            primes.append(i)
            for j in range(i * i, limit, i):
                sieve[j] = 0
    return primes


_SMALL_PRIMES = _small_primes()


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Miller-Rabin.
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _lcm(a: int, b: int) -> int:
    return a // _gcd(a, b) * b


def _modulus_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


def _random_below(bound: int) -> int:
    """Uniform random integer in [1, bound)."""
    k = (bound.bit_length() + 7) // 8
    for _ in range(128):
        v = int.from_bytes(secrets.token_bytes(k), "big") % bound
        if 0 < v < bound:
            return v
    raise MRSAError(SPLIT_FAILED, "rejection sampling failed after 128 attempts")


def _validate_share(share: Optional[KeyShare]) -> None:
    if not isinstance(share, KeyShare):
        raise MRSAError(INVALID_SHARE, "key share is missing modulus, exponent, or private share")
    if share.n <= 0 or share.e <= 0:
        raise MRSAError(INVALID_SHARE, "key share has a zero modulus or exponent")
    # The split routine guarantees 0 < d_i < λ(N); without the primes we
    # can only check the coarser bound d_i < N here.
    if share.d_share <= 0 or share.d_share >= share.n:
        raise MRSAError(INVALID_SHARE, "private share must be nonzero and smaller than the modulus")
