"""Local verification tests for the Python medicated-rsa SDK.

Pins the cryptographic core against the shared cross-language test vector
(sdk/testdata/vector.json), exercises the full mediated flow, and checks
the error contract. Pure standard library — no third-party dependencies.

Run with:  python3 -m unittest discover -s tests -v
"""

import unittest
from pathlib import Path

from medicated_rsa import core
from medicated_rsa.errors import (
    COMBINE_FAILED,
    EMPTY_INPUT,
    INVALID_INPUT,
    INVALID_KEY,
    INVALID_SHARE,
    KEY_GEN_FAILED,
    PARTIAL_SIGN_FAILED,
    SPLIT_FAILED,
    VERIFY_FAILED,
    MRSAError,
)

import json

VECTOR_PATH = Path(__file__).resolve().parents[2] / "testdata" / "vector.json"


def load_vector():
    return json.loads(VECTOR_PATH.read_text())


def shares_from_vector(vec):
    pub = core.PublicKey(int(vec["n"], 16), int(vec["e"], 16))
    member = core.KeyShare(int(vec["n"], 16), int(vec["e"], 16), int(vec["d_member"], 16))
    mediator = core.KeyShare(int(vec["n"], 16), int(vec["e"], 16), int(vec["d_mediator"], 16))
    return pub, member, mediator


class TestVector(unittest.TestCase):
    """Both partial signatures, their product, and the final RSA signature
    must match the vector byte for byte — the same vector the Go and Rust
    SDKs test against."""

    @classmethod
    def setUpClass(cls):
        cls.vec = load_vector()
        cls.pub, cls.member, cls.mediator = shares_from_vector(cls.vec)
        cls.em = bytes.fromhex(cls.vec["em"])

    def test_partial_signatures_match(self):
        self.assertEqual(core.partial_sign(self.member, self.em), bytes.fromhex(self.vec["sig_member"]))
        self.assertEqual(core.partial_sign(self.mediator, self.em), bytes.fromhex(self.vec["sig_mediator"]))

    def test_combined_signature_matches_and_verifies(self):
        sig = core.combine(
            bytes.fromhex(self.vec["sig_member"]),
            bytes.fromhex(self.vec["sig_mediator"]),
            self.pub.n,
        )
        self.assertEqual(sig.hex(), self.vec["signature"])
        core.verify(self.pub, self.em, sig)  # standard RSA verification

    def test_single_share_cannot_sign(self):
        for share_sig in ("sig_member", "sig_mediator"):
            with self.assertRaises(MRSAError) as cm:
                core.verify(self.pub, self.em, bytes.fromhex(self.vec[share_sig]))
            self.assertEqual(cm.exception.code, VERIFY_FAILED)

    def test_encode_em_matches(self):
        em = core.encode_em(bytes.fromhex(self.vec["digest"]), len(bytes.fromhex(self.vec["n"])))
        self.assertEqual(em.hex(), self.vec["em"])


class TestFullMediatedFlow(unittest.TestCase):
    """Key generation, split, member partial sign, mediator co-sign,
    combine, verify — plus tamper rejection."""

    @classmethod
    def setUpClass(cls):
        cls.kp = core.generate_keypair(2048)
        cls.member, cls.mediator = core.split_private_key(cls.kp)
        cls.pub = core.PublicKey(cls.kp.n, cls.kp.e)

    def test_round_trip(self):
        k = (self.kp.n.bit_length() + 7) // 8
        digest = b"medicated-rsa local test".ljust(32, b"\x00")[:32]
        em = core.encode_em(digest, k)

        s_m = core.partial_sign(self.member, em)
        s_z = core.partial_sign(self.mediator, em)
        sig = core.combine(s_m, s_z, self.kp.n)
        core.verify(self.pub, em, sig)

    def test_shares_differ(self):
        self.assertNotEqual(self.member.d_share, self.mediator.d_share)

    def test_tampered_signature_rejected(self):
        k = (self.kp.n.bit_length() + 7) // 8
        em = core.encode_em(b"\x42" * 32, k)
        sig = bytearray(
            core.combine(core.partial_sign(self.member, em), core.partial_sign(self.mediator, em), self.kp.n)
        )
        sig[k // 2] ^= 0xFF
        with self.assertRaises(MRSAError) as cm:
            core.verify(self.pub, em, bytes(sig))
        self.assertEqual(cm.exception.code, VERIFY_FAILED)

    def test_foreign_share_never_verifies(self):
        other = core.generate_keypair(2048)
        _, other_mediator = core.split_private_key(other)
        k = (self.kp.n.bit_length() + 7) // 8
        em = core.encode_em(b"\x42" * 32, k)
        s_m = core.partial_sign(self.member, em)
        s_z = core.partial_sign(other_mediator, em)
        # Same modulus size, so combine may succeed numerically — but the
        # product must never verify under the member's public key.
        try:
            sig = core.combine(s_m, s_z, self.kp.n)
        except MRSAError:
            return  # rejected structurally: also fine
        with self.assertRaises(MRSAError):
            core.verify(self.pub, em, sig)


class TestErrorCodes(unittest.TestCase):
    """Pin the cross-language error contract."""

    @classmethod
    def setUpClass(cls):
        cls.vec = load_vector()
        cls.pub, cls.member, cls.mediator = shares_from_vector(cls.vec)
        cls.em = bytes.fromhex(cls.vec["em"])

    def assertCode(self, code, ctx, fn, *args, **kwargs):
        with self.assertRaises(MRSAError) as cm:
            fn(*args, **kwargs)
        self.assertEqual(cm.exception.code, code, f"{ctx}: {cm.exception}")

    def test_keygen_too_small(self):
        self.assertCode(KEY_GEN_FAILED, "key too small", core.generate_keypair, 512)

    def test_partial_sign_inputs(self):
        self.assertCode(EMPTY_INPUT, "empty EM", core.partial_sign, self.member, b"")
        self.assertCode(INVALID_INPUT, "bad EM size", core.partial_sign, self.member, self.em[:10])
        self.assertCode(INVALID_SHARE, "none share", core.partial_sign, None, self.em)
        bad_share = core.KeyShare(self.pub.n, self.pub.e, 1)  # valid on construction…
        bad_share.d_share = self.pub.n  # …then corrupted (test-only bypass)
        self.assertCode(INVALID_SHARE, "share >= N", core.partial_sign, bad_share, self.em)
        self.assertCode(INVALID_KEY, "bad public key", core.PublicKey, -1, 65537)

    def test_combine_inputs(self):
        sig_z = bytes.fromhex(self.vec["sig_mediator"])
        self.assertCode(EMPTY_INPUT, "combine empty", core.combine, b"", sig_z, self.pub.n)
        self.assertCode(COMBINE_FAILED, "combine mismatch", core.combine, self.em[:10], sig_z, self.pub.n)
        self.assertCode(INVALID_INPUT, "combine bad modulus", core.combine, self.em, sig_z, 0)

    def test_verify_failures(self):
        self.assertCode(
            VERIFY_FAILED, "wrong sig", core.verify, self.pub, self.em, bytes.fromhex(self.vec["sig_member"])
        )
        self.assertCode(EMPTY_INPUT, "empty sig", core.verify, self.pub, self.em, b"")
        self.assertCode(INVALID_KEY, "none pub", core.verify, None, self.em, b"\x00" * 256)
        self.assertCode(INVALID_INPUT, "bad digest size", core.encode_em, b"\x00" * 16, 256)

    def test_split_requires_keypair(self):
        self.assertCode(SPLIT_FAILED, "no keypair", core.split_private_key, None)

    def test_error_message_format(self):
        with self.assertRaises(MRSAError) as cm:
            core.partial_sign(None, None)
        self.assertEqual(
            str(cm.exception),
            "mrsa: INVALID_SHARE (code 1004): key share is missing modulus, exponent, or private share",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
