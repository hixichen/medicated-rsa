"""Stable, cross-language error contract for the medicated-rsa SDKs.

Every SDK (Go, Python, Rust) raises errors carrying the same numeric codes
and textual names, so a mediator written in one language can interpret a
member SDK error from another without string matching.

    1xxx  key management errors
    2xxx  signing errors
    3xxx  verification errors
    4xxx  input errors
"""

# Key management errors (1xxx).
INVALID_KEY = 1001  # malformed or unusable RSA key material
KEY_GEN_FAILED = 1002  # RSA key generation failed
SPLIT_FAILED = 1003  # private exponent could not be split
INVALID_SHARE = 1004  # malformed key share (zero, or not reduced)

# Signing errors (2xxx).
PARTIAL_SIGN_FAILED = 2001  # partial signing failed
COMBINE_FAILED = 2002  # partial signatures incompatible (length/modulus mismatch)

# Verification errors (3xxx).
VERIFY_FAILED = 3001  # signature failed verification

# Input errors (4xxx).
EMPTY_INPUT = 4001  # a required input was empty
INVALID_INPUT = 4002  # input malformed (bad length or value)

_CODE_NAMES = {
    INVALID_KEY: "INVALID_KEY",
    KEY_GEN_FAILED: "KEY_GEN_FAILED",
    SPLIT_FAILED: "SPLIT_FAILED",
    INVALID_SHARE: "INVALID_SHARE",
    PARTIAL_SIGN_FAILED: "PARTIAL_SIGN_FAILED",
    COMBINE_FAILED: "COMBINE_FAILED",
    VERIFY_FAILED: "VERIFY_FAILED",
    EMPTY_INPUT: "EMPTY_INPUT",
    INVALID_INPUT: "INVALID_INPUT",
}


class MRSAError(Exception):
    """The concrete error raised by this SDK.

    Attributes:
        code: stable numeric error code, identical across the Go, Python,
            and Rust SDKs (see the table above).
        name: stable textual name for the code (e.g. ``VERIFY_FAILED``).
        message: human-readable description of what went wrong.
    """

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        self.name = _CODE_NAMES.get(code, "UNKNOWN")
        super().__init__(f"mrsa: {self.name} (code {code}): {message}")
