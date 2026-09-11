//! Stable, cross-language error contract for the medicated-rsa SDKs.
//!
//! Every SDK (Go, Python, Rust) returns errors carrying the same numeric
//! codes and textual names, so a mediator written in one language can
//! interpret a member SDK error from another without string matching:
//!
//! - 1xxx: key management errors
//! - 2xxx: signing errors
//! - 3xxx: verification errors
//! - 4xxx: input errors

use std::fmt;

/// Stable numeric error code, identical across the Go, Python, and Rust
/// SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// Malformed or unusable RSA key material.
    InvalidKey = 1001,
    /// RSA key generation failed.
    KeyGen = 1002,
    /// The private exponent could not be split.
    SplitFailed = 1003,
    /// Malformed key share (zero, or not reduced).
    InvalidShare = 1004,
    /// Partial signing failed.
    PartialSignFailed = 2001,
    /// Partial signatures incompatible (length/modulus mismatch).
    CombineFailed = 2002,
    /// The signature failed verification.
    VerifyFailed = 3001,
    /// A required input was empty.
    EmptyInput = 4001,
    /// Input malformed (bad length or value).
    InvalidInput = 4002,
}

impl ErrorCode {
    /// Stable textual name for the code (e.g. `VERIFY_FAILED`).
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidKey => "INVALID_KEY",
            Self::KeyGen => "KEY_GEN_FAILED",
            Self::SplitFailed => "SPLIT_FAILED",
            Self::InvalidShare => "INVALID_SHARE",
            Self::PartialSignFailed => "PARTIAL_SIGN_FAILED",
            Self::CombineFailed => "COMBINE_FAILED",
            Self::VerifyFailed => "VERIFY_FAILED",
            Self::EmptyInput => "EMPTY_INPUT",
            Self::InvalidInput => "INVALID_INPUT",
        }
    }
}

/// The concrete error type returned by this crate. Always carries a
/// cross-language [`ErrorCode`] and a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    message: String,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// Stable numeric code, identical across the Go, Python, and Rust SDKs.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Stable textual name for the code (e.g. `VERIFY_FAILED`).
    pub fn name(&self) -> &'static str {
        self.code.name()
    }

    /// Human-readable description of what went wrong.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mrsa: {} (code {}): {}", self.code.name(), self.code as u32, self.message)
    }
}

impl std::error::Error for Error {}

pub(crate) fn err(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message)
}
