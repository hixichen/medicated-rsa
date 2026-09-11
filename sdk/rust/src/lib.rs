//! medicated-rsa: Mediated RSA (mRSA) — an additive split of the RSA
//! private exponent between a member and a mediator.
//!
//! Quick start:
//!
//! ```
//! use medicated_rsa::{self as mrsa, PublicKey};
//!
//! let kp = mrsa::generate_keypair(2048)?;          // generation time only
//! let (member, mediator) = kp.split()?;             // d = d_M + d_Z mod λ(N)
//!
//! let digest = [0x42u8; 32];                        // any SHA-256 digest
//! let k = kp.n.bits().div_ceil(8);
//! let em = mrsa::encode_em(&digest, k)?;
//!
//! let s_m = mrsa::partial_sign(&member, &em)?;      // member's share
//! let s_z = mrsa::partial_sign(&mediator, &em)?;    // mediator's share
//! let sig = mrsa::combine(&s_m, &s_z, &kp.n)?;      // standard RSA signature
//!
//! let pub_key = PublicKey { n: kp.n.clone(), e: kp.e.clone() };
//! mrsa::verify(&pub_key, &em, &sig)?;               // ordinary RSA check
//! # Ok::<(), medicated_rsa::Error>(())
//! ```

mod errors;
mod mrsa;

pub use errors::{Error, ErrorCode};
pub use mrsa::{combine, encode_em, generate_keypair, partial_sign, verify, KeyPair, KeyShare, PublicKey};
