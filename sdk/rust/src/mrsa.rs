//! Mediated RSA (mRSA) core: an additive split of the RSA private exponent
//! between two parties that never trust each other.
//!
//! A single RSA key pair (N, e) is generated centrally and the private
//! exponent d is split additively:
//!
//! ```text
//! d = d_M + d_Z  (mod λ(N))
//! ```
//!
//! The **member** (e.g. a Kubernetes cluster, a node, an application
//! instance) holds d_M, the **Mediator** holds d_Z. Each party
//! exponentiates the PKCS#1 v1.5 encoded message (EM) with its own share,
//! and the product of the two partial signatures is a byte-for-byte
//! standard RSA signature under the public key (N, e):
//!
//! ```text
//! s_M · s_Z = EM^(d_M) · EM^(d_Z) = EM^(d_M + d_Z) ≡ EM^d  (mod N)
//! ```
//!
//! Neither party ever holds the full private exponent d. For any
//! legitimately padded EM, gcd(EM, N) = 1 and Carmichael's theorem
//! guarantees EM^λ(N) ≡ 1 (mod N), so the additive split verifies even
//! when the two shares sum to d + k·λ(N).

use num_traits::Zero;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};

use crate::errors::{err, ErrorCode, Error};

/// DER DigestInfo header for a SHA-256 digest (RFC 8017, section 9.2, note 1).
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

const SHA256_DIGEST_SIZE: usize = 32;

/// The shared RSA public key. Every member signs under the same (N, e),
/// so verifiers see exactly one key.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Modulus.
    pub n: BigUint,
    /// Public exponent.
    pub e: BigUint,
}

/// A freshly generated RSA key pair. The full private exponent `d` exists
/// only here, at generation time: call [`KeyPair::split`] immediately and
/// drop the KeyPair so neither party can ever observe `d`.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Public modulus N.
    pub n: BigUint,
    /// Public exponent e.
    pub e: BigUint,
    /// Full private exponent — generation time only.
    pub d: BigUint,
    /// Prime p.
    pub p: BigUint,
    /// Prime q.
    pub q: BigUint,
    /// λ(N) = lcm(p-1, q-1).
    pub lambda: BigUint,
}

/// One party's additive share of the private exponent. A share is useless
/// on its own: it cannot produce a signature that verifies.
#[derive(Debug, Clone)]
pub struct KeyShare {
    /// Shared public modulus.
    pub n: BigUint,
    /// Shared public exponent.
    pub e: BigUint,
    /// This party's share d_i of d, 0 < d_i < λ(N). Never logged or
    /// serialized by the SDK.
    pub d_share: BigUint,
}

impl KeyPair {
    /// Split the private exponent into two additive shares:
    ///
    /// ```text
    /// d_M (member) + d_Z (mediator) ≡ d  (mod λ(N))
    /// ```
    ///
    /// Each share is a uniform random value in [1, λ(N)); neither party
    /// can derive the other's share or the full exponent. Drop the KeyPair
    /// immediately after this returns.
    pub fn split(&self) -> Result<(KeyShare, KeyShare), Error> {
        let d_member = random_below(&self.lambda)?;
        let d_mediator = (&self.d - &d_member) % &self.lambda;
        if d_mediator.is_zero() {
            // d_member happened to equal d mod λ(N): redraw rather than
            // hand out a zero share.
            return self.split();
        }
        let member = KeyShare { n: self.n.clone(), e: self.e.clone(), d_share: d_member };
        let mediator = KeyShare { n: self.n.clone(), e: self.e.clone(), d_share: d_mediator };
        Ok((member, mediator))
    }
}

/// Generate a fresh RSA key pair of the given size.
///
/// `bits` must be at least 2048 for production use; 1024 is accepted for
/// tests only.
pub fn generate_keypair(bits: usize) -> Result<KeyPair, Error> {
    if bits < 1024 {
        return Err(err(
            ErrorCode::KeyGen,
            format!("key size must be at least 1024 bits, got {bits}"),
        ));
    }
    let mut rng = rand::rngs::OsRng;
    let key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| err(ErrorCode::KeyGen, format!("RSA key generation failed: {e}")))?;
    let primes = key.primes();
    let p = primes[0].clone();
    let q = primes[1].clone();

    let lambda = carmichael(&p, &q);
    Ok(KeyPair {
        n: key.n().clone(),
        e: key.e().clone(),
        d: key.d().clone(),
        p,
        q,
        lambda,
    })
}

/// Compute this party's partial signature s_i = EM^(d_i) mod N.
///
/// `em` is the EMSA-PKCS1-v1_5 encoded message and must be exactly as
/// long as the modulus.
pub fn partial_sign(share: &KeyShare, em: &[u8]) -> Result<Vec<u8>, Error> {
    validate_share(share)?;
    let k = modulus_len(&share.n);
    if em.is_empty() {
        return Err(err(ErrorCode::EmptyInput, "encoded message is empty"));
    }
    if em.len() != k {
        return Err(err(
            ErrorCode::InvalidInput,
            format!("encoded message must be exactly {k} bytes (modulus size), got {}", em.len()),
        ));
    }
    let em_int = BigUint::from_bytes_be(em);
    if em_int >= share.n {
        return Err(err(ErrorCode::InvalidInput, "encoded message is not smaller than the modulus"));
    }
    let s = em_int.modpow(&share.d_share, &share.n);
    Ok(left_pad(&s.to_bytes_be(), k))
}

/// Multiply two partial signatures into a full RSA signature:
/// s = s_M · s_Z mod N. Both partials must be exactly modulus-sized.
pub fn combine(a: &[u8], b: &[u8], n: &BigUint) -> Result<Vec<u8>, Error> {
    if n.is_zero() {
        return Err(err(ErrorCode::InvalidInput, "modulus is missing or zero"));
    }
    let k = modulus_len(n);
    if a.is_empty() || b.is_empty() {
        return Err(err(ErrorCode::EmptyInput, "a partial signature is empty"));
    }
    if a.len() != k || b.len() != k {
        return Err(err(
            ErrorCode::CombineFailed,
            format!("partial signatures must be exactly {k} bytes (modulus size), got {} and {}", a.len(), b.len()),
        ));
    }
    let s_a = BigUint::from_bytes_be(a);
    let s_b = BigUint::from_bytes_be(b);
    if s_a >= *n || s_b >= *n {
        return Err(err(ErrorCode::CombineFailed, "a partial signature is not reduced modulo N"));
    }
    let s = (s_a * s_b) % n;
    Ok(left_pad(&s.to_bytes_be(), k))
}

/// Check that `sig` is a valid PKCS#1 v1.5 signature over `em`.
///
/// Returns [`ErrorCode::VerifyFailed`] if the signature does not verify.
/// Verification is standard RSA — any conforming library produces the
/// same result.
pub fn verify(public_key: &PublicKey, em: &[u8], sig: &[u8]) -> Result<(), Error> {
    let k = modulus_len(&public_key.n);
    if em.is_empty() {
        return Err(err(ErrorCode::EmptyInput, "encoded message is empty"));
    }
    if sig.is_empty() {
        return Err(err(ErrorCode::EmptyInput, "signature is empty"));
    }
    if em.len() != k || sig.len() != k {
        return Err(err(
            ErrorCode::InvalidInput,
            format!(
                "encoded message and signature must be exactly {k} bytes (modulus size), got {} and {}",
                em.len(),
                sig.len()
            ),
        ));
    }
    let em_int = BigUint::from_bytes_be(em);
    let sig_int = BigUint::from_bytes_be(sig);
    if em_int >= public_key.n {
        return Err(err(ErrorCode::InvalidInput, "encoded message is not smaller than the modulus"));
    }
    if sig_int >= public_key.n {
        return Err(err(ErrorCode::InvalidInput, "signature is not reduced modulo N"));
    }
    let recovered = sig_int.modpow(&public_key.e, &public_key.n);
    if recovered != em_int {
        return Err(err(
            ErrorCode::VerifyFailed,
            "signature verification failed: sig^e does not reproduce the encoded message",
        ));
    }
    Ok(())
}

/// Build the EMSA-PKCS1-v1_5 encoded message for a SHA-256 digest
/// (RFC 8017, section 9.2) with a modulus of `em_len` bytes:
///
/// ```text
/// EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || digest,  PS = 0xFF…
/// ```
///
/// This is exactly what a stock RSA-SHA256 implementation encodes before
/// the private exponentiation, so the combined mediated signature is
/// byte-for-byte a standard one.
pub fn encode_em(digest: &[u8], em_len: usize) -> Result<Vec<u8>, Error> {
    if digest.len() != SHA256_DIGEST_SIZE {
        return Err(err(
            ErrorCode::InvalidInput,
            format!("digest must be {SHA256_DIGEST_SIZE} bytes (SHA-256), got {}", digest.len()),
        ));
    }
    let t = SHA256_DIGEST_INFO_PREFIX.len() + digest.len();
    if em_len < t + 11 {
        return Err(err(
            ErrorCode::InvalidInput,
            format!("encoded message length {em_len} is too small for SHA-256 (needs at least {} bytes)", t + 11),
        ));
    }
    let ps = em_len - t - 3;
    let mut em = Vec::with_capacity(em_len);
    em.push(0x00);
    em.push(0x01);
    em.resize(2 + ps, 0xFF);
    em.push(0x00);
    em.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
    em.extend_from_slice(digest);
    debug_assert_eq!(em.len(), em_len);
    Ok(em)
}

// ---------------------------------------------------------------- internals

/// λ(N) = lcm(p-1, q-1) for a two-prime modulus.
fn carmichael(p: &BigUint, q: &BigUint) -> BigUint {
    let one = BigUint::from(1u8);
    let p1 = p - &one;
    let q1 = q - &one;
    let g = num_integer::gcd(p1.clone(), q1.clone());
    (p1 * q1) / g
}

/// Uniform random integer in [1, bound).
fn random_below(bound: &BigUint) -> Result<BigUint, Error> {
    let k = modulus_len(bound);
    let mut buf = vec![0u8; k];
    for _ in 0..128 {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
        let v = BigUint::from_bytes_be(&buf) % bound;
        if !v.is_zero() && v < *bound {
            return Ok(v);
        }
    }
    Err(err(ErrorCode::SplitFailed, "rejection sampling failed after 128 attempts"))
}

fn modulus_len(n: &BigUint) -> usize {
    (n.bits()).div_ceil(8)
}

fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

fn validate_share(share: &KeyShare) -> Result<(), Error> {
    if share.n.is_zero() || share.e.is_zero() {
        return Err(err(ErrorCode::InvalidShare, "key share has a zero modulus or exponent"));
    }
    // The split routine guarantees 0 < d_i < λ(N); without the primes we
    // can only check the coarser bound d_i < N here.
    if share.d_share.is_zero() || share.d_share >= share.n {
        return Err(err(
            ErrorCode::InvalidShare,
            "private share must be nonzero and smaller than the modulus",
        ));
    }
    Ok(())
}
