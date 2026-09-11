//! Local verification tests for the Rust medicated-rsa SDK.
//!
//! Pins the cryptographic core against the shared cross-language test
//! vector (sdk/testdata/vector.json), exercises the full mediated flow,
//! and checks the error contract.
//!
//! Run with:  cargo test

use medicated_rsa as mrsa;
use medicated_rsa::Error;
use medicated_rsa::ErrorCode;
use medicated_rsa::KeyShare;
use medicated_rsa::PublicKey;
use rsa::BigUint;
use std::path::PathBuf;

fn vector() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/vector.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vector.json"))
        .expect("parse vector.json")
}

fn hex_big(v: &serde_json::Value, key: &str) -> BigUint {
    BigUint::from_bytes_be(&hex::decode(v[key].as_str().unwrap()).unwrap())
}

fn hex_bytes(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

fn shares_from_vector(v: &serde_json::Value) -> (PublicKey, KeyShare, KeyShare) {
    let n = hex_big(v, "n");
    let e = hex_big(v, "e");
    let member = KeyShare { n: n.clone(), e: e.clone(), d_share: hex_big(v, "d_member") };
    let mediator = KeyShare { n: n.clone(), e: e.clone(), d_share: hex_big(v, "d_mediator") };
    (PublicKey { n, e }, member, mediator)
}

/// Both partial signatures, their product, and the final RSA signature
/// must match the vector byte for byte — the same vector the Go and
/// Python SDKs test against.
#[test]
fn vector_partial_sign_combine() {
    let v = vector();
    let (pub_key, member, mediator) = shares_from_vector(&v);
    let em = hex_bytes(&v, "em");

    assert_eq!(mrsa::partial_sign(&member, &em).unwrap(), hex_bytes(&v, "sig_member"));
    assert_eq!(mrsa::partial_sign(&mediator, &em).unwrap(), hex_bytes(&v, "sig_mediator"));

    let sig = mrsa::combine(&hex_bytes(&v, "sig_member"), &hex_bytes(&v, "sig_mediator"), &pub_key.n).unwrap();
    assert_eq!(sig, hex_bytes(&v, "signature"));
    mrsa::verify(&pub_key, &em, &sig).unwrap();
}

/// A single party's partial signature must never verify.
#[test]
fn vector_single_share_cannot_sign() {
    let v = vector();
    let (pub_key, _, _) = shares_from_vector(&v);
    let em = hex_bytes(&v, "em");

    for key in ["sig_member", "sig_mediator"] {
        let err = mrsa::verify(&pub_key, &em, &hex_bytes(&v, key)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::VerifyFailed, "single share must not verify: {err}");
    }
}

/// The EMSA-PKCS1-v1_5 encoding must match the vector.
#[test]
fn vector_encode_em() {
    let v = vector();
    let em = mrsa::encode_em(&hex_bytes(&v, "digest"), hex_bytes(&v, "n").len()).unwrap();
    assert_eq!(em, hex_bytes(&v, "em"));
}

/// The production-shaped round trip: key generation, split, member
/// partial sign, mediator co-sign, combine, verify — plus tamper
/// rejection and foreign-share rejection.
#[test]
fn full_mediated_flow() {
    let kp = mrsa::generate_keypair(2048).unwrap();
    let (member, mediator) = kp.split().unwrap();
    assert_ne!(member.d_share, mediator.d_share);

    let digest = [0x42u8; 32];
    let k = kp.n.bits().div_ceil(8);
    let em = mrsa::encode_em(&digest, k).unwrap();

    let s_m = mrsa::partial_sign(&member, &em).unwrap();
    let s_z = mrsa::partial_sign(&mediator, &em).unwrap();
    let sig = mrsa::combine(&s_m, &s_z, &kp.n).unwrap();

    let pub_key = PublicKey { n: kp.n.clone(), e: kp.e.clone() };
    mrsa::verify(&pub_key, &em, &sig).unwrap();

    // A tampered signature must fail verification.
    let mut tampered = sig.clone();
    tampered[k / 2] ^= 0xFF;
    let err = mrsa::verify(&pub_key, &em, &tampered).unwrap_err();
    assert_eq!(err.code(), ErrorCode::VerifyFailed);

    // Shares from a second key must never co-sign with the first key's
    // member share.
    let other = mrsa::generate_keypair(2048).unwrap();
    let (_, other_mediator) = other.split().unwrap();
    let s_z = mrsa::partial_sign(&other_mediator, &em).unwrap();
    if let Ok(sig) = mrsa::combine(&s_m, &s_z, &kp.n) {
        assert!(mrsa::verify(&pub_key, &em, &sig).is_err());
    }
}

/// Pin the cross-language error contract.
#[test]
fn error_codes() {
    let v = vector();
    let (pub_key, member, _) = shares_from_vector(&v);
    let em = hex_bytes(&v, "em");

    let cases: Vec<(&str, ErrorCode, Result<(), Error>)> = vec![
        ("key too small", ErrorCode::KeyGen, mrsa::generate_keypair(512).map(|_| ())),
        ("empty EM", ErrorCode::EmptyInput, mrsa::partial_sign(&member, b"").map(|_| ())),
        ("bad EM size", ErrorCode::InvalidInput, mrsa::partial_sign(&member, &em[..10]).map(|_| ())),
        ("share >= N", ErrorCode::InvalidShare, mrsa::partial_sign(&KeyShare { n: pub_key.n.clone(), e: pub_key.e.clone(), d_share: pub_key.n.clone() }, &em).map(|_| ())),
        ("combine length mismatch", ErrorCode::CombineFailed, mrsa::combine(&hex_bytes(&v, "sig_member"), &hex_bytes(&v, "sig_mediator")[..10], &pub_key.n).map(|_| ())),
        ("combine empty", ErrorCode::EmptyInput, mrsa::combine(b"", &hex_bytes(&v, "sig_mediator"), &pub_key.n).map(|_| ())),
        ("verify wrong sig", ErrorCode::VerifyFailed, mrsa::verify(&pub_key, &em, &hex_bytes(&v, "sig_member"))),
        ("verify empty sig", ErrorCode::EmptyInput, mrsa::verify(&pub_key, &em, b"")),
        ("encode EM bad digest", ErrorCode::InvalidInput, mrsa::encode_em(&[0u8; 16], 256).map(|_| ())),
    ];
    for (name, want, result) in cases {
        let err = result.err().unwrap_or_else(|| panic!("{name}: expected error, got Ok"));
        assert_eq!(err.code(), want, "{name}: {err}");
    }
}

/// Every SDK error renders a message a human can act on.
#[test]
fn error_message_format() {
    let err = mrsa::partial_sign(&KeyShare { n: BigUint::from(3u8), e: BigUint::from(3u8), d_share: BigUint::from(2u8) }, &[]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::EmptyInput);
    assert_eq!(err.to_string(), format!("mrsa: EMPTY_INPUT (code 4001): {}", err.message()));
}
