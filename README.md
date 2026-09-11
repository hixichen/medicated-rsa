# medicated-rsa

Mediated RSA (mRSA) SDKs in Go, Python, and Rust — an additive split of the
RSA private exponent between a **member** and a **mediator**, with a shared
error contract and cross-language test vectors.

**Why am I doing this?** for fun.

> **This is a fun project, not production crypto.** Nothing here is
> audited or hardened — treat it as a working reference implementation of
> the BDTW mediated-RSA construction.
>
> Also note the clock: NIST's IR 8547 transition plan deprecates classical
> 112-bit-security algorithms — which includes RSA-2048 — after **2030**,
> and disallows them entirely after 2035. mRSA is a clever use of 25-year-old
> math, but the world is moving to post-quantum algorithms; if you're
> designing something real today, don't build on RSA.

The full design story — why the obvious fixes (merged JWKS, x5c headers,
central HSM) don't survive production, and why RS256 splits additively while
ECDSA needs multi-round MPC — is in the blog post that motivated this repo:
**[One Key, a Hundred Clusters: Multi-Cluster JWT Signing with Mediated RSA](
https://hixichen.github.io/2026/09/10/multi-cluster-jwt-signing-mediated-rsa.html)**

## What's here

The SDKs implement exactly the minimum mediated-RSA core — key generation,
split, partial signing, combine, verify — nothing else. No JWT layer, no
policy engine, no transport: those belong to the mediator service you build
around this.

```
sdk/
├── go/        Go module: github.com/hixichen/medicated-rsa/sdk/go
├── python/    Python package: medicated_rsa (pure standard library)
├── rust/      Rust crate: medicated-rsa
└── testdata/vector.json   shared cross-language test vector
```

| SDK | Language version | Dependencies |
|-----|------------------|--------------|
| Go  | 1.25+            | none (stdlib only) |
| Python | 3.13+         | none (stdlib only) |
| Rust | 1.85+ (edition 2024) | rsa, num-traits, num-integer, rand |

## The API (identical in all three languages)

```
generate_keypair(bits)              -> key pair (exists at generation time only)
key_pair.split()                    -> (member share, mediator share)
partial_sign(share, em)             -> partial signature  s_i = EM^(d_i) mod N
combine(s_member, s_mediator, n)    -> full signature     s_M · s_Z mod N
verify(public_key, em, signature)   -> valid / error      sig^e == EM mod N
encode_em(digest, em_len)            -> EMSA-PKCS1-v1_5 encoded message (RFC 8017)
```

Quick start (Go; the others mirror it):

```go
kp, _ := mrsa.GenerateKeyPair(2048)
member, mediator, _ := kp.Split() // d = d_member + d_mediator mod λ(N)

digest := sha256.Sum256(message)
em, _ := mrsa.EncodeEM(digest[:], 256)

sM, _ := mrsa.PartialSign(member, em)    // member's share
sZ, _ := mrsa.PartialSign(mediator, em)  // mediator's share
sig, _ := mrsa.Combine(sM, sZ, kp.N)     // ordinary RSA signature

err := mrsa.Verify(&mrsa.PublicKey{N: kp.N, E: kp.E}, em, sig) // nil
```

## Error codes (stable across all three SDKs)

Every error carries a machine-readable code, a stable textual name, and a
human-readable message. A mediator in one language can interpret a member
SDK error from another without string matching.

| Code | Name | Meaning |
|------|------|---------|
| 1001 | INVALID_KEY | malformed or unusable RSA key material |
| 1002 | KEY_GEN_FAILED | RSA key generation failed |
| 1003 | SPLIT_FAILED | private exponent could not be split |
| 1004 | INVALID_SHARE | malformed key share (zero, or not reduced) |
| 2001 | PARTIAL_SIGN_FAILED | partial signing failed |
| 2002 | COMBINE_FAILED | partial signatures incompatible (length/modulus mismatch) |
| 3001 | VERIFY_FAILED | signature failed verification |
| 4001 | EMPTY_INPUT | a required input was empty |
| 4002 | INVALID_INPUT | input malformed (bad length or value) |

Message format: `mrsa: NAME (code N): <what went wrong>` — identical in all
three SDKs, e.g.

```
mrsa: VERIFY_FAILED (code 3001): signature verification failed: sig^e does not reproduce the encoded message
```

## Running the local verification tests

Each SDK is pinned against `sdk/testdata/vector.json` — a fixed 2048-bit
signing transcript (partial signatures, their product, the standard
signature) generated once and committed. All three language suites must
reproduce it byte for byte, which is what makes the SDKs provably
interoperable: a member in Go can combine with a mediator in Python or Rust.

```sh
cd sdk/go     && go test ./...
cd sdk/python && python3 -m unittest discover -s tests -v
cd sdk/rust   && cargo test
```

Each suite additionally checks the full mediated flow (generate → split →
partial sign → combine → verify), that a single share can never verify, that
shares from a different key never combine into anything valid, tamper
rejection, and the error-code contract above.

## Notes and limits

- The full private exponent `d` exists only transiently at key generation
  time, inside the generating process. `split` must be called immediately
  and the key pair discarded — never logged, never serialized.
- A share's validation bound at signing time is `0 < d_i < N`; the strict
  bound `d_i < λ(N)` is enforced at split time (the primes are discarded
  afterwards).
- Correctness of the additive split relies on Carmichael's theorem:
  `EM^λ(N) ≡ 1 (mod N)` for any legitimately padded EM (gcd(EM, N) = 1), so
  `s_M · s_Z = EM^(d + kλ(N)) ≡ EM^d (mod N)` even when the two shares sum
  past `d` by a multiple of `λ(N)`.
- Verification here is textbook `sig^e == EM`. For adversarial settings use
  constant-time verification from your platform's crypto library; the
  signature bytes are identical, so any conforming RSA verifier accepts
  them.
- 2048-bit keys are the floor for correctness of the code; remember that
  RSA-2048 is scheduled for deprecation after 2030 (see the note above).
  This is a toy — enjoy it, don't deploy it.

## License

MIT
