// Package mrsa implements Mediated RSA (mRSA): an additive split of the
// RSA private exponent between two parties that never trust each other.
//
// A single RSA key pair (N, e) is generated centrally and the private
// exponent d is split additively:
//
//	d = d_M + d_Z  (mod λ(N))
//
// The member (e.g. a Kubernetes cluster, a node, an application instance)
// holds d_M, the Mediator holds d_Z. Each party exponentiates the PKCS#1
// v1.5 encoded message (EM) with its own share, and the product of the two
// partial signatures is a byte-for-byte standard RSA signature under the
// public key (N, e):
//
//	s_M · s_Z = EM^(d_M) · EM^(d_Z) = EM^(d_M + d_Z) ≡ EM^d  (mod N)
//
// Neither party ever holds the full private exponent d. For any
// legitimately padded EM, gcd(EM, N) = 1 and Carmichael's theorem
// guarantees EM^λ(N) ≡ 1 (mod N), so the additive split verifies even
// when the two shares sum to d + k·λ(N).
package mrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
)

// PublicKey is the shared RSA public key. Every member signs under the
// same (N, e), so verifiers see exactly one key.
type PublicKey struct {
	N *big.Int // modulus
	E *big.Int // public exponent
}

// KeyPair is a freshly generated RSA key pair. The full private exponent
// D exists only here, at generation time: call Split immediately and
// discard the KeyPair so neither party can ever observe D.
type KeyPair struct {
	N, E   *big.Int
	D      *big.Int // full private exponent — generation time only
	p, q   *big.Int
	lambda *big.Int // λ(N) = lcm(p-1, q-1)
}

// KeyShare is one party's additive share of the private exponent. A share
// is useless on its own: it cannot produce a signature that verifies.
type KeyShare struct {
	N      *big.Int // shared public modulus
	E      *big.Int // shared public exponent
	DShare *big.Int // this party's share d_i of d, 0 < d_i < λ(N)
}

// GenerateKeyPair generates a fresh RSA key pair of the given size.
// bits must be at least 2048 for production use; 1024 is accepted for
// tests only.
func GenerateKeyPair(bits int) (*KeyPair, error) {
	if bits < 1024 {
		return nil, newError(ErrCodeKeyGen, "key size must be at least 1024 bits, got %d", bits)
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, newError(ErrCodeKeyGen, "RSA key generation failed: %v", err)
	}
	p, q := key.Primes[0], key.Primes[1]
	if key.N == nil || key.D == nil || p == nil || q == nil {
		return nil, newError(ErrCodeKeyGen, "RSA key generation produced incomplete key material")
	}
	return &KeyPair{
		N:      new(big.Int).Set(key.N),
		E:      new(big.Int).Set(big.NewInt(int64(key.E))),
		D:      new(big.Int).Set(key.D),
		p:      new(big.Int).Set(p),
		q:      new(big.Int).Set(q),
		lambda: carmichael(p, q),
	}, nil
}

// Split splits the private exponent into two additive shares:
//
//	d_M (member) + d_Z (mediator) ≡ d  (mod λ(N))
//
// Each share is a uniform random value in [1, λ(N)); neither party can
// derive the other's share or the full exponent. The KeyPair should be
// discarded immediately after Split returns.
func (kp *KeyPair) Split() (member, mediator *KeyShare, err error) {
	if kp == nil || kp.D == nil || kp.lambda == nil || kp.N == nil || kp.E == nil {
		return nil, nil, newError(ErrCodeSplitFailed, "key pair is incomplete; call GenerateKeyPair first")
	}
	dM, err := randomBelow(kp.lambda)
	if err != nil {
		return nil, nil, newError(ErrCodeSplitFailed, "failed to draw member share: %v", err)
	}
	dZ := new(big.Int).Sub(kp.D, dM)
	dZ.Mod(dZ, kp.lambda)
	if dZ.Sign() == 0 {
		// dM happened to equal d mod λ(N): redraw rather than hand out a zero share.
		return kp.Split()
	}
	member = &KeyShare{N: new(big.Int).Set(kp.N), E: new(big.Int).Set(kp.E), DShare: dM}
	mediator = &KeyShare{N: new(big.Int).Set(kp.N), E: new(big.Int).Set(kp.E), DShare: dZ}
	return member, mediator, nil
}

// PartialSign computes this party's partial signature s_i = EM^(d_i) mod N
// over the EMSA-PKCS1-v1_5 encoded message em. em must be exactly as long
// as the modulus.
func PartialSign(share *KeyShare, em []byte) ([]byte, error) {
	if err := validateShare(share); err != nil {
		return nil, err
	}
	k := (share.N.BitLen() + 7) / 8
	if len(em) == 0 {
		return nil, newError(ErrCodeEmptyInput, "encoded message is empty")
	}
	if len(em) != k {
		return nil, newError(ErrCodeInvalidInput, "encoded message must be exactly %d bytes (modulus size), got %d", k, len(em))
	}
	emInt := new(big.Int).SetBytes(em)
	if emInt.Cmp(share.N) >= 0 {
		return nil, newError(ErrCodeInvalidInput, "encoded message is not smaller than the modulus")
	}
	s := new(big.Int).Exp(emInt, share.DShare, share.N)
	return s.FillBytes(make([]byte, k)), nil
}

// Combine multiplies two partial signatures into a full RSA signature:
// s = s_M · s_Z mod N. Both partials must be exactly modulus-sized.
func Combine(a, b []byte, n *big.Int) ([]byte, error) {
	if n == nil || n.Sign() <= 0 {
		return nil, newError(ErrCodeInvalidInput, "modulus is missing or zero")
	}
	if len(a) == 0 || len(b) == 0 {
		return nil, newError(ErrCodeEmptyInput, "a partial signature is empty")
	}
	k := (n.BitLen() + 7) / 8
	if len(a) != k || len(b) != k {
		return nil, newError(ErrCodeCombineFailed, "partial signatures must be exactly %d bytes (modulus size), got %d and %d", k, len(a), len(b))
	}
	sA := new(big.Int).SetBytes(a)
	sB := new(big.Int).SetBytes(b)
	if sA.Cmp(n) >= 0 || sB.Cmp(n) >= 0 {
		return nil, newError(ErrCodeCombineFailed, "a partial signature is not reduced modulo N")
	}
	s := sA.Mul(sA, sB)
	s.Mod(s, n)
	return s.FillBytes(make([]byte, k)), nil
}

// Verify checks that sig is a valid PKCS#1 v1.5 signature over em under the
// public key (N, e): it must satisfy sig^e ≡ EM (mod N). Verification is
// standard RSA — any conforming library produces the same result.
func Verify(pub *PublicKey, em, sig []byte) error {
	if pub == nil || pub.N == nil || pub.E == nil || pub.N.Sign() <= 0 || pub.E.Sign() <= 0 {
		return newError(ErrCodeInvalidKey, "public key is missing or incomplete")
	}
	k := (pub.N.BitLen() + 7) / 8
	if len(em) == 0 {
		return newError(ErrCodeEmptyInput, "encoded message is empty")
	}
	if len(sig) == 0 {
		return newError(ErrCodeEmptyInput, "signature is empty")
	}
	if len(em) != k || len(sig) != k {
		return newError(ErrCodeInvalidInput, "encoded message and signature must be exactly %d bytes (modulus size), got %d and %d", k, len(em), len(sig))
	}
	emInt := new(big.Int).SetBytes(em)
	if emInt.Cmp(pub.N) >= 0 {
		return newError(ErrCodeInvalidInput, "encoded message is not smaller than the modulus")
	}
	sigInt := new(big.Int).SetBytes(sig)
	if sigInt.Cmp(pub.N) >= 0 {
		return newError(ErrCodeInvalidInput, "signature is not reduced modulo N")
	}
	recovered := new(big.Int).Exp(sigInt, pub.E, pub.N)
	if recovered.Cmp(emInt) != 0 {
		return newError(ErrCodeVerifyFailed, "signature verification failed: sig^e does not reproduce the encoded message")
	}
	return nil
}

// EncodeEM builds the EMSA-PKCS1-v1_5 encoded message for a SHA-256 digest
// (RFC 8017, section 9.2) with a modulus of emLen bytes:
//
//	EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || digest,  PS = 0xFF…
//
// This is exactly what a stock RSA-SHA256 implementation encodes before the
// private exponentiation, so the combined mediated signature is
// byte-for-byte a standard one.
func EncodeEM(digest []byte, emLen int) ([]byte, error) {
	if len(digest) != 32 {
		return nil, newError(ErrCodeInvalidInput, "digest must be 32 bytes (SHA-256), got %d", len(digest))
	}
	t := len(sha256DigestInfoPrefix) + len(digest)
	if emLen < t+11 {
		return nil, newError(ErrCodeInvalidInput, "encoded message length %d is too small for SHA-256 (needs at least %d bytes)", emLen, t+11)
	}
	em := make([]byte, emLen)
	em[0], em[1] = 0x00, 0x01
	ps := emLen - t - 3
	for i := 2; i < 2+ps; i++ {
		em[i] = 0xFF
	}
	em[2+ps] = 0x00
	copy(em[3+ps:], sha256DigestInfoPrefix)
	copy(em[3+ps+len(sha256DigestInfoPrefix):], digest)
	return em, nil
}

// sha256DigestInfoPrefix is the DER DigestInfo header for a SHA-256 digest
// (RFC 8017, section 9.2, note 1).
var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20,
}

// carmichael returns λ(N) = lcm(p-1, q-1) for a two-prime modulus.
func carmichael(p, q *big.Int) *big.Int {
	p1 := new(big.Int).Sub(p, big.NewInt(1))
	q1 := new(big.Int).Sub(q, big.NewInt(1))
	g := new(big.Int).GCD(nil, nil, p1, q1)
	l := new(big.Int).Mul(p1, q1)
	return l.Div(l, g)
}

// randomBelow returns a uniform random integer in [1, bound).
func randomBelow(bound *big.Int) (*big.Int, error) {
	k := (bound.BitLen() + 7) / 8
	buf := make([]byte, k)
	for i := 0; i < 128; i++ {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		v := new(big.Int).SetBytes(buf)
		v.Mod(v, bound)
		if v.Sign() > 0 && v.Cmp(bound) < 0 {
			return v, nil
		}
	}
	return nil, errors.New("rejection sampling failed after 128 attempts")
}

func validateShare(share *KeyShare) error {
	if share == nil || share.N == nil || share.E == nil || share.DShare == nil {
		return newError(ErrCodeInvalidShare, "key share is missing modulus, exponent, or private share")
	}
	if share.N.Sign() <= 0 || share.E.Sign() <= 0 {
		return newError(ErrCodeInvalidShare, "key share has a zero modulus or exponent")
	}
	// The split routine guarantees 0 < d_i < λ(N); without the primes we can
	// only check the coarser bound d_i < N here.
	if share.DShare.Sign() <= 0 || share.DShare.Cmp(share.N) >= 0 {
		return newError(ErrCodeInvalidShare, "private share must be nonzero and smaller than the modulus")
	}
	return nil
}
