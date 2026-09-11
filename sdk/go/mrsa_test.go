package mrsa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// vector mirrors sdk/testdata/vector.json — a fixed 2048-bit mediated
// signing transcript shared by the Go, Python, and Rust SDK tests.
type vector struct {
	BitSize     int    `json:"bits"`
	N           string `json:"n"`
	E           string `json:"e"`
	DMember     string `json:"d_member"`
	DMediator   string `json:"d_mediator"`
	Digest      string `json:"digest"`
	EM          string `json:"em"`
	SigMember   string `json:"sig_member"`
	SigMediator string `json:"sig_mediator"`
	Signature   string `json:"signature"`
}

func loadVector(t *testing.T) *vector {
	t.Helper()
	raw, err := os.ReadFile("../testdata/vector.json")
	if err != nil {
		t.Fatalf("read vector.json: %v", err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector.json: %v", err)
	}
	return &v
}

func sharesFromVector(t *testing.T, v *vector) (pub PublicKey, member, mediator *KeyShare) {
	t.Helper()
	n := hexToBig(t, v.N)
	e := hexToBig(t, v.E)
	return PublicKey{N: n, E: e},
		&KeyShare{N: n, E: e, DShare: hexToBig(t, v.DMember)},
		&KeyShare{N: n, E: e, DShare: hexToBig(t, v.DMediator)}
}

// TestVector pins the cryptographic core against the shared cross-language
// vector: both partial signatures, their product, and the final standard
// RSA signature must match byte for byte.
func TestVector(t *testing.T) {
	v := loadVector(t)
	pub, member, mediator := sharesFromVector(t, v)
	em := mustHex(t, v.EM)

	if got, err := PartialSign(member, em); err != nil || string(got) != string(mustHex(t, v.SigMember)) {
		t.Fatalf("member partial signature mismatch (err=%v)", err)
	}
	if got, err := PartialSign(mediator, em); err != nil || string(got) != string(mustHex(t, v.SigMediator)) {
		t.Fatalf("mediator partial signature mismatch (err=%v)", err)
	}
	sig, err := Combine(mustHex(t, v.SigMember), mustHex(t, v.SigMediator), pub.N)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if hex.EncodeToString(sig) != v.Signature {
		t.Fatal("combined signature does not match vector")
	}
	if err := Verify(&pub, em, sig); err != nil {
		t.Fatalf("combined signature must verify as standard RSA: %v", err)
	}

	// A single party's partial signature must never verify.
	if err := Verify(&pub, em, mustHex(t, v.SigMember)); err == nil {
		t.Fatal("member partial signature alone must not verify")
	}
	if err := Verify(&pub, em, mustHex(t, v.SigMediator)); err == nil {
		t.Fatal("mediator partial signature alone must not verify")
	}
}

// TestEncodeEM pins the EMSA-PKCS1-v1_5 encoding against the vector.
func TestEncodeEM(t *testing.T) {
	v := loadVector(t)
	em, err := EncodeEM(mustHex(t, v.Digest), len(mustHex(t, v.N)))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(em) != v.EM {
		t.Fatal("EM encoding does not match vector")
	}
}

// TestFullMediatedFlow exercises the production-shaped round trip: key
// generation, split, member partial sign, mediator co-sign, combine, and
// standard verification.
func TestFullMediatedFlow(t *testing.T) {
	kp, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	member, mediator, err := kp.Split()
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if member.DShare.Cmp(mediator.DShare) == 0 {
		t.Fatal("shares must differ")
	}

	digest := sha256Digest(t)
	k := (kp.N.BitLen() + 7) / 8
	em, err := EncodeEM(digest, k)
	if err != nil {
		t.Fatal(err)
	}

	sM, err := PartialSign(member, em)
	if err != nil {
		t.Fatalf("member partial sign: %v", err)
	}
	sZ, err := PartialSign(mediator, em)
	if err != nil {
		t.Fatalf("mediator partial sign: %v", err)
	}
	sig, err := Combine(sM, sZ, kp.N)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	pub := PublicKey{N: kp.N, E: kp.E}
	if err := Verify(&pub, em, sig); err != nil {
		t.Fatalf("combined signature must verify: %v", err)
	}

	// A tampered signature must fail verification.
	tampered := append([]byte(nil), sig...)
	tampered[k/2] ^= 0xFF
	if err := Verify(&pub, em, tampered); err == nil {
		t.Fatal("tampered signature must not verify")
	}
}

// TestShareIndependence proves the isolation property: shares from a
// second key cannot co-sign with the first key's member share.
func TestShareIndependence(t *testing.T) {
	v := loadVector(t)
	_, member, _ := sharesFromVector(t, v)
	em := mustHex(t, v.EM)

	other, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	_, otherMediator, err := other.Split()
	if err != nil {
		t.Fatalf("split second key: %v", err)
	}

	sM, err := PartialSign(member, em)
	if err != nil {
		t.Fatal(err)
	}
	sZ, err := PartialSign(otherMediator, em)
	if err != nil {
		t.Fatal(err)
	}
	// Same modulus size, so Combine may succeed numerically — but the
	// product must never verify under the member's public key.
	if sig, err := Combine(sM, sZ, member.N); err == nil {
		if err := Verify(&PublicKey{N: member.N, E: member.E}, em, sig); err == nil {
			t.Fatal("signature co-signed with a foreign share must never verify")
		}
	}
}

// TestErrorCodes pins the cross-language error contract.
func TestErrorCodes(t *testing.T) {
	v := loadVector(t)
	pub, member, _ := sharesFromVector(t, v)
	em := mustHex(t, v.EM)

	cases := []struct {
		name string
		code ErrorCode
		err  error
	}{
		{"key too small", ErrCodeKeyGen, func() error { _, err := GenerateKeyPair(512); return err }()},
		{"empty EM", ErrCodeEmptyInput, func() error { _, err := PartialSign(member, nil); return err }()},
		{"bad EM size", ErrCodeInvalidInput, func() error { _, err := PartialSign(member, em[:10]); return err }()},
		{"EM too small for N", ErrCodeInvalidInput, func() error { _, err := PartialSign(member, []byte{0xFF, 0xFF}); return err }()},
		{"nil share", ErrCodeInvalidShare, func() error { _, err := PartialSign(nil, em); return err }()},
		{"share >= N", ErrCodeInvalidShare, func() error {
			_, err := PartialSign(&KeyShare{N: pub.N, E: pub.E, DShare: pub.N}, em)
			return err
		}()},
		{"combine length mismatch", ErrCodeCombineFailed, func() error {
			_, err := Combine(mustHex(t, v.SigMember), mustHex(t, v.SigMediator)[:10], pub.N)
			return err
		}()},
		{"combine empty", ErrCodeEmptyInput, func() error { _, err := Combine(nil, mustHex(t, v.SigMediator), pub.N); return err }()},
		{"verify wrong sig", ErrCodeVerifyFailed, Verify(&pub, em, mustHex(t, v.SigMember))},
		{"encode EM bad digest", ErrCodeInvalidInput, func() error { _, err := EncodeEM(make([]byte, 16), 256); return err }()},
		{"verify nil public key", ErrCodeInvalidKey, Verify(nil, em, mustHex(t, v.Signature))},
		{"verify empty sig", ErrCodeEmptyInput, Verify(&pub, em, nil)},
	}
	for _, tc := range cases {
		if tc.err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
			continue
		}
		code, ok := CodeOf(tc.err)
		if !ok {
			t.Errorf("%s: error is not an SDK error: %v", tc.name, tc.err)
			continue
		}
		if code != tc.code {
			t.Errorf("%s: got code %d (%s), want %d (%s): %v", tc.name, code, code.Name(), tc.code, tc.code.Name(), tc.err)
		}
	}
}

// TestErrorMessagesAreReadable ensures every SDK error renders a message a
// human can act on — the code alone is not enough.
func TestErrorMessagesAreReadable(t *testing.T) {
	_, err := PartialSign(nil, nil)
	want := "mrsa: INVALID_SHARE (code 1004): key share is missing modulus, exponent, or private share"
	if err == nil || err.Error() != want {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// ---------------------------------------------------------------- helpers

func sha256Digest(t *testing.T) []byte {
	t.Helper()
	d := sha256.Sum256([]byte(t.Name()))
	return d[:]
}

func hexToBig(t *testing.T, s string) *big.Int {
	t.Helper()
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad hex big.Int in vector: %s", s[:16])
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vector: %v", err)
	}
	return b
}
