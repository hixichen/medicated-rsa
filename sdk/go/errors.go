package mrsa

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable, machine-readable error code shared by every
// medicated-rsa SDK (Go, Python, Rust). See sdk/README.md for the table.
type ErrorCode int

const (
	// Key management errors (1xxx).
	ErrCodeInvalidKey   ErrorCode = 1001 // malformed or unusable RSA key material
	ErrCodeKeyGen       ErrorCode = 1002 // RSA key generation failed
	ErrCodeSplitFailed  ErrorCode = 1003 // private exponent could not be split
	ErrCodeInvalidShare ErrorCode = 1004 // malformed key share (zero, or not reduced)

	// Signing errors (2xxx).
	ErrCodePartialSignFailed ErrorCode = 2001 // partial signing failed
	ErrCodeCombineFailed     ErrorCode = 2002 // partial signatures incompatible (length/modulus mismatch)

	// Verification errors (3xxx).
	ErrCodeVerifyFailed ErrorCode = 3001 // signature failed verification

	// Input errors (4xxx).
	ErrCodeEmptyInput   ErrorCode = 4001 // a required input was empty
	ErrCodeInvalidInput ErrorCode = 4002 // input malformed (bad length or value)
)

var errorCodeNames = map[ErrorCode]string{
	ErrCodeInvalidKey:        "INVALID_KEY",
	ErrCodeKeyGen:            "KEY_GEN_FAILED",
	ErrCodeSplitFailed:       "SPLIT_FAILED",
	ErrCodeInvalidShare:      "INVALID_SHARE",
	ErrCodePartialSignFailed: "PARTIAL_SIGN_FAILED",
	ErrCodeCombineFailed:     "COMBINE_FAILED",
	ErrCodeVerifyFailed:      "VERIFY_FAILED",
	ErrCodeEmptyInput:        "EMPTY_INPUT",
	ErrCodeInvalidInput:      "INVALID_INPUT",
}

// Name returns the stable textual name for the code.
func (c ErrorCode) Name() string {
	if n, ok := errorCodeNames[c]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN_%d", int(c))
}

// Error is the concrete error type returned by this package. It always
// carries a cross-language ErrorCode and a human-readable message.
type Error struct {
	Code    ErrorCode
	Name    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("mrsa: %s (code %d): %s", e.Name, int(e.Code), e.Message)
}

func newError(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Name: code.Name(), Message: fmt.Sprintf(format, args...)}
}

// CodeOf extracts the SDK error code from err. It returns false if err is
// not a medicated-rsa error.
func CodeOf(err error) (ErrorCode, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Code, true
	}
	return 0, false
}
