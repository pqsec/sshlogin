// Package ecdhutil provides helpers for ephemeral ECDH key generation,
// shared-secret computation, and OTP derivation/verification.
package ecdhutil

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// DefaultOTPLen is the default number of base64url characters used for the OTP.
	DefaultOTPLen = 10
	// MinOTPLen is the minimum acceptable OTP length (enforced when parsing PAM options).
	MinOTPLen = 6

	// hkdfInfo is the domain-separation context string for HKDF OTP derivation.
	hkdfInfo = "sshlogin-otp-v1"
)

// GenerateEphemeral returns a fresh ephemeral ECDH private key on the same
// curve as pub (P-256, P-384, P-521, or X25519).
func GenerateEphemeral(pub *ecdh.PublicKey) (*ecdh.PrivateKey, error) {
	return pub.Curve().GenerateKey(rand.Reader)
}

// SharedSecret computes the ECDH shared secret between priv and peer.
// For NIST curves this is the X-coordinate of the scalar product.
// For X25519 this is the 32-byte RFC 7748 output.
func SharedSecret(priv *ecdh.PrivateKey, peer *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(peer)
}

// DeriveOTP derives an OTP from secret using HKDF-SHA256 (RFC 5869) with domain
// separation, encodes the derived key material as unpadded base64url, and returns
// the first otpLen characters.
//
// The base64url alphabet uses '-' and '_' instead of '+' and '/', with no trailing
// '=' padding — safe for serial-console input.
func DeriveOTP(secret []byte, otpLen int) string {
	if otpLen <= 0 {
		return ""
	}
	// Each 3 bytes produces 4 base64 characters without padding.
	// Rounding up the byte count to a multiple of 3 ensures that every 3-byte chunk
	// encodes independently, so DeriveOTP(secret, N) is always a strict prefix of
	// DeriveOTP(secret, M) for any N < M.
	nBytes := 33 // minimum 33 bytes (264 bits), yields 44 base64 characters
	if req := ((otpLen*6+7)/8 + 2) / 3 * 3; req > nBytes {
		nBytes = req
	}
	kdf := hkdf.New(sha256.New, secret, nil, []byte(hkdfInfo))
	derived := make([]byte, nBytes)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		panic(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(derived)
	if otpLen > len(encoded) {
		otpLen = len(encoded)
	}
	return encoded[:otpLen]
}

// VerifyOTP returns true if userOTP matches the OTP derived from secret in
// constant time. Length mismatch is detected before the constant-time compare
// because length is not secret information.
func VerifyOTP(secret []byte, otpLen int, userOTP string) bool {
	if len(userOTP) != otpLen {
		return false
	}
	expected := []byte(DeriveOTP(secret, otpLen))
	return subtle.ConstantTimeCompare(expected, []byte(userOTP)) == 1
}
