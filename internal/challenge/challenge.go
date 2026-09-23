// Package challenge builds and verifies the SSH key challenge-response exchange.
//
// The PAM module calls Build to generate one Entry per eligible SSH key, then
// Format to display all entries to the user, and finally VerifyAny to check
// the user's OTP against every key's pre-computed shared secret.
package challenge

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pqsec/sshlogin/internal/ecdhutil"
	"github.com/pqsec/sshlogin/internal/keys"
)

// Entry holds one key's challenge: an ephemeral public key and the pre-computed
// ECDH shared secret that will be used to verify the user's OTP.
type Entry struct {
	Fingerprint  string
	CurveName    string
	EphemeralPub *ecdh.PublicKey
	SharedSecret []byte // ECDH(ephemeralPriv, userPub) — stored for verification
}

// nistXCoord returns the raw X coordinate bytes from an uncompressed NIST public
// key (which has the form 0x04 || X || Y). The X coordinate is the first half of
// the payload after the leading 0x04 byte.
func nistXCoord(pub *ecdh.PublicKey) []byte {
	raw := pub.Bytes() // 0x04 || X || Y
	n := (len(raw) - 1) / 2
	return raw[1 : 1+n]
}

// Token returns the copy-pasteable challenge token for this entry:
//
//	"<curveName>:<base64url(pubkey)>"
//
// For NIST curves the token encodes only the X coordinate of the ephemeral
// public key (32 bytes for P-256, 48 for P-384, 66 for P-521). Transmitting
// the Y coordinate is unnecessary because the ECDH shared secret on Weierstrass
// curves depends solely on the X coordinate of the scalar product, making both
// possible Y values (±Y) produce the same secret. This halves the token length
// versus uncompressed form.
// For X25519, Bytes() returns the 32-byte Montgomery u-coordinate directly.
func (e *Entry) Token() string {
	var payload []byte
	switch e.CurveName {
	case "nistp256", "nistp384", "nistp521":
		payload = nistXCoord(e.EphemeralPub)
	default: // x25519
		payload = e.EphemeralPub.Bytes()
	}
	return e.CurveName + ":" + base64.RawURLEncoding.EncodeToString(payload)
}

// ReconstructPublicKey parses raw bytes from a challenge token and returns the
// corresponding ecdh.PublicKey.
//
// For NIST curves the bytes are the X-coordinate only; the function always
// decompresses using the even Y (0x02 prefix). Because ECDH on Weierstrass
// curves uses only the X coordinate of the result, (X, Y) and (X, −Y) produce
// the same shared secret, so no sign bit needs to be transmitted.
// For X25519 the bytes are the 32-byte Montgomery u-coordinate passed directly.
func ReconstructPublicKey(curveName string, pubBytes []byte) (*ecdh.PublicKey, error) {
	switch curveName {
	case "x25519":
		return ecdh.X25519().NewPublicKey(pubBytes)
	case "nistp256":
		return decompressNIST(ecdh.P256(), elliptic.P256(), pubBytes)
	case "nistp384":
		return decompressNIST(ecdh.P384(), elliptic.P384(), pubBytes)
	case "nistp521":
		return decompressNIST(ecdh.P521(), elliptic.P521(), pubBytes)
	default:
		return nil, fmt.Errorf("unsupported curve %q", curveName)
	}
}

// decompressNIST reconstructs an ecdh.PublicKey from a raw X coordinate.
// It prepends 0x02 (even Y) to the X bytes, decompresses via crypto/elliptic,
// then marshals the result back to uncompressed form for crypto/ecdh.
func decompressNIST(ecdhCurve ecdh.Curve, ellipCurve elliptic.Curve, xBytes []byte) (*ecdh.PublicKey, error) {
	compressed := make([]byte, 1+len(xBytes))
	compressed[0] = 0x02
	copy(compressed[1:], xBytes)
	x, y := elliptic.UnmarshalCompressed(ellipCurve, compressed)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid X coordinate for curve")
	}
	return ecdhCurve.NewPublicKey(elliptic.Marshal(ellipCurve, x, y))
}


// Build generates one Entry per eligible key by creating a fresh ephemeral key
// pair and pre-computing the ECDH shared secret with each user public key.
func Build(eligible []keys.EligibleKey) ([]Entry, error) {
	entries := make([]Entry, 0, len(eligible))
	for _, k := range eligible {
		ephPriv, err := ecdhutil.GenerateEphemeral(k.ECDHPub)
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral key for %s: %w", k.Fingerprint, err)
		}
		secret, err := ecdhutil.SharedSecret(ephPriv, k.ECDHPub)
		if err != nil {
			return nil, fmt.Errorf("computing shared secret for %s: %w", k.Fingerprint, err)
		}
		entries = append(entries, Entry{
			Fingerprint:  k.Fingerprint,
			CurveName:    k.CurveName,
			EphemeralPub: ephPriv.PublicKey(),
			SharedSecret: secret,
		})
	}
	return entries, nil
}

// Format returns the multi-line challenge block to display to the user via the
// PAM conversation, including tokens for every eligible key and the OTP prompt.
func Format(entries []Entry, otpLen int) string {
	var sb strings.Builder
	sb.WriteString("sshlogin: use 'sshlogin-response -c <token>' to compute your OTP\n\n")
	for i, e := range entries {
		fmt.Fprintf(&sb, "  [%d] %s (%s)\n", i+1, e.Fingerprint, e.CurveName)
		fmt.Fprintf(&sb, "      %s\n\n", e.Token())
	}
	fmt.Fprintf(&sb, "Enter OTP (%d chars): ", otpLen)
	return sb.String()
}

// VerifyAny checks userOTP against every entry's shared secret.
// It always iterates all entries (no early exit on match) to avoid timing
// side-channels that would reveal how many keys produced a matching secret.
func VerifyAny(entries []Entry, otpLen int, userOTP string) bool {
	matched := false
	for _, e := range entries {
		if ecdhutil.VerifyOTP(e.SharedSecret, otpLen, userOTP) {
			matched = true
		}
	}
	return matched
}

// ParseToken decodes a "<curveName>:<base64url>" token into a curve name and
// raw public key bytes suitable for passing to ecdh.Curve.NewPublicKey.
func ParseToken(token string) (curveName string, pubBytes []byte, err error) {
	idx := strings.IndexByte(token, ':')
	if idx < 0 {
		return "", nil, fmt.Errorf("invalid token: missing ':'")
	}
	curveName = token[:idx]
	pubBytes, err = base64.RawURLEncoding.DecodeString(token[idx+1:])
	if err != nil {
		return "", nil, fmt.Errorf("decoding token pubkey: %w", err)
	}
	if curveName == "" || len(pubBytes) == 0 {
		return "", nil, fmt.Errorf("invalid token: empty curve name or pubkey")
	}
	return curveName, pubBytes, nil
}
