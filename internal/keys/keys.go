// Package keys parses SSH authorized_keys files and converts ECDSA and Ed25519
// public keys into the crypto/ecdh representation required for challenge generation.
package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"os"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

// EligibleKey is one authorized_keys entry converted to ECDH-ready form.
type EligibleKey struct {
	Fingerprint string          // e.g. "SHA256:abc...xyz"
	CurveName   string          // "nistp256" | "nistp384" | "nistp521" | "x25519"
	ECDHPub     *ecdh.PublicKey // ready for crypto/ecdh key exchange
}

// ParseAuthorizedKeys reads an authorized_keys file and returns all
// ecdsa-sha2-nistp{256,384,521} and ssh-ed25519 entries.
// Lines with unsupported key types (RSA, DSA, etc.) are silently skipped.
func ParseAuthorizedKeys(path string) ([]EligibleKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result []EligibleKey
	rest := data
	for len(rest) > 0 {
		pub, _, _, remaining, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		rest = remaining

		key, err := convertKey(pub)
		if err != nil {
			continue // unsupported type — skip silently
		}
		result = append(result, key)
	}
	return result, nil
}

// convertKey converts a parsed ssh.PublicKey to an EligibleKey.
// Returns an error for unsupported key types.
func convertKey(pub ssh.PublicKey) (EligibleKey, error) {
	cp, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return EligibleKey{}, fmt.Errorf("key does not implement ssh.CryptoPublicKey")
	}

	fp := ssh.FingerprintSHA256(pub)

	switch k := cp.CryptoPublicKey().(type) {
	case *ecdsa.PublicKey:
		curveName, ecdhPub, err := ECDSAPubToECDH(k)
		if err != nil {
			return EligibleKey{}, err
		}
		return EligibleKey{
			Fingerprint: fp,
			CurveName:   curveName,
			ECDHPub:     ecdhPub,
		}, nil

	case ed25519.PublicKey:
		ecdhPub, err := Ed25519PubToX25519(k)
		if err != nil {
			return EligibleKey{}, err
		}
		return EligibleKey{
			Fingerprint: fp,
			CurveName:   "x25519",
			ECDHPub:     ecdhPub,
		}, nil

	default:
		return EligibleKey{}, fmt.Errorf("unsupported key type: %T", k)
	}
}

// ECDSAPubToECDH converts an ECDSA public key to a curve name and ecdh.PublicKey.
// Supported curves: P-256, P-384, P-521.
func ECDSAPubToECDH(pub *ecdsa.PublicKey) (curveName string, ecdhPub *ecdh.PublicKey, err error) {
	switch pub.Curve.Params().Name {
	case "P-256":
		curveName = "nistp256"
	case "P-384":
		curveName = "nistp384"
	case "P-521":
		curveName = "nistp521"
	default:
		return "", nil, fmt.Errorf("unsupported ECDSA curve: %s", pub.Curve.Params().Name)
	}

	ecdhPub, err = pub.ECDH()
	if err != nil {
		return "", nil, fmt.Errorf("converting to ECDH key: %w", err)
	}
	return curveName, ecdhPub, nil
}

// Ed25519PubToX25519 converts an Ed25519 public key to an X25519 ecdh.PublicKey
// via the canonical Edwards→Montgomery birational map: u = (1+y)/(1-y) in GF(2²⁵⁵-19).
// This allows ECDH using the same key material as an Ed25519 signing key.
func Ed25519PubToX25519(pub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing Ed25519 point: %w", err)
	}
	return ecdh.X25519().NewPublicKey(p.BytesMontgomery())
}
