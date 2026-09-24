// sshlogin-response computes the OTP for an sshlogin PAM challenge.
//
// The user runs this on their local machine (where the SSH private key lives),
// copies the challenge token from the server's serial console prompt, and
// types the printed OTP back at the server.
//
// Usage:
//
//	sshlogin-response -c <token> [-i <keyfile>] [-n <otplen>]
//
// Example:
//
//	sshlogin-response -c "x25519:AAAA..." -i ~/.ssh/id_ed25519
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha512"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/pqsec/sshlogin/internal/challenge"
	"github.com/pqsec/sshlogin/internal/ecdhutil"
)

func main() {
	var (
		identity = flag.String("i", "", "SSH private key path (auto-detected from ~/.ssh if omitted)")
		token    = flag.String("c", "", "Challenge token from the PAM prompt, e.g. \"nistp256:AAAA...\"")
		otpLen   = flag.Int("n", ecdhutil.DefaultOTPLen, "OTP character length (must match server otp_len)")
	)
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "usage: sshlogin-response -c <token> [-i <keyfile>] [-n <otplen>]")
		os.Exit(1)
	}

	// Parse the challenge token into curve name + raw ephemeral public key bytes.
	curveName, pubBytes, err := challenge.ParseToken(*token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid token: %v\n", err)
		os.Exit(1)
	}

	// Select the ECDH curve.
	// Reconstruct the server's ephemeral public key from the X-coordinate in the token.
	ephPub, err := challenge.ReconstructPublicKey(curveName, pubBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid ephemeral public key: %v\n", err)
		os.Exit(1)
	}

	// Resolve the private key path.
	keyPath := *identity
	if keyPath == "" {
		keyPath = findDefaultKey()
	}
	if keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: no SSH private key found; specify with -i")
		os.Exit(1)
	}

	// Load and convert the private key to an ECDH key.
	privKey, err := loadKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading %s: %v\n", keyPath, err)
		os.Exit(1)
	}

	// Perform ECDH and derive the OTP.
	secret, err := ecdhutil.SharedSecret(privKey, ephPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: ECDH failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(ecdhutil.DeriveOTP(secret, *otpLen))
}

// findDefaultKey searches ~/.ssh for the first supported private key file.
func findDefaultKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ecdsa", "id_ed25519"} {
		p := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// loadKey reads an OpenSSH private key from path and returns it as an
// ecdh.PrivateKey. If the key is passphrase-protected, the passphrase is
// read from the terminal. Supports ECDSA (P-256/384/521) and Ed25519.
func loadKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	rawKey, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		// Handle passphrase-protected keys gracefully.
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", path)
			passphrase, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr) // newline after hidden input
			if readErr != nil {
				return nil, fmt.Errorf("reading passphrase: %w", readErr)
			}
			rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
			if err != nil {
				return nil, fmt.Errorf("decrypting private key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
	}

	return toECDHKey(rawKey)
}

// toECDHKey converts a crypto.PrivateKey (as returned by ssh.ParseRawPrivateKey)
// to an ecdh.PrivateKey. Only ECDSA and Ed25519 keys are supported.
func toECDHKey(rawKey interface{}) (*ecdh.PrivateKey, error) {
	switch k := rawKey.(type) {
	case *ecdsa.PrivateKey:
		// crypto/ecdsa.PrivateKey gained ECDH() in Go 1.20.
		return k.ECDH()

	case ed25519.PrivateKey:
		return ed25519PrivToX25519(k)

	case *ed25519.PrivateKey:
		return ed25519PrivToX25519(*k)

	default:
		return nil, fmt.Errorf("unsupported key type %T (only ECDSA and Ed25519 are supported)", rawKey)
	}
}

// ed25519PrivToX25519 converts an Ed25519 private key to an X25519 private key.
//
// An Ed25519 private key is a 64-byte blob: seed (32 bytes) || public key (32 bytes).
// The X25519 scalar is derived by hashing the seed with SHA-512 and applying the
// Montgomery clamping specified in RFC 7748 §5.
func ed25519PrivToX25519(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(priv))
	}
	seed := priv[:32] // first 32 bytes are the seed
	h := sha512.Sum512(seed)
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
	// RFC 7748 §5 clamping for X25519 scalars:
	scalar[0] &= 248  // clear bottom 3 bits (cofactor of the curve is 8)
	scalar[31] &= 127 // clear the top bit
	scalar[31] |= 64  // set the second-highest bit
	return ecdh.X25519().NewPrivateKey(scalar)
}
