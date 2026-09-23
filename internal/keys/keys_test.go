package keys_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/pqsec/sshlogin/internal/keys"
)

// makeAuthorizedKeysFile writes a synthetic authorized_keys file containing
// the given SSH public keys and returns the file path.
func makeAuthorizedKeysFile(t *testing.T, pubs ...ssh.PublicKey) string {
	t.Helper()
	var content []byte
	for _, pub := range pubs {
		content = append(content, ssh.MarshalAuthorizedKey(pub)...)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseAuthorizedKeys_ECDSA_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	path := makeAuthorizedKeysFile(t, pub)
	got, err := keys.ParseAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	if got[0].CurveName != "nistp256" {
		t.Errorf("want curveName=nistp256, got %s", got[0].CurveName)
	}
	if got[0].ECDHPub == nil {
		t.Error("ECDHPub is nil")
	}
}

func TestParseAuthorizedKeys_Ed25519(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}

	path := makeAuthorizedKeysFile(t, pub)
	got, err := keys.ParseAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
	if got[0].CurveName != "x25519" {
		t.Errorf("want curveName=x25519, got %s", got[0].CurveName)
	}
}

func TestParseAuthorizedKeys_MultipleKeys(t *testing.T) {
	// P-256 ECDSA
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPub, err := ssh.NewPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Ed25519
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSSHPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}

	// P-384 ECDSA
	ec384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384Pub, err := ssh.NewPublicKey(&ec384Priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	path := makeAuthorizedKeysFile(t, ecPub, edSSHPub, ec384Pub)
	got, err := keys.ParseAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 keys, got %d", len(got))
	}

	wantCurves := []string{"nistp256", "x25519", "nistp384"}
	for i, ek := range got {
		if ek.CurveName != wantCurves[i] {
			t.Errorf("key[%d]: want curve %s, got %s", i, wantCurves[i], ek.CurveName)
		}
		if ek.ECDHPub == nil {
			t.Errorf("key[%d]: ECDHPub is nil", i)
		}
		if ek.Fingerprint == "" {
			t.Errorf("key[%d]: Fingerprint is empty", i)
		}
	}
}

func TestParseAuthorizedKeys_MissingFile(t *testing.T) {
	_, err := keys.ParseAuthorizedKeys("/nonexistent/path/authorized_keys")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestParseAuthorizedKeys_SkipsUnsupportedKeys(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("# this is a comment\n")
	content = append(content, ssh.MarshalAuthorizedKey(pub)...)

	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := keys.ParseAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 key, got %d", len(got))
	}
}

func TestEd25519PubToX25519_RoundTrip(t *testing.T) {
	// Generate an Ed25519 key pair (user's SSH key)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Server-side: convert Ed25519 public key → X25519 public key
	serverSideX25519Pub, err := keys.Ed25519PubToX25519(edPub)
	if err != nil {
		t.Fatalf("Ed25519PubToX25519: %v", err)
	}

	// Server-side: generate ephemeral X25519 key pair
	ephPriv, err := serverSideX25519Pub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Server-side: compute shared secret (ephemeralPriv × userX25519Pub)
	serverSecret, err := ephPriv.ECDH(serverSideX25519Pub)
	if err != nil {
		t.Fatalf("server ECDH: %v", err)
	}

	// Client-side: derive X25519 scalar from Ed25519 private key
	seed := edPriv[:32]
	h := sha512.Sum512(seed)
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	clientPriv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("client X25519 NewPrivateKey: %v", err)
	}

	// Client-side: compute shared secret (clientX25519Priv × ephemeralPub)
	clientSecret, err := clientPriv.ECDH(ephPriv.PublicKey())
	if err != nil {
		t.Fatalf("client ECDH: %v", err)
	}

	if !bytes.Equal(serverSecret, clientSecret) {
		t.Fatalf("shared secrets do not match:\nserver: %x\nclient: %x", serverSecret, clientSecret)
	}
}
