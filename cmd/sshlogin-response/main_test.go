package main_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/pqsec/sshlogin/internal/challenge"
	"github.com/pqsec/sshlogin/internal/keys"
)

func writeKeyPEM(t *testing.T, path string, privKey any) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func TestResponseCLI_ECDSA_and_Ed25519(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Generate P-256 key
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKeyPath := filepath.Join(tmpDir, "id_ecdsa")
	writeKeyPEM(t, ecKeyPath, ecPriv)

	ecSSHPub, err := ssh.NewPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Generate Ed25519 key
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edKeyPath := filepath.Join(tmpDir, "id_ed25519")
	writeKeyPEM(t, edKeyPath, edPriv)

	edSSHPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Write authorized_keys
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	authKeysContent := append(ssh.MarshalAuthorizedKey(ecSSHPub), ssh.MarshalAuthorizedKey(edSSHPub)...)
	if err := os.WriteFile(authKeysPath, authKeysContent, 0600); err != nil {
		t.Fatal(err)
	}

	// 4. Parse authorized_keys (server side)
	eligible, err := keys.ParseAuthorizedKeys(authKeysPath)
	if err != nil {
		t.Fatalf("ParseAuthorizedKeys: %v", err)
	}
	if len(eligible) != 2 {
		t.Fatalf("expected 2 eligible keys, got %d", len(eligible))
	}

	// 5. Server builds challenges
	entries, err := challenge.Build(eligible)
	if err != nil {
		t.Fatalf("challenge.Build: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// 6. Build response binary if not built
	binPath := filepath.Join(tmpDir, "sshlogin-response")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/sshlogin-response")
	buildCmd.Dir = "../.." // from cmd/sshlogin-response to module root
	// Since we are in cmd/sshlogin-response package, let's use absolute or relative path
	// Actually go test runs in package directory: sshlogin/cmd/sshlogin-response
	buildCmd = exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, string(out))
	}

	// 7. Test response with ECDSA key
	token1 := entries[0].Token()
	cmd1 := exec.Command(binPath, "-i", ecKeyPath, "-c", token1, "-n", "10")
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		t.Fatalf("sshlogin-response for ec key: %v: %s", err, string(out1))
	}
	otp1 := strings.TrimSpace(string(out1))
	if len(otp1) != 10 {
		t.Fatalf("expected OTP len 10, got %q (len %d)", otp1, len(otp1))
	}
	if !challenge.VerifyAny(entries, 10, otp1) {
		t.Errorf("VerifyAny failed on ECDSA OTP %q", otp1)
	}

	// 8. Test response with Ed25519 key
	token2 := entries[1].Token()
	cmd2 := exec.Command(binPath, "-i", edKeyPath, "-c", token2, "-n", "10")
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("sshlogin-response for ed25519 key: %v: %s", err, string(out2))
	}
	otp2 := strings.TrimSpace(string(out2))
	if len(otp2) != 10 {
		t.Fatalf("expected OTP len 10, got %q (len %d)", otp2, len(otp2))
	}
	if !challenge.VerifyAny(entries, 10, otp2) {
		t.Errorf("VerifyAny failed on Ed25519 OTP %q", otp2)
	}

	// 9. Negative test: wrong key used for token
	// Try responding to token1 (ECDSA) with edKeyPath (Ed25519)
	cmdBad := exec.Command(binPath, "-i", edKeyPath, "-c", token1, "-n", "10")
	outBad, _ := cmdBad.CombinedOutput()
	// Since curves differ (nistp256 vs x25519), loadKey will return x25519, but ephPub is nistp256,
	// so ecdhutil.SharedSecret will fail with curve mismatch.
	// Let's verify it failed or didn't verify.
	otpBad := strings.TrimSpace(string(outBad))
	if challenge.VerifyAny(entries, 10, otpBad) {
		t.Errorf("expected cross-key challenge response to fail, but it succeeded")
	}
}
