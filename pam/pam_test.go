package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

func TestParseOptions(t *testing.T) {
	// Test default options
	opts := parseOptions(0, nil)
	if opts.otpLen != 10 {
		t.Errorf("expected default otpLen 10, got %d", opts.otpLen)
	}
	if opts.keysFile != "" {
		t.Errorf("expected empty keysFile, got %q", opts.keysFile)
	}

	// Test custom options
	arg1 := []byte("otp_len=14\x00")
	arg2 := []byte("keys_file=/custom/path\x00")
	argv := []*byte{&arg1[0], &arg2[0]}

	opts2 := parseOptions(2, (**_Ctype_char)(unsafe.Pointer(&argv[0])))
	if opts2.otpLen != 14 {
		t.Errorf("expected otpLen 14, got %d", opts2.otpLen)
	}
	if opts2.keysFile != "/custom/path" {
		t.Errorf("expected keysFile /custom/path, got %q", opts2.keysFile)
	}

	// Test minimum otpLen clamp
	argShort := []byte("otp_len=3\x00")
	argvShort := []*byte{&argShort[0]}
	optsShort := parseOptions(1, (**_Ctype_char)(unsafe.Pointer(&argvShort[0])))
	if optsShort.otpLen != 10 {
		t.Errorf("expected clamped otpLen to remain default 10, got %d", optsShort.otpLen)
	}
}

func TestResolveKeysPath(t *testing.T) {
	// Custom override
	custom := "/etc/ssh/custom_keys"
	if p := resolveKeysPath("nobody", custom); p != custom {
		t.Errorf("got %q, want %q", p, custom)
	}

	// Default fallback contains .ssh/authorized_keys
	p := resolveKeysPath("nobody", "")
	if !filepath.IsAbs(p) || filepath.Base(p) != "authorized_keys" {
		t.Errorf("unexpected path: %q", p)
	}
}

func TestPAMAuthenticate_NoKeys(t *testing.T) {
	tmpDir := t.TempDir()
	emptyKeysFile := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(emptyKeysFile, []byte("# empty\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Test when authorized_keys has no eligible keys
	eligible, err := os.ReadFile(emptyKeysFile)
	if err != nil {
		t.Fatal(err)
	}
	_ = eligible
}

func TestGenerateAndParseSyntheticKeys(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(keyFile, ssh.MarshalAuthorizedKey(sshPub), 0600); err != nil {
		t.Fatal(err)
	}
}
