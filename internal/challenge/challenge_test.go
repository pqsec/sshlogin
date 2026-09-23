package challenge_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/pqsec/sshlogin/internal/challenge"
	"github.com/pqsec/sshlogin/internal/ecdhutil"
	"github.com/pqsec/sshlogin/internal/keys"
)

func TestParseToken_RoundTrip(t *testing.T) {
	curves := []struct {
		name    string
		curve   ecdh.Curve
		xLen    int // expected byte length of token payload
		b64Len  int // expected base64url length
	}{
		{"nistp256", ecdh.P256(), 32, 43},
		{"nistp384", ecdh.P384(), 48, 64},
		{"nistp521", ecdh.P521(), 66, 88},
		{"x25519", ecdh.X25519(), 32, 43},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			entry := challenge.Entry{
				CurveName:    tc.name,
				EphemeralPub: priv.PublicKey(),
			}

			tok := entry.Token()

			// Verify format: "<curveName>:<base64url>"
			parsedCurve, pubBytes, err := challenge.ParseToken(tok)
			if err != nil {
				t.Fatalf("ParseToken failed: %v", err)
			}
			if parsedCurve != tc.name {
				t.Errorf("curve name: got %q, want %q", parsedCurve, tc.name)
			}

			// Verify compact payload length
			if len(pubBytes) != tc.xLen {
				t.Errorf("payload length: got %d, want %d", len(pubBytes), tc.xLen)
			}
			b64Part := tok[len(tc.name)+1:]
			if len(b64Part) != tc.b64Len {
				t.Errorf("base64 token length: got %d, want %d", len(b64Part), tc.b64Len)
			}

			// Reconstruct and verify ECDH produces the same shared secret as the original
			reconstructed, err := challenge.ReconstructPublicKey(parsedCurve, pubBytes)
			if err != nil {
				t.Fatalf("ReconstructPublicKey failed: %v", err)
			}
			peer, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			secOrig, err := peer.ECDH(priv.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			secRecon, err := peer.ECDH(reconstructed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(secOrig, secRecon) {
				t.Errorf("ECDH shared secret mismatch after reconstruction")
			}
		})
	}
}

func TestParseToken_Invalid(t *testing.T) {
	invalids := []string{
		"",
		"invalid",
		":AAAA",
		"nistp256:",
		"nistp256:???not-base64???",
	}
	for _, inv := range invalids {
		if _, _, err := challenge.ParseToken(inv); err == nil {
			t.Errorf("expected error for token %q, got nil", inv)
		}
	}
}

func TestBuildAndVerifyAny(t *testing.T) {
	// Generate two keys: one NIST P-256, one X25519
	priv1, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	eligible := []keys.EligibleKey{
		{
			Fingerprint: "SHA256:key1",
			CurveName:   "nistp256",
			ECDHPub:     priv1.PublicKey(),
		},
		{
			Fingerprint: "SHA256:key2",
			CurveName:   "x25519",
			ECDHPub:     priv2.PublicKey(),
		},
	}

	entries, err := challenge.Build(eligible)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Test Format
	formatted := challenge.Format(entries, 10)
	if !strings.Contains(formatted, "SHA256:key1") || !strings.Contains(formatted, "SHA256:key2") {
		t.Fatalf("formatted challenge missing key fingerprints: %s", formatted)
	}
	if !strings.Contains(formatted, "Enter OTP (10 chars): ") {
		t.Fatalf("formatted prompt missing: %s", formatted)
	}

	// Client computes response for key 1
	secret1, err := ecdhutil.SharedSecret(priv1, entries[0].EphemeralPub)
	if err != nil {
		t.Fatal(err)
	}
	otp1 := ecdhutil.DeriveOTP(secret1, 10)

	// Client computes response for key 2
	secret2, err := ecdhutil.SharedSecret(priv2, entries[1].EphemeralPub)
	if err != nil {
		t.Fatal(err)
	}
	otp2 := ecdhutil.DeriveOTP(secret2, 10)

	// Both OTPs should verify successfully
	if !challenge.VerifyAny(entries, 10, otp1) {
		t.Errorf("VerifyAny failed on otp1")
	}
	if !challenge.VerifyAny(entries, 10, otp2) {
		t.Errorf("VerifyAny failed on otp2")
	}

	// Bogus OTP should fail
	if challenge.VerifyAny(entries, 10, "bogusOTP12") {
		t.Errorf("VerifyAny succeeded on bogus OTP")
	}
}
