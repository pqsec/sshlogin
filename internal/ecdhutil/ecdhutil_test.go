package ecdhutil_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/pqsec/sshlogin/internal/ecdhutil"
)

func testCurveRoundTrip(t *testing.T, curve ecdh.Curve) {
	t.Helper()
	// User key
	userPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPriv.PublicKey()

	// Server ephemeral key
	ephPriv, err := ecdhutil.GenerateEphemeral(userPub)
	if err != nil {
		t.Fatal(err)
	}
	ephPub := ephPriv.PublicKey()

	// Server ECDH
	serverSecret, err := ecdhutil.SharedSecret(ephPriv, userPub)
	if err != nil {
		t.Fatal(err)
	}

	// Client ECDH
	clientSecret, err := ecdhutil.SharedSecret(userPriv, ephPub)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(serverSecret, clientSecret) {
		t.Fatalf("ECDH secrets do not match")
	}

	// Verify OTP
	otpLen := 10
	clientOTP := ecdhutil.DeriveOTP(clientSecret, otpLen)
	if len(clientOTP) != otpLen {
		t.Fatalf("expected OTP length %d, got %d", otpLen, len(clientOTP))
	}

	if !ecdhutil.VerifyOTP(serverSecret, otpLen, clientOTP) {
		t.Fatalf("VerifyOTP failed on valid OTP")
	}

	// Verify failure on altered OTP
	badOTP := []byte(clientOTP)
	if badOTP[0] == 'a' {
		badOTP[0] = 'b'
	} else {
		badOTP[0] = 'a'
	}
	if ecdhutil.VerifyOTP(serverSecret, otpLen, string(badOTP)) {
		t.Fatalf("VerifyOTP succeeded on bad OTP")
	}

	// Verify failure on wrong length
	if ecdhutil.VerifyOTP(serverSecret, otpLen, clientOTP[:otpLen-1]) {
		t.Fatalf("VerifyOTP succeeded on shortened OTP")
	}
}

func TestECDHRoundTrip_P256(t *testing.T) {
	testCurveRoundTrip(t, ecdh.P256())
}

func TestECDHRoundTrip_P384(t *testing.T) {
	testCurveRoundTrip(t, ecdh.P384())
}

func TestECDHRoundTrip_P521(t *testing.T) {
	testCurveRoundTrip(t, ecdh.P521())
}

func TestECDHRoundTrip_X25519(t *testing.T) {
	testCurveRoundTrip(t, ecdh.X25519())
}

func TestDeriveOTP_KnownVector(t *testing.T) {
	// 32-byte known vector
	secret := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	// HKDF-SHA256 (salt=nil, info="sshlogin-otp-v1")
	got := ecdhutil.DeriveOTP(secret, 10)
	want := "gyQ6yX2ZKg"
	if got != want {
		t.Fatalf("DeriveOTP: got %q, want %q", got, want)
	}

	// Verify requested length is respected up to 100 characters
	gotFull := ecdhutil.DeriveOTP(secret, 100)
	if len(gotFull) != 100 {
		t.Fatalf("expected len 100, got %d", len(gotFull))
	}

	// Verify prefix consistency: shorter OTPs are strict prefixes of longer OTPs
	if gotFull[:10] != want {
		t.Fatalf("prefix mismatch: gotFull[:10]=%q, want=%q", gotFull[:10], want)
	}

	for _, n := range []int{6, 10, 16, 32, 44, 50} {
		otp := ecdhutil.DeriveOTP(secret, n)
		if len(otp) != n {
			t.Errorf("expected len %d, got %d", n, len(otp))
		}
		if gotFull[:n] != otp {
			t.Errorf("DeriveOTP(secret, %d)=%q is not prefix of %q", n, otp, gotFull)
		}
	}
}

func TestDeriveOTP_P521_NotFixedPrefix(t *testing.T) {
	curve := ecdh.P521()
	firstChars := make(map[byte]bool)

	for i := 0; i < 20; i++ {
		k1, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := k1.ECDH(k2.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		otp := ecdhutil.DeriveOTP(secret, 10)
		if len(otp) != 10 {
			t.Fatalf("expected len 10, got %d", len(otp))
		}
		firstChars[otp[0]] = true
	}

	// Without HKDF, every P-521 secret starts with 7 zero bits, making the first
	// base64 character always 'A' (len(firstChars) == 1). With HKDF, first characters
	// are pseudorandomly distributed.
	if len(firstChars) <= 1 {
		t.Fatalf("expected diverse first characters for P-521 OTPs, got: %v", firstChars)
	}
}
