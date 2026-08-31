package session

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	testKeyB64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // "0123456789abcdef0123456789abcdef"
)

var testKeyRawB64 = strings.TrimSuffix(testKeyB64, "==")

func newTestCipher(t *testing.T) *CredentialCipher {
	t.Helper()
	c, err := NewCredentialCipher(testKeyB64)
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}
	return c
}

func TestCredentialRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	secret := []byte("correct horse battery staple")
	env, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(env, secret) {
		t.Fatal("envelope contains plaintext")
	}
	got, err := c.Decrypt(env)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("round-trip mismatch: %q", got)
	}
}

func TestCredentialRandomNonce(t *testing.T) {
	c := newTestCipher(t)
	a, err := c.Encrypt([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encrypt([]byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two encryptions of the same plaintext must differ (random nonce)")
	}
}

func TestCredentialEmptyAndLong(t *testing.T) {
	c := newTestCipher(t)
	for _, in := range [][]byte{nil, {}, bytes.Repeat([]byte("x"), 4096)} {
		env, err := c.Encrypt(in)
		if err != nil {
			t.Fatalf("Encrypt(%d bytes): %v", len(in), err)
		}
		got, err := c.Decrypt(env)
		if err != nil {
			t.Fatalf("Decrypt(%d bytes): %v", len(in), err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("round-trip mismatch for %d bytes", len(in))
		}
	}
}

func TestCredentialTamper(t *testing.T) {
	c := newTestCipher(t)
	env, err := c.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"version byte": func(b []byte) []byte { b[0] ^= 0xff; return b },
		"nonce byte":   func(b []byte) []byte { b[1] ^= 0xff; return b },
		"cipher byte":  func(b []byte) []byte { b[len(b)-1] ^= 0xff; return b },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cp := append([]byte(nil), env...)
			_, err := c.Decrypt(mutate(cp))
			if err == nil {
				t.Fatal("tampered envelope decrypted successfully")
			}
			if errors.Is(err, ErrCredentialCorrupt) || errors.Is(err, ErrCredentialKeyMismatch) {
				return
			}
			t.Errorf("unexpected error class: %v", err)
		})
	}
}

func TestCredentialWrongKey(t *testing.T) {
	c := newTestCipher(t)
	env, err := c.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCredentialCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Decrypt(env); !errors.Is(err, ErrCredentialKeyMismatch) {
		t.Fatalf("want ErrCredentialKeyMismatch, got %v", err)
	}
}

func TestCredentialCorruptEnvelope(t *testing.T) {
	c := newTestCipher(t)
	for _, in := range [][]byte{nil, {0x01}, {0x02}, make([]byte, 12), []byte("short")} {
		if _, err := c.Decrypt(in); !errors.Is(err, ErrCredentialCorrupt) {
			t.Errorf("Decrypt(%d bytes) = %v, want ErrCredentialCorrupt", len(in), err)
		}
	}
}

func TestCredentialKeyValidation(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"not base64", "!!!not-base64!!!"},
		{"too short", "aGVsbG8="},            // 5 bytes
		{"wrong length", "aGVsbG8gd29ybGQ="}, // 11 bytes
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCredentialCipher(tc.key); err == nil {
				t.Fatal("want key validation error")
			}
		})
	}
}

func TestCredentialRawBase64Key(t *testing.T) {
	c, err := NewCredentialCipher(testKeyRawB64)
	if err != nil {
		t.Fatalf("raw base64 key rejected: %v", err)
	}
	env, err := c.Encrypt([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(env); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
}

func TestCredentialFingerprintRedacted(t *testing.T) {
	c := newTestCipher(t)
	fp := c.KeyFingerprint()
	if fp == "" || strings.Contains(fp, testKeyB64) {
		t.Errorf("fingerprint %q must not leak the key", fp)
	}
}
