package tplengine

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

func TestHashAndVerifyRoundTrip(t *testing.T) {
	for _, scheme := range []string{"SSHA512", "SSHA256", "SSHA", "SHA512", "SHA256", "SHA", "ARGON2ID"} {
		hashed, err := HashPassword(scheme, "NewPass#2026")
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		prefix := "{" + scheme + "}"
		if scheme == "ARGON2ID" {
			prefix = "{ARGON2}"
		}
		if !strings.HasPrefix(hashed, prefix) {
			t.Errorf("%s prefix: %q", scheme, hashed)
		}
		if !VerifyPassword(hashed, "NewPass#2026") {
			t.Errorf("%s: verify failed", scheme)
		}
		if VerifyPassword(hashed, "wrong") {
			t.Errorf("%s: wrong password accepted", scheme)
		}
	}
}

func TestSSHASaltRandomness(t *testing.T) {
	a, _ := HashPassword("SSHA512", "same")
	b, _ := HashPassword("SSHA512", "same")
	if a == b {
		t.Error("salted hashes must differ across calls")
	}
}

func TestMD4Empty(t *testing.T) {
	// RFC 1320 test vector: MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0.
	// Our MD4 hashes the UTF-16LE encoding; for the empty string that is the
	// empty digest, matching the RFC vector.
	hashed, err := HashPassword("MD4", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(hashed, "{MD4}"))
	if hex.EncodeToString(raw) != "31d6cfe0d16ae931b73c59d7e0c089c0" {
		t.Errorf("md4 empty = %x", raw)
	}
	if !VerifyPassword(hashed, "") {
		t.Error("md4 verify failed")
	}
}

func TestWriteAllowlistEnforced(t *testing.T) {
	for _, scheme := range []string{"MD5", "SMD5", "CRYPT", "BLOWFISH", "SHA256CRYPT", "SHA512CRYPT", "MD5CRYPT", "PLAIN"} {
		if _, err := HashPassword(scheme, "x"); err == nil {
			t.Errorf("%s should be read-only", scheme)
		}
	}
	if _, err := HashPassword("BOGUS", "x"); err == nil {
		t.Error("unknown scheme should error")
	}
}

func TestPlainOverride(t *testing.T) {
	if _, err := HashPassword("PLAIN", "pw"); err == nil {
		t.Fatal("plain must be rejected without override")
	}
	got, err := HashPasswordWithOverride("PLAIN", "pw", true, nil)
	if err != nil || got != "pw" {
		t.Errorf("override = %q, %v", got, err)
	}
}

func TestDetectScheme(t *testing.T) {
	cases := map[string]string{
		"{SSHA}abc":    "SSHA",
		"{ssha512}abc": "SSHA512",
		"{ARGON2}$x":   "ARGON2",
		"plaintext":    "PLAIN",
		"{":            "PLAIN",
	}
	for in, want := range cases {
		if got := DetectScheme(in); got != want {
			t.Errorf("DetectScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifyLegacySchemes(t *testing.T) {
	// bcrypt ($2a$ prefix) read-side verification (KTD 6 BLOWFISH read-only).
	bc, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("{BLOWFISH}"+string(bc), "password") {
		t.Error("bcrypt verify failed")
	}
	if VerifyPassword("{BLOWFISH}"+string(bc), "nope") {
		t.Error("bcrypt accepted wrong password")
	}

	// crypt SHA-512 round-trip through GehirnInc.
	c := crypt.New(crypt.SHA512)
	hash, err := c.Generate([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("{CRYPT}"+hash, "secret") {
		t.Error("crypt sha512 verify failed")
	}
	if VerifyPassword("{CRYPT}"+hash, "nope") {
		t.Error("crypt accepted wrong password")
	}
}

func TestPasswordEncryptionTypesList(t *testing.T) {
	vals := passwordEncryptionTypes()
	if len(vals) < 8 {
		t.Errorf("scheme list too small: %d", len(vals))
	}
	seen := map[string]bool{}
	for _, v := range vals {
		seen[v.ID] = true
	}
	if !seen["SSHA512"] || !seen["ARGON2ID"] {
		t.Errorf("scheme list missing defaults: %v", seen)
	}
}
