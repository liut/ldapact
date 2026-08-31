package tplengine

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf16"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 required for AD userPassword compatibility (KTD 6)
)

// DefaultHashScheme is the write default per KTD 6 (SSHA512 preferred).
const DefaultHashScheme = "SSHA512"

// WriteAllowlist lists the schemes new writes may use (KTD 6).
var WriteAllowlist = map[string]bool{
	"SSHA512":  true,
	"SSHA256":  true,
	"SSHA":     true,
	"SHA512":   true,
	"SHA256":   true,
	"ARGON2ID": true,
	"MD4":      true,
}

// ReadOnlySchemes are accepted for verification of legacy entries only (KTD 6).
var ReadOnlySchemes = map[string]bool{
	"MD5":         true,
	"SMD5":        true,
	"SHA":         true,
	"CRYPT":       true,
	"BLOWFISH":    true,
	"SHA256CRYPT": true,
	"SHA512CRYPT": true,
	"MD5CRYPT":    true,
	"PLAIN":       true,
}

var errSchemeNotWritable = errors.New("tplengine: password scheme not in write allowlist (KTD 6)")

// HashPassword hashes password with the RFC 2307 {SCHEME} prefix. Plain is
// rejected unless allowPlain (KTD 6: reject {PLAIN} from new writes unless an
// explicit server-profile override is set).
func HashPassword(scheme, password string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(scheme))
	switch s {
	case "SSHA512", "SSHA256", "SSHA":
		return saltedHash(s, password)
	case "SHA512", "SHA256", "SHA":
		return digestHash(s, password)
	case "ARGON2ID":
		h, err := argon2id.CreateHash(password, argon2id.DefaultParams)
		if err != nil {
			return "", fmt.Errorf("tplengine: argon2id: %w", err)
		}
		return "{ARGON2}" + h, nil
	case "MD4":
		u := utf16.Encode([]rune(password))
		b := make([]byte, 0, len(u)*2)
		for _, r := range u {
			b = append(b, byte(r), byte(r>>8))
		}
		h := md4.New()
		h.Write(b)
		return "{MD4}" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
	case "MD5", "SMD5", "CRYPT", "BLOWFISH", "SHA256CRYPT", "SHA512CRYPT", "MD5CRYPT":
		return "", fmt.Errorf("%w: %s is read-only", errSchemeNotWritable, s)
	case "PLAIN":
		return "", errSchemeNotWritable
	default:
		return "", fmt.Errorf("tplengine: unknown password scheme %q", s)
	}
}

// HashPasswordWithOverride hashes password, honoring the explicit {PLAIN}
// server-profile override with a structured warn (KTD 6).
func HashPasswordWithOverride(scheme, password string, allowPlain bool, logger *slog.Logger) (string, error) {
	if strings.ToUpper(strings.TrimSpace(scheme)) == "PLAIN" {
		if !allowPlain {
			return "", errSchemeNotWritable
		}
		if logger != nil {
			logger.Warn("plaintext password stored (explicit server-profile override)",
				"event", "password.plain_override")
		}
		return password, nil
	}
	return HashPassword(scheme, password)
}

func saltedHash(scheme, password string) (string, error) {
	var sum []byte
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	switch scheme {
	case "SSHA":
		h := sha1.New()
		h.Write([]byte(password))
		h.Write(salt)
		sum = h.Sum(nil)
	case "SSHA256":
		h := sha256.New()
		h.Write([]byte(password))
		h.Write(salt)
		sum = h.Sum(nil)
	case "SSHA512":
		h := sha512.New()
		h.Write([]byte(password))
		h.Write(salt)
		sum = h.Sum(nil)
	default:
		return "", fmt.Errorf("tplengine: invalid salted scheme %q", scheme)
	}
	combined := append(sum, salt...)
	return "{" + scheme + "}" + base64.StdEncoding.EncodeToString(combined), nil
}

func digestHash(scheme, password string) (string, error) {
	switch scheme {
	case "SHA":
		h := sha1.Sum([]byte(password))
		return "{SHA}" + base64.StdEncoding.EncodeToString(h[:]), nil
	case "SHA256":
		h := sha256.Sum256([]byte(password))
		return "{SHA256}" + base64.StdEncoding.EncodeToString(h[:]), nil
	case "SHA512":
		h := sha512.Sum512([]byte(password))
		return "{SHA512}" + base64.StdEncoding.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("tplengine: invalid digest scheme %q", scheme)
	}
}

// DetectScheme extracts the {SCHEME} prefix from a stored value.
func DetectScheme(hashed string) string {
	if !strings.HasPrefix(hashed, "{") {
		return "PLAIN"
	}
	if i := strings.IndexByte(hashed, '}'); i > 1 {
		return strings.ToUpper(hashed[1:i])
	}
	return "PLAIN"
}

// VerifyPassword checks password against a stored {SCHEME} value (read-side
// support per KTD 6).
func VerifyPassword(hashed, password string) bool {
	scheme := DetectScheme(hashed)
	payload := hashed
	if strings.HasPrefix(hashed, "{") {
		if i := strings.IndexByte(hashed, '}'); i >= 0 {
			payload = hashed[i+1:]
		}
	}
	switch scheme {
	case "SSHA512", "SSHA256", "SSHA":
		return verifySalted(scheme, payload, password)
	case "SHA":
		return constantEq(digestBytes("SHA", password), payload)
	case "SHA256":
		return constantEq(digestBytes("SHA256", password), payload)
	case "SHA512":
		return constantEq(digestBytes("SHA512", password), payload)
	case "MD5":
		h := md5.Sum([]byte(password))
		return constantEq(h[:], payload)
	case "SMD5":
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil || len(raw) <= md5.Size {
			return false
		}
		sum := raw[:md5.Size]
		salt := raw[md5.Size:]
		h := md5.New()
		h.Write([]byte(password))
		h.Write(salt)
		return constantEq(h.Sum(nil), base64.StdEncoding.EncodeToString(sum))
	case "BLOWFISH":
		return bcrypt.CompareHashAndPassword([]byte(payload), []byte(password)) == nil
	case "ARGON2", "ARGON2ID":
		ok, err := argon2id.ComparePasswordAndHash(password, payload)
		return err == nil && ok
	case "MD4":
		u := utf16.Encode([]rune(password))
		b := make([]byte, 0, len(u)*2)
		for _, r := range u {
			b = append(b, byte(r), byte(r>>8))
		}
		h := md4.New()
		h.Write(b)
		return constantEq(h.Sum(nil), payload)
	case "CRYPT", "SHA256CRYPT", "SHA512CRYPT", "MD5CRYPT":
		c := crypt.NewFromHash(payload)
		if c == nil {
			return false
		}
		return c.Verify(payload, []byte(password)) == nil
	case "PLAIN":
		return payload == password
	default:
		return false
	}
}

func verifySalted(scheme, payload, password string) bool {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var size int
	switch scheme {
	case "SSHA":
		size = sha1.Size
	case "SSHA256":
		size = sha256.Size
	case "SSHA512":
		size = sha512.Size
	default:
		return false
	}
	if len(raw) <= size {
		return false
	}
	sum := raw[:size]
	salt := raw[size:]
	var got []byte
	switch scheme {
	case "SSHA":
		h := sha1.New()
		h.Write([]byte(password))
		h.Write(salt)
		got = h.Sum(nil)
	case "SSHA256":
		h := sha256.New()
		h.Write([]byte(password))
		h.Write(salt)
		got = h.Sum(nil)
	case "SSHA512":
		h := sha512.New()
		h.Write([]byte(password))
		h.Write(salt)
		got = h.Sum(nil)
	}
	return constantEq(got, base64.StdEncoding.EncodeToString(sum))
}

func digestBytes(scheme, password string) []byte {
	switch scheme {
	case "SHA":
		h := sha1.Sum([]byte(password))
		return h[:]
	case "SHA256":
		h := sha256.Sum256([]byte(password))
		return h[:]
	case "SHA512":
		h := sha512.Sum512([]byte(password))
		return h[:]
	default:
		return nil
	}
}

func constantEq(got []byte, encoded string) bool {
	want, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	if len(got) != len(want) {
		return false
	}
	var diff byte
	for i := range got {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}
