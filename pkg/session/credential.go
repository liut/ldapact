package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Credential encryption envelope (U4, R6/R14): version byte + 12-byte random
// nonce + AES-256-GCM ciphertext with tag. The key is the base64-decoded
// 32-byte LDAPADM_SESSION_KEY secret; changing the key invalidates every
// stored envelope (documented tradeoff, R14).
const (
	credentialVersion    = 1
	credentialNonceSize  = 12
	credentialKeyBytes   = 32
	credentialVersionLen = 1
)

// Sentinel errors for credential decryption. Callers treat ErrCredentialKeyMismatch
// as "session invalid → re-login" (R14) and ErrCredentialCorrupt as an
// integrity failure; neither ever carries secret material.
var (
	ErrCredentialCorrupt     = errors.New("session: credential envelope corrupt")
	ErrCredentialKeyMismatch = errors.New("session: credential decryption failed (key mismatch or tampered data)")
)

// CredentialCipher seals and opens session bind credentials.
type CredentialCipher struct {
	gcm         cipher.AEAD
	fingerprint string
}

// NewCredentialCipher builds the cipher from the base64-encoded 32-byte
// session key (LDAPADM_SESSION_KEY). Both padded and raw base64 are
// accepted; any other length is rejected at startup.
func NewCredentialCipher(keyB64 string) (*CredentialCipher, error) {
	raw, err := decodeKey(keyB64)
	if err != nil {
		return nil, fmt.Errorf("session: credential key: %w", err)
	}
	if len(raw) != credentialKeyBytes {
		return nil, fmt.Errorf("session: credential key must decode to %d bytes, got %d", credentialKeyBytes, len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("session: credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("session: credential gcm: %w", err)
	}
	return &CredentialCipher{gcm: gcm, fingerprint: credentialFingerprint(keyB64)}, nil
}

// decodeKey accepts standard base64 (with padding) or raw standard base64.
func decodeKey(keyB64 string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(keyB64); err == nil {
		return raw, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, errors.New("key must be base64-encoded")
	}
	return raw, nil
}

// Encrypt seals plaintext with a fresh random nonce. The output is the
// versioned envelope; empty plaintext is valid.
func (c *CredentialCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("session: credential nonce: %w", err)
	}
	out := make([]byte, 0, credentialVersionLen+credentialNonceSize+len(plaintext)+c.gcm.Overhead())
	out = append(out, credentialVersion)
	out = append(out, nonce...)
	out = c.gcm.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Decrypt opens an envelope produced by Encrypt. Structural defects report
// ErrCredentialCorrupt; authentication failure (tampering or wrong key)
// reports ErrCredentialKeyMismatch.
func (c *CredentialCipher) Decrypt(envelope []byte) ([]byte, error) {
	if len(envelope) < credentialVersionLen+credentialNonceSize+c.gcm.Overhead() {
		return nil, ErrCredentialCorrupt
	}
	if envelope[0] != credentialVersion {
		return nil, ErrCredentialCorrupt
	}
	nonce := envelope[credentialVersionLen : credentialVersionLen+credentialNonceSize]
	ciphertext := envelope[credentialVersionLen+credentialNonceSize:]
	plain, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrCredentialKeyMismatch
	}
	return plain, nil
}

// KeyFingerprint returns a truncated fingerprint safe for log lines: the
// first 6 hex characters of the SHA-256 of the key material. Unlike a raw
// substring of the base64 key, a hash fingerprint reveals nothing about the
// key itself.
func (c *CredentialCipher) KeyFingerprint() string { return c.fingerprint }

func credentialFingerprint(s string) string {
	if s == "" {
		return "[empty]"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:3])
}
