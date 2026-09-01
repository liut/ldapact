package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// NewID returns a fresh 256-bit session ID, base64url-encoded (KTD 8).
func NewID() (string, error) {
	var b [IDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Rotate migrates a session to a new ID, invalidating the old one (KTD 8:
// renewal on privilege/state change; AE7 rotation semantics).
func (s *BboltStore) Rotate(oldID, newID string) (*Value, error) {
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()
	v, err := s.Get(oldID)
	if err != nil {
		return nil, err
	}
	if err := s.put(newID, v); err != nil {
		return nil, err
	}
	if err := s.Delete(oldID); err != nil {
		// Roll back the new entry to avoid a duplicate live session.
		_ = s.Delete(newID)
		return nil, err
	}
	return v, nil
}
