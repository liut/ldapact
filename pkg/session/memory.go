package session

import (
	"sync"
	"time"
)

// MemoryStore is an in-process session store (R3): the same dual-timeout and
// rotation semantics as the bbolt backend, but nothing persists across a
// restart (AE7). It is safe for concurrent use and intended for single
// instances only.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]*Value
	now      func() time.Time
	idle     time.Duration
	absolute time.Duration
}

// NewMemoryStore returns an empty in-memory session store.
func NewMemoryStore(idle, absolute time.Duration) *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*Value),
		now:      time.Now,
		idle:     idle,
		absolute: absolute,
	}
}

// Create inserts a new session and returns its value.
func (s *MemoryStore) Create(id, profileRef, serverRef string, credential []byte) (*Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := newValue(s.now(), profileRef, serverRef, credential, s.idle, s.absolute)
	s.sessions[id] = v
	cp := *v
	return &cp, nil
}

// Get returns the session, refreshing its idle timeout. Expired sessions are
// deleted and reported as ErrSessionExpired.
func (s *MemoryStore) Get(id string) (*Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionMissing
	}
	now := s.now()
	if expired(v, now) {
		delete(s.sessions, id)
		return nil, ErrSessionExpired
	}
	refresh(v, now, s.idle)
	cp := *v
	return &cp, nil
}

// Rotate migrates a session to a new ID, invalidating the old one (KTD 8).
func (s *MemoryStore) Rotate(oldID, newID string) (*Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[oldID]
	if !ok {
		return nil, ErrSessionMissing
	}
	now := s.now()
	if expired(v, now) {
		delete(s.sessions, oldID)
		return nil, ErrSessionExpired
	}
	refresh(v, now, s.idle)
	cp := *v
	s.sessions[newID] = &cp
	delete(s.sessions, oldID)
	return &cp, nil
}

// Delete removes a session.
func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

// Sweep deletes all expired sessions and reports how many were removed.
func (s *MemoryStore) Sweep() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for id, v := range s.sessions {
		if expired(v, now) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed, nil
}

// Close releases backend resources (no-op for the memory backend).
func (s *MemoryStore) Close() error { return nil }

// SetNow replaces the store clock (testing seam for expiry/rotation tests).
func (s *MemoryStore) SetNow(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = fn
}
