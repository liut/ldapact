// Package session implements the R13 server-side session stores (KTD 7/8):
// opaque random IDs in a __Host- cookie, idle + absolute timeouts, rotation
// after state changes, and a periodic sweeper. The bbolt and memory backends
// live here; the Redis backend (default, multi-instance) lives in redis.go.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// Sentinel errors.
var (
	ErrSessionExpired = errors.New("session: expired")
	ErrSessionMissing = errors.New("session: not found")
)

const (
	// BucketName is the bbolt bucket holding sessions.
	BucketName = "sessions"
	// IDBytes is the entropy of each session ID (32 bytes = 256 bits, KTD 8).
	IDBytes = 32
	// DBFileMode is the required sessions.db mode (KTD 7).
	DBFileMode = 0o600
)

// Value is the server-side session record.
type Value struct {
	CreatedAt         time.Time `json:"created_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
	ProfileRef        string    `json:"profile_ref"`
	// ServerRef names the LDAP replica the credential is bound to (R2).
	ServerRef string `json:"server_ref,omitempty"`
	// Credential carries the encrypted bind credential for this session
	// (opaque bytes; encryption happens at the session layer, U4).
	Credential []byte            `json:"credential,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
}

// Store is the session store abstraction (R1). Backends: bbolt (default
// compatibility), memory (single instance, cleared on restart), Redis
// (multi-instance shared).
type Store interface {
	// Create stamps a new session record and stores it under id.
	Create(id, profileRef, serverRef string, credential []byte) (*Value, error)
	// Get returns the session, refreshing its idle timeout. Expired sessions
	// are deleted and reported as ErrSessionExpired.
	Get(id string) (*Value, error)
	// Rotate migrates the session to a new ID, invalidating the old one.
	Rotate(oldID, newID string) (*Value, error)
	// Delete removes a session.
	Delete(id string) error
	// Sweep deletes all expired sessions and reports how many were removed.
	Sweep() (int, error)
	// Close releases backend resources.
	Close() error
}

// BboltStore is the bbolt-backed session store.
type BboltStore struct {
	db       *bbolt.DB
	now      func() time.Time
	idle     time.Duration
	absolute time.Duration
	// rotateMu serializes Rotate so concurrent state-changing requests
	// cannot both read the old session before either deletes it (which
	// would leave two live sessions).
	rotateMu sync.Mutex
}

// newValue stamps a fresh session record with the shared timeout semantics.
func newValue(now time.Time, profileRef, serverRef string, credential []byte, idle, absolute time.Duration) *Value {
	return &Value{
		CreatedAt:         now,
		LastSeenAt:        now,
		ExpiresAt:         now.Add(idle),
		AbsoluteExpiresAt: now.Add(absolute),
		ProfileRef:        profileRef,
		ServerRef:         serverRef,
		Credential:        credential,
		Data:              make(map[string]string),
	}
}

// expired reports whether v has exceeded either its idle or absolute
// deadline at now.
func expired(v *Value, now time.Time) bool {
	return now.After(v.AbsoluteExpiresAt) || now.After(v.ExpiresAt)
}

// refresh advances the idle deadline to now + idle.
func refresh(v *Value, now time.Time, idle time.Duration) {
	v.LastSeenAt = now
	v.ExpiresAt = now.Add(idle)
}

// NewStore opens (or creates) the sessions database, enforcing mode 0600 and
// creating the sessions bucket. startup fails if an existing file has the
// wrong mode (KTD 7).
func NewStore(path string, idleTimeout, absoluteTimeout time.Duration) (*BboltStore, error) {
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}
	if err := checkFileMode(path); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(path, DBFileMode, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("session: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BucketName))
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("session: create bucket: %w", err)
	}
	return &BboltStore{
		db:       db,
		now:      time.Now,
		idle:     idleTimeout,
		absolute: absoluteTimeout,
	}, nil
}

// ensureParentDir creates the database's parent directory only when it is
// missing. bbolt does not create parents, and the default path may be a
// per-user XDG state dir that is not pre-created (e.g.
// ~/.local/state/ldapact on first run). If the directory already exists, or
// cannot be stat'ed at all, we never attempt to create it: MkdirAll would
// otherwise report a misleading "mkdir: permission denied" for an
// existing-but-unstat-able system directory. Such stat errors are left for
// the open below to report truthfully.
func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err == nil {
		if fi.IsDir() {
			return nil
		}
		return fmt.Errorf("session: %s is not a directory", dir)
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("session: create directory for %s: %w", path, err)
		}
	}
	return nil
}

func checkFileMode(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("session: stat %s: %w", path, err)
	}
	if fi.Mode().Perm() != DBFileMode {
		return fmt.Errorf("session: %s mode is %o, want %o (KTD 7)",
			path, fi.Mode().Perm(), DBFileMode)
	}
	return nil
}

// Create inserts a new session and returns its value.
func (s *BboltStore) Create(id, profileRef, serverRef string, credential []byte) (*Value, error) {
	v := newValue(s.now(), profileRef, serverRef, credential, s.idle, s.absolute)
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("session: encode: %w", err)
	}
	err = s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(BucketName)).Put([]byte(id), raw)
	})
	if err != nil {
		return nil, fmt.Errorf("session: create %s: %w", id, err)
	}
	return v, nil
}

// Get returns the session, refreshing its idle timeout. Expired sessions are
// deleted and reported as ErrSessionExpired (AE7).
func (s *BboltStore) Get(id string) (*Value, error) {
	var raw []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		raw = tx.Bucket([]byte(BucketName)).Get([]byte(id))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("session: read %s: %w", id, err)
	}
	if raw == nil {
		return nil, ErrSessionMissing
	}
	var v Value
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("session: decode %s: %w", id, err)
	}
	now := s.now()
	if expired(&v, now) {
		_ = s.Delete(id)
		return nil, ErrSessionExpired
	}
	refresh(&v, now, s.idle)
	if err := s.put(id, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Delete removes a session.
func (s *BboltStore) Delete(id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(BucketName)).Delete([]byte(id))
	})
}

// GetData returns session form state (F2 multi-page wizard, U6).
func (s *BboltStore) GetData(id, key string) (string, bool) {
	v, err := s.Get(id)
	if err != nil {
		return "", false
	}
	val, ok := v.Data[key]
	return val, ok
}

// SetData stores session form state.
func (s *BboltStore) SetData(id, key, val string) error {
	v, err := s.Get(id)
	if err != nil {
		return err
	}
	if v.Data == nil {
		v.Data = make(map[string]string)
	}
	v.Data[key] = val
	return s.put(id, v)
}

func (s *BboltStore) put(id string, v *Value) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("session: encode: %w", err)
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(BucketName)).Put([]byte(id), raw)
	})
}

// Close closes the underlying database.
func (s *BboltStore) Close() error {
	return s.db.Close()
}

// Path returns the database path (for diagnostics).
func (s *BboltStore) Path() string {
	return filepath.Clean(s.db.Path())
}

// SetNow replaces the store clock (testing seam for expiry/rotation tests).
func (s *BboltStore) SetNow(fn func() time.Time) {
	s.now = fn
}
