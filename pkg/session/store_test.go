package session

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T, idle, absolute time.Duration) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "sessions.db"), idle, absolute)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateGetDelete(t *testing.T) {
	s := newTestStore(t, 30*time.Minute, 8*time.Hour)
	id := "sess-1"
	v, err := s.Create(id, "cn=admin,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	if v.ProfileRef != "cn=admin,dc=example,dc=com" {
		t.Errorf("profile = %q", v.ProfileRef)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastSeenAt.After(v.LastSeenAt) {
		t.Error("Get should refresh LastSeenAt")
	}
	if err := s.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing, got %v", err)
	}
}

func TestIdleExpiry(t *testing.T) {
	s := newTestStore(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.now = func() time.Time { return base }
	id := "idle"
	if _, err := s.Create(id, ""); err != nil {
		t.Fatal(err)
	}
	// No access until 31 minutes after creation: expired.
	s.now = func() time.Time { return base.Add(31 * time.Minute) }
	if _, err := s.Get(id); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired, got %v", err)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrSessionMissing) {
		t.Error("expired session should have been deleted")
	}

	// Access refreshes the idle window: a hit at 29 min keeps the session
	// alive at 31 min, and only expires after another 30 idle minutes.
	id2 := "refresh"
	if _, err := s.Create(id2, ""); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(29 * time.Minute) }
	if _, err := s.Get(id2); err != nil {
		t.Fatalf("within idle window: %v", err)
	}
	s.now = func() time.Time { return base.Add(31 * time.Minute) }
	if _, err := s.Get(id2); err != nil {
		t.Fatalf("refreshed session should survive at 31 min: %v", err)
	}
	s.now = func() time.Time { return base.Add(61*time.Minute + time.Second) }
	if _, err := s.Get(id2); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired after idle window, got %v", err)
	}
}

func TestAbsoluteExpiry(t *testing.T) {
	s := newTestStore(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.now = func() time.Time { return base }
	id := "abs"
	if _, err := s.Create(id, ""); err != nil {
		t.Fatal(err)
	}
	// Recent activity, but past the absolute horizon.
	s.now = func() time.Time { return base.Add(9 * time.Hour) }
	if _, err := s.Get(id); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired despite activity, got %v", err)
	}
}

func TestRotate(t *testing.T) {
	s := newTestStore(t, 30*time.Minute, 8*time.Hour)
	oldID := "old"
	if _, err := s.Create(oldID, "p"); err != nil {
		t.Fatal(err)
	}
	v, err := s.Rotate(oldID, "new")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if v.ProfileRef != "p" {
		t.Errorf("rotated value lost profile: %+v", v)
	}
	if _, err := s.Get("new"); err != nil {
		t.Errorf("new session missing: %v", err)
	}
	if _, err := s.Get(oldID); !errors.Is(err, ErrSessionMissing) {
		t.Error("old session should be gone")
	}
}

func TestRotateMissingOld(t *testing.T) {
	s := newTestStore(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Rotate("nope", "new"); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing, got %v", err)
	}
}

func TestDataRoundTrip(t *testing.T) {
	s := newTestStore(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Create("d", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetData("d", "form:abc", `{"uid":"alice"}`); err != nil {
		t.Fatal(err)
	}
	got, ok := s.GetData("d", "form:abc")
	if !ok || got != `{"uid":"alice"}` {
		t.Errorf("GetData = %q, %v", got, ok)
	}
}

func TestSweep(t *testing.T) {
	s := newTestStore(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.now = func() time.Time { return base }
	if _, err := s.Create("old", ""); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(30 * time.Minute) }
	if _, err := s.Create("fresh", ""); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(31 * time.Minute) }
	removed, err := s.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, err := s.Get("fresh"); err != nil {
		t.Errorf("fresh session should survive: %v", err)
	}
}

func TestFileModeEnforced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	if err := os.WriteFile(path, []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, time.Minute, time.Hour); err == nil {
		t.Fatal("want error for 0644 db file")
	}
}

func TestNewID(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("ids must be unique")
	}
	if len(a) != base64.RawURLEncoding.EncodedLen(IDBytes) {
		t.Errorf("id length = %d", len(a))
	}
}
