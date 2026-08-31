package session

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestMemory(t *testing.T, idle, absolute time.Duration) *MemoryStore {
	t.Helper()
	s := NewMemoryStore(idle, absolute)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMemoryCreateGetDelete(t *testing.T) {
	s := newTestMemory(t, 30*time.Minute, 8*time.Hour)
	id := "sess-1"
	v, err := s.Create(id, "cn=admin,dc=example,dc=com", "ldap://replica-1", []byte("encrypted"))
	if err != nil {
		t.Fatal(err)
	}
	if v.ProfileRef != "cn=admin,dc=example,dc=com" {
		t.Errorf("profile = %q", v.ProfileRef)
	}
	if v.ServerRef != "ldap://replica-1" {
		t.Errorf("server_ref = %q", v.ServerRef)
	}
	if string(v.Credential) != "encrypted" {
		t.Errorf("credential = %q", v.Credential)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastSeenAt.After(v.LastSeenAt) {
		t.Error("Get should refresh LastSeenAt")
	}
	if got.ServerRef != "ldap://replica-1" || string(got.Credential) != "encrypted" {
		t.Error("server/credential fields lost in Get round-trip")
	}
	if err := s.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing, got %v", err)
	}
}

func TestMemoryIdleExpiry(t *testing.T) {
	s := newTestMemory(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.SetNow(func() time.Time { return base })
	if _, err := s.Create("idle", "", "", nil); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return base.Add(31 * time.Minute) })
	if _, err := s.Get("idle"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired, got %v", err)
	}
	if _, err := s.Get("idle"); !errors.Is(err, ErrSessionMissing) {
		t.Error("expired session should have been deleted")
	}

	if _, err := s.Create("refresh", "", "", nil); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return base.Add(29 * time.Minute) })
	if _, err := s.Get("refresh"); err != nil {
		t.Fatalf("within idle window: %v", err)
	}
	s.SetNow(func() time.Time { return base.Add(31 * time.Minute) })
	if _, err := s.Get("refresh"); err != nil {
		t.Fatalf("refreshed session should survive at 31 min: %v", err)
	}
	s.SetNow(func() time.Time { return base.Add(61*time.Minute + time.Second) })
	if _, err := s.Get("refresh"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired after idle window, got %v", err)
	}
}

func TestMemoryAbsoluteExpiry(t *testing.T) {
	s := newTestMemory(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.SetNow(func() time.Time { return base })
	if _, err := s.Create("abs", "", "", nil); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return base.Add(9 * time.Hour) })
	if _, err := s.Get("abs"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired despite activity, got %v", err)
	}
}

func TestMemoryRotate(t *testing.T) {
	s := newTestMemory(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Create("old", "p", "srv", []byte("cred")); err != nil {
		t.Fatal(err)
	}
	v, err := s.Rotate("old", "new")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if v.ProfileRef != "p" || v.ServerRef != "srv" || string(v.Credential) != "cred" {
		t.Errorf("rotated value lost fields: %+v", v)
	}
	if _, err := s.Get("new"); err != nil {
		t.Errorf("new session missing: %v", err)
	}
	if _, err := s.Get("old"); !errors.Is(err, ErrSessionMissing) {
		t.Error("old session should be gone")
	}
}

func TestMemoryRotateMissingOld(t *testing.T) {
	s := newTestMemory(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Rotate("nope", "new"); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing, got %v", err)
	}
}

func TestMemorySweep(t *testing.T) {
	s := newTestMemory(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.SetNow(func() time.Time { return base })
	if _, err := s.Create("old", "", "", nil); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return base.Add(30 * time.Minute) })
	if _, err := s.Create("fresh", "", "", nil); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return base.Add(31 * time.Minute) })
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

// TestMemoryRestartClears is AE7 for the memory backend: a new store instance
// starts empty.
func TestMemoryRestartClears(t *testing.T) {
	s := NewMemoryStore(30*time.Minute, 8*time.Hour)
	if _, err := s.Create("gone", "", "", nil); err != nil {
		t.Fatal(err)
	}
	s.Close()

	reopened := NewMemoryStore(30*time.Minute, 8*time.Hour)
	defer reopened.Close()
	if _, err := reopened.Get("gone"); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing after restart, got %v", err)
	}
}

// TestMemoryConcurrentAccess exercises Create/Get/Rotate/Delete on the same
// ID from many goroutines: the mutex must prevent panics and corruption.
func TestMemoryConcurrentAccess(t *testing.T) {
	s := newTestMemory(t, time.Hour, 8*time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("sess-%d", n%4)
			switch n % 4 {
			case 0:
				_, _ = s.Create(id, "p", "srv", []byte("cred"))
			case 1:
				_, _ = s.Get(id)
			case 2:
				_, _ = s.Rotate(id, id+"-new")
			case 3:
				_ = s.Delete(id)
			}
		}(i)
	}
	wg.Wait()
}
