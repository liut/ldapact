package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Gated integration tests against a real Redis backend (AE1: cross-instance
// sharing). Skip when no backend is available (see testredis.go).

func startIntegrationRedis(t *testing.T) *testRedis {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inst, err := startTestRedis(ctx)
	if errors.Is(err, errRedisUnavailable) {
		t.Skip(errRedisUnavailable)
	}
	if err != nil {
		t.Fatalf("start test redis: %v", err)
	}
	t.Cleanup(inst.Stop)
	return inst
}

func TestRedisCrossInstanceShared(t *testing.T) {
	inst := startIntegrationRedis(t)
	opts := RedisOptions{URL: inst.URL}
	a, err := NewRedisStore(context.Background(), opts, 30*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewRedisStore(context.Background(), opts, 30*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// AE1: instance A writes, instance B reads.
	if _, err := a.Create("shared", "cn=admin,dc=example,dc=com", "ldap://replica-1", []byte("encrypted")); err != nil {
		t.Fatal(err)
	}
	v, err := b.Get("shared")
	if err != nil {
		t.Fatalf("instance B cannot read instance A session: %v", err)
	}
	if v.ProfileRef != "cn=admin,dc=example,dc=com" || v.ServerRef != "ldap://replica-1" || string(v.Credential) != "encrypted" {
		t.Errorf("cross-instance fields lost: %+v", v)
	}

	// Rotation on B invalidates the old ID for A (R14).
	if _, err := b.Rotate("shared", "shared-new"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get("shared"); !errors.Is(err, ErrSessionMissing) {
		t.Errorf("old ID should be gone after rotation, got %v", err)
	}
	if _, err := a.Get("shared-new"); err != nil {
		t.Errorf("new ID should be visible to A: %v", err)
	}

	// Delete on A is visible to B.
	if err := a.Delete("shared-new"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get("shared-new"); !errors.Is(err, ErrSessionMissing) {
		t.Errorf("deleted session should be missing, got %v", err)
	}
}

// TestRedisConcurrentRotateNoDualLive asserts atomic rotation semantics:
// racing rotations of the same session may succeed or lose, but the losing
// rotations never create a second live session (RENAME-NX).
func TestRedisConcurrentRotateNoDualLive(t *testing.T) {
	inst := startIntegrationRedis(t)
	s, err := NewRedisStore(context.Background(), RedisOptions{URL: inst.URL}, 30*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Create("base", "p", "srv", []byte("cred")); err != nil {
		t.Fatal(err)
	}
	const workers = 12
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, _ = s.Rotate("base", fmt.Sprintf("rot-%d", n))
		}(i)
	}
	wg.Wait()

	live := 0
	for i := 0; i < workers; i++ {
		if _, err := s.Get(fmt.Sprintf("rot-%d", i)); err == nil {
			live++
		} else if !errors.Is(err, ErrSessionMissing) {
			t.Errorf("unexpected error for rot-%d: %v", i, err)
		}
	}
	if live > 1 {
		t.Errorf("dual-live sessions after racing rotations: %d", live)
	}
}
