package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newTestRedis(t *testing.T, idle, absolute time.Duration) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	s, err := NewRedisStore(context.Background(), RedisOptions{URL: "redis://" + mr.Addr()}, idle, absolute)
	if err != nil {
		t.Fatalf("NewRedisStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, mr
}

func TestRedisCreateGetDelete(t *testing.T) {
	s, mr := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	id := "sess-1"
	v, err := s.Create(id, "cn=admin,dc=example,dc=com", "ldap://replica-1", []byte("encrypted"))
	if err != nil {
		t.Fatal(err)
	}
	if v.ProfileRef != "cn=admin,dc=example,dc=com" || v.ServerRef != "ldap://replica-1" || string(v.Credential) != "encrypted" {
		t.Errorf("fields lost at create: %+v", v)
	}
	if got := mr.TTL(redisKeyPrefix + id); got <= 0 {
		t.Errorf("expected TTL on session key, got %v", got)
	}
	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
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

func TestRedisIdleTTLExpires(t *testing.T) {
	s, mr := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Create("idle", "", "", nil); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(31 * time.Minute)
	if _, err := s.Get("idle"); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing after TTL expiry, got %v", err)
	}
}

func TestRedisGetRefreshesSlidingTTL(t *testing.T) {
	s, mr := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Create("refresh", "", "", nil); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(29 * time.Minute)
	if _, err := s.Get("refresh"); err != nil {
		t.Fatalf("within idle window: %v", err)
	}
	mr.FastForward(29 * time.Minute)
	if _, err := s.Get("refresh"); err != nil {
		t.Fatalf("refreshed session should survive at 58 min: %v", err)
	}
	mr.FastForward(31 * time.Minute)
	if _, err := s.Get("refresh"); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing after idle window, got %v", err)
	}
}

func TestRedisAbsoluteExpiry(t *testing.T) {
	s, mr := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.SetNow(func() time.Time { return base })
	if _, err := s.Create("abs", "", "", nil); err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return base.Add(9 * time.Hour) })
	if _, err := s.Get("abs"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired despite TTL, got %v", err)
	}
	if mr.Exists(redisKeyPrefix + "abs") {
		t.Error("expired session should have been deleted lazily")
	}
}

func TestRedisRotate(t *testing.T) {
	s, mr := newTestRedis(t, 30*time.Minute, 8*time.Hour)
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
	if got := mr.TTL(redisKeyPrefix + "new"); got <= 0 {
		t.Errorf("rotated key should keep a TTL, got %v", got)
	}
}

func TestRedisRotateMissingOld(t *testing.T) {
	s, _ := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Rotate("nope", "new"); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("want ErrSessionMissing, got %v", err)
	}
}

func TestRedisRotateTargetCollision(t *testing.T) {
	s, _ := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	if _, err := s.Create("old", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("new", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate("old", "new"); err == nil {
		t.Fatal("want error when rotate target already exists")
	}
}

func TestRedisSweepNoop(t *testing.T) {
	s, _ := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	removed, err := s.Sweep()
	if err != nil || removed != 0 {
		t.Fatalf("Sweep = %d, %v; want no-op 0, nil", removed, err)
	}
}

func TestRedisLargeValueRoundTrip(t *testing.T) {
	s, _ := newTestRedis(t, 30*time.Minute, 8*time.Hour)
	longDN := "cn=" + string(make([]byte, 512)) + ",dc=example,dc=com"
	bigCred := make([]byte, 8192)
	for i := range bigCred {
		bigCred[i] = byte(i)
	}
	if _, err := s.Create("big", longDN, "srv", bigCred); err != nil {
		t.Fatal(err)
	}
	v, err := s.Get("big")
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Credential) != string(bigCred) {
		t.Error("large credential round-trip mismatch")
	}
}

func TestRedisUnreachableFailsFast(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	if err := mr.Start(); err != nil {
		t.Fatal(err)
	}
	url := "redis://" + mr.Addr()
	mr.Close()
	if _, err := NewRedisStore(context.Background(), RedisOptions{URL: url}, time.Minute, time.Hour); err == nil {
		t.Fatal("want fail-fast error when Redis is unreachable")
	}
}
