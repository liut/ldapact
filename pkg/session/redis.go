package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis key namespace for session records (R2). The suffix is the 256-bit
// session ID.
const redisKeyPrefix = "ldapa_sess:"

// RedisOptions configures the Redis session backend.
type RedisOptions struct {
	// URL is redis://host:port or rediss://host:port (TLS verification is
	// mandatory and cannot be disabled).
	URL      string
	Password string
	DB       int
	// IdleTimeout closes pooled connections idle too long; ConnMaxLifetime
	// bounds connection age. Both avoid TIME_WAIT accumulation.
	IdleTimeout     time.Duration
	ConnMaxLifetime time.Duration
	// Now is a clock seam for tests; nil means time.Now.
	Now func() time.Time
}

// RedisStore is the shared multi-instance session store (R1/R2): each session
// is one key holding the JSON-encoded Value (including the encrypted bind
// credential). A sliding TTL implements the idle timeout (GETEX refreshes it
// atomically); the in-value absolute timestamp is authoritative for the
// absolute timeout (lazy deletion, R2). TTL expiry replaces the sweeper.
type RedisStore struct {
	rdb      *redis.Client
	now      func() time.Time
	idle     time.Duration
	absolute time.Duration
	prefix   string
}

// NewRedisStore connects to Redis and fails fast when it is unreachable
// (R14 startup posture).
func NewRedisStore(ctx context.Context, opts RedisOptions, idle, absolute time.Duration) (*RedisStore, error) {
	opt, err := redis.ParseURL(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("session: redis url: %w", err)
	}
	if opts.Password != "" {
		opt.Password = opts.Password
	}
	opt.DB = opts.DB
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 5 * time.Minute
	}
	if opts.ConnMaxLifetime <= 0 {
		opts.ConnMaxLifetime = 30 * time.Minute
	}
	opt.ConnMaxIdleTime = opts.IdleTimeout
	opt.ConnMaxLifetime = opts.ConnMaxLifetime
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("session: redis ping: %w", err)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &RedisStore{rdb: rdb, now: now, idle: idle, absolute: absolute, prefix: redisKeyPrefix}, nil
}

func (s *RedisStore) key(id string) string {
	return s.prefix + id
}

// Create stamps a new session record and stores it under id with a TTL of
// min(idle, absolute) (idle at creation).
func (s *RedisStore) Create(id, profileRef, serverRef string, credential []byte) (*Value, error) {
	v := newValue(s.now(), profileRef, serverRef, credential, s.idle, s.absolute)
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("session: redis encode: %w", err)
	}
	if err := s.rdb.Set(context.Background(), s.key(id), raw, minDuration(s.idle, s.absolute)).Err(); err != nil {
		return nil, fmt.Errorf("session: redis create %s: %w", id, err)
	}
	cp := *v
	return &cp, nil
}

// Get returns the session, atomically refreshing its idle TTL (GETEX) and
// enforcing the absolute deadline from the in-value timestamp. Expired
// sessions are deleted and reported as ErrSessionExpired.
func (s *RedisStore) Get(id string) (*Value, error) {
	raw, err := s.rdb.GetEx(context.Background(), s.key(id), s.idle).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrSessionMissing
	}
	if err != nil {
		return nil, fmt.Errorf("session: redis get %s: %w", id, err)
	}
	v, err := s.decode(raw, id)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if expired(v, now) {
		_ = s.rdb.Del(context.Background(), s.key(id))
		return nil, ErrSessionExpired
	}
	refresh(v, now, s.idle)
	if err := s.persist(id, v); err != nil {
		return nil, err
	}
	cp := *v
	return &cp, nil
}

// Rotate migrates a session to a new ID. RENAME moves the key atomically
// (preserving its TTL); the payload is then rewritten with refreshed
// timestamps and the correct min(idle, absolute) TTL.
func (s *RedisStore) Rotate(oldID, newID string) (*Value, error) {
	oldKey, newKey := s.key(oldID), s.key(newID)
	raw, err := s.rdb.GetEx(context.Background(), oldKey, s.idle).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrSessionMissing
	}
	if err != nil {
		return nil, fmt.Errorf("session: redis get %s: %w", oldID, err)
	}
	v, err := s.decode(raw, oldID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if expired(v, now) {
		_ = s.rdb.Del(context.Background(), oldKey)
		return nil, ErrSessionExpired
	}
	refresh(v, now, s.idle)
	moved, err := s.rdb.RenameNX(context.Background(), oldKey, newKey).Result()
	if err != nil {
		return nil, fmt.Errorf("session: redis rotate %s -> %s: %w", oldID, newID, err)
	}
	if !moved {
		return nil, fmt.Errorf("session: redis rotate %s -> %s: target session already exists", oldID, newID)
	}
	if err := s.persist(newID, v); err != nil {
		return nil, err
	}
	cp := *v
	return &cp, nil
}

// Delete removes a session.
func (s *RedisStore) Delete(id string) error {
	if err := s.rdb.Del(context.Background(), s.key(id)).Err(); err != nil {
		return fmt.Errorf("session: redis delete %s: %w", id, err)
	}
	return nil
}

// Sweep is a no-op for the Redis backend: TTL expiry handles cleanup (R2).
func (s *RedisStore) Sweep() (int, error) { return 0, nil }

// Close closes the underlying Redis client.
func (s *RedisStore) Close() error { return s.rdb.Close() }

// SetNow replaces the store clock (testing seam for expiry/rotation tests).
func (s *RedisStore) SetNow(fn func() time.Time) { s.now = fn }

func (s *RedisStore) decode(raw, id string) (*Value, error) {
	var v Value
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, fmt.Errorf("session: redis decode %s: %w", id, err)
	}
	return &v, nil
}

// persist rewrites the value JSON with a TTL of min(remaining idle, remaining
// absolute) — the absolute timestamp in the payload stays authoritative.
func (s *RedisStore) persist(id string, v *Value) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("session: redis encode: %w", err)
	}
	ttl := minDuration(v.ExpiresAt.Sub(s.now()), v.AbsoluteExpiresAt.Sub(s.now()))
	if err := s.rdb.Set(context.Background(), s.key(id), raw, ttl).Err(); err != nil {
		return fmt.Errorf("session: redis persist %s: %w", id, err)
	}
	return nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
