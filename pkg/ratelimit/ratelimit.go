// Package ratelimit provides a simple per-IP token-bucket limiter for the
// request chain (U1).
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// KeyFunc derives the rate-limit key from a request.
type KeyFunc func(*http.Request) string

// Limiter is a per-key token bucket. It is safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	key     KeyFunc
}

// New creates a limiter allowing `burst` tokens immediately and refilling at
// `rate` tokens per second, keyed by the client IP from RemoteAddr.
func New(rate, burst int) *Limiter {
	return NewWithKey(rate, burst, RemoteAddrKey)
}

// NewWithKey creates a limiter that derives its key with fn. Choose the key
// function deliberately: RemoteAddrKey is the safe default; ProxyKey trusts
// X-Forwarded-For and must only be enabled behind a reverse proxy that
// overwrites that header.
func NewWithKey(rate, burst int, key KeyFunc) *Limiter {
	if rate < 1 {
		rate = 1
	}
	if burst < 1 {
		burst = 1
	}
	if key == nil {
		key = RemoteAddrKey
	}
	return &Limiter{
		rate:    float64(rate),
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		key:     key,
	}
}

// RemoteAddrKey keys the limiter by the client IP from RemoteAddr. Safe
// without a reverse proxy; behind a proxy every client shares the proxy IP.
func RemoteAddrKey(r *http.Request) string {
	return clientIP(r.RemoteAddr)
}

// ProxyKey keys the limiter by the first X-Forwarded-For hop when present,
// falling back to RemoteAddr. Only enable behind a trusted reverse proxy
// that overwrites X-Forwarded-For; an attacker who can set the header
// directly (no proxy) can rotate keys and bypass the limit.
func ProxyKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	return RemoteAddrKey(r)
}

// Allow reports whether the key may proceed, consuming a token when allowed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Handler wraps next, keying the limiter by the client IP from RemoteAddr.
func (l *Limiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := l.key(r)
		if !l.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
