// Package ratelimit provides a simple per-IP token-bucket limiter for the
// request chain (U1).
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a per-key token bucket. It is safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

// New creates a limiter allowing `burst` tokens immediately and refilling at
// `rate` tokens per second.
func New(rate, burst int) *Limiter {
	if rate < 1 {
		rate = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    float64(rate),
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
	}
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
		ip := clientIP(r.RemoteAddr)
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
