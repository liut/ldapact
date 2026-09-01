package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterBurst(t *testing.T) {
	l := New(1, 2)
	if !l.Allow("1.2.3.4") {
		t.Error("first request should be allowed")
	}
	if !l.Allow("1.2.3.4") {
		t.Error("second request should be allowed (burst)")
	}
	if l.Allow("1.2.3.4") {
		t.Error("third request should be rejected")
	}
}

func TestLimiterRefills(t *testing.T) {
	l := New(1000, 1)
	if !l.Allow("k") || l.Allow("k") {
		t.Fatal("burst=1 should allow exactly one")
	}
	time.Sleep(50 * time.Millisecond) // refills ~50 tokens at 1000/s
	if !l.Allow("k") {
		t.Error("token should have refilled after 50ms")
	}
}

func TestLimiterIndependentKeys(t *testing.T) {
	l := New(1, 1)
	if !l.Allow("a") {
		t.Error("a1 should pass")
	}
	if !l.Allow("b") {
		t.Error("b1 should pass independently")
	}
	if l.Allow("a") {
		t.Error("a2 should be rejected")
	}
}

func TestHandler(t *testing.T) {
	l := New(1, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	l.Handler(next).ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("first request: code = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	l.Handler(next).ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: code = %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q", rr.Header().Get("Retry-After"))
	}
}

func TestProxyKeyFirstHop(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.2")
	if got := ProxyKey(req); got != "203.0.113.7" {
		t.Errorf("ProxyKey = %q, want the first hop", got)
	}
}

func TestProxyKeyFallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	if got := ProxyKey(req); got != "10.0.0.1" {
		t.Errorf("ProxyKey = %q, want RemoteAddr fallback", got)
	}
}

func TestHandlerWithCustomKey(t *testing.T) {
	l := NewWithKey(1000, 1, func(r *http.Request) string {
		return r.Header.Get("X-Client")
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	alice := httptest.NewRequest(http.MethodGet, "/", nil)
	alice.Header.Set("X-Client", "alice")
	rr := httptest.NewRecorder()
	l.Handler(next).ServeHTTP(rr, alice)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("first alice request = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	l.Handler(next).ServeHTTP(rr, alice)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("second alice request = %d, want 429", rr.Code)
	}
	bob := httptest.NewRequest(http.MethodGet, "/", nil)
	bob.Header.Set("X-Client", "bob")
	rr = httptest.NewRecorder()
	l.Handler(next).ServeHTTP(rr, bob)
	if rr.Code != http.StatusNoContent {
		t.Errorf("bob request = %d, want independent key to pass", rr.Code)
	}
}
