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
