package authn

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestCSRFRejectsCrossOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/entry", nil)
	req.Header.Set("Origin", "http://attacker.com")
	req.Host = "localhost:8080"
	rr := httptest.NewRecorder()
	CSRF(testLogger())(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", rr.Code)
	}
}

func TestCSRFAllowsSameOrigin(t *testing.T) {
	for _, origin := range []string{"http://localhost:8080", "https://localhost:8080"} {
		req := httptest.NewRequest(http.MethodPost, "/api/entry", nil)
		req.Header.Set("Origin", origin)
		req.Host = "localhost:8080"
		rr := httptest.NewRecorder()
		CSRF(nil)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("origin %s: code = %d, want 200", origin, rr.Code)
		}
	}
}

func TestCSRFAllowsMissingOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/entry", nil)
	rr := httptest.NewRecorder()
	CSRF(nil)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

func TestCSRFAllowsNullOrigin(t *testing.T) {
	// Chromium sends "Origin: null" on form submissions from pages served
	// with a strict Referrer-Policy (no-referrer); the app must not treat
	// that opaque serialization as a cross-origin attack.
	req := httptest.NewRequest(http.MethodPost, "/api/entry", nil)
	req.Header.Set("Origin", "null")
	req.Host = "localhost:8080"
	rr := httptest.NewRecorder()
	CSRF(nil)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Origin: null must pass like a missing Origin: code = %d, want 200", rr.Code)
	}
}

func TestCSRFStillRejectsMismatchedOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/entry", nil)
	req.Header.Set("Origin", "http://attacker.example")
	req.Host = "localhost:8080"
	rr := httptest.NewRecorder()
	CSRF(nil)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("mismatched Origin must still be rejected: code = %d, want 403", rr.Code)
	}
}

func TestCSRFIgnoresSafeMethods(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/entry", nil)
	req.Header.Set("Origin", "http://attacker.com")
	rr := httptest.NewRecorder()
	CSRF(nil)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET with mismatched origin: code = %d, want 200", rr.Code)
	}
}

func TestCSRFRejectsAllStateChangingMethods(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/entry", nil)
		req.Header.Set("Origin", "http://attacker.com")
		req.Host = "localhost:8080"
		rr := httptest.NewRecorder()
		CSRF(nil)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d, want 403", method, rr.Code)
		}
	}
}

func TestCSRFRejectsMalformedOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/entry", nil)
	req.Header.Set("Origin", "::::")
	req.Host = "localhost:8080"
	rr := httptest.NewRecorder()
	CSRF(nil)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", rr.Code)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"localhost:8080": "localhost:8080",
		"LOCALHOST:8080": "localhost:8080",
		"example.com:80": "example.com",
		"example.com":    "example.com",
		"[::1]:8080":     "[::1]:8080",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
