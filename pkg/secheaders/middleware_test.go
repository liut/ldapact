package secheaders

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaders(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", got)
	}
	if got := rr.Header().Get("Permissions-Policy"); got != "camera=(), microphone=(), geolocation=(), payment=()" {
		t.Errorf("Permissions-Policy = %q", got)
	}
	if got := rr.Header().Get("Content-Security-Policy-Report-Only"); got == "" {
		t.Error("CSP-Report-Only missing")
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS sent over plain HTTP: %q", got)
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://ldapact.example/", nil)
	req.TLS = &tls.ConnectionState{}
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)
	if got := rr.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Errorf("HSTS = %q", got)
	}
}

func TestStaticCacheControl(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil)
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want public max-age=300", got)
	}
}
