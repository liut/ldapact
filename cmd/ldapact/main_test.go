package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHandlerHealthz(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	newHandler(logger).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("healthz code = %d, want 200", rr.Code)
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Cache-Control":          "no-store",
	} {
		if got := rr.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if rr.Header().Get("X-Request-Id") == "" {
		t.Error("X-Request-Id missing")
	}
}

func TestNewHandlerCSRFInChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	req.Host = "ldapact.example"
	req.Header.Set("Origin", "http://attacker.com")
	rr := httptest.NewRecorder()
	newHandler(logger).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST code = %d, want 403", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	req2.Host = "ldapact.example"
	req2.Header.Set("Origin", "https://ldapact.example")
	rr2 := httptest.NewRecorder()
	newHandler(logger).ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusForbidden {
		t.Error("same-origin POST should not be rejected by CSRF (405 from method routing is fine)")
	}
}

func TestNewHandlerHomePage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	newHandler(logger).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("home code = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`class="skip-link"`, `role="main"`, `role="contentinfo"`, "ldapact"} {
		if !strings.Contains(body, want) {
			t.Errorf("home page missing %q", want)
		}
	}
}

func TestNewHandlerStaticAssets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	newHandler(logger).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("static code = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("static Cache-Control = %q", got)
	}
}
