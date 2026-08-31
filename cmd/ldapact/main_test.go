package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/liut/ldapact/internal/app"
	"github.com/liut/ldapact/pkg/session"
)

func TestNewHandlerHealthz(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	app.NewHandler(app.Deps{Logger: logger}).ServeHTTP(rr, req)

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
	app.NewHandler(app.Deps{Logger: logger}).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST code = %d, want 403", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	req2.Host = "ldapact.example"
	req2.Header.Set("Origin", "https://ldapact.example")
	rr2 := httptest.NewRecorder()
	app.NewHandler(app.Deps{Logger: logger}).ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusForbidden {
		t.Error("same-origin POST should not be rejected by CSRF (405 from method routing is fine)")
	}
}

func TestNewHandlerHomePage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	app.NewHandler(app.Deps{Logger: logger}).ServeHTTP(rr, req)
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
	app.NewHandler(app.Deps{Logger: logger}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("static code = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("static Cache-Control = %q", got)
	}
}

func TestNewHandlerLoginGate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := session.NewMemoryStore(30*time.Minute, 8*time.Hour)
	defer store.Close()
	cipher, err := session.NewCredentialCipher("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		t.Fatal(err)
	}
	deps := app.Deps{Logger: logger, Store: store, Cipher: cipher}

	// The login gate redirects unauthenticated requests to /login.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	app.NewHandler(deps).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("gate code = %d, want 302", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), "/login?next=") {
		t.Errorf("gate Location = %q", rr.Header().Get("Location"))
	}

	// The login page renders with the next target preserved.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/login?next=%2Fprotected", nil)
	app.NewHandler(deps).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login code = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `value="/protected"`) {
		t.Errorf("login page missing next target: %s", rr.Body.String())
	}
}
