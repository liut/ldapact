package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelDebug, &buf)
	logger.Info("test",
		"userPassword", "{SSHA}secret-hash",
		"bind_password", "plain-secret",
		"newPassword", "new-secret",
		"dn", "cn=alice,dc=example,dc=com",
		"event", "ldap.create",
	)
	out := buf.String()
	for _, leak := range []string{"secret-hash", "plain-secret", "new-secret"} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaked %q: %s", leak, out)
		}
	}
	for _, want := range []string{"cn=alice,dc=example,dc=com", "ldap.create"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q: %s", want, out)
		}
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("output is not valid JSON: %s", out)
	}
}

func TestSafeAttr(t *testing.T) {
	if SafeAttr("userPassword", "x").Key != "" {
		t.Error("SafeAttr should drop userPassword")
	}
	if SafeAttr("auto_number_password", "x").Key != "" {
		t.Error("SafeAttr should drop *_password")
	}
	if SafeAttr("dn", "cn=x").Key != "dn" {
		t.Error("SafeAttr should keep dn")
	}
}

func TestLevelFromString(t *testing.T) {
	cases := map[string]slog.Level{
		"":      slog.LevelInfo,
		"debug": slog.LevelDebug,
		"INFO":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}
	for in, want := range cases {
		got, err := LevelFromString(in)
		if err != nil || got != want {
			t.Errorf("LevelFromString(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := LevelFromString("loud"); err == nil {
		t.Error("want error for invalid level")
	}
}

func TestLevelFromEnv(t *testing.T) {
	t.Setenv(LevelEnv, "debug")
	lvl, err := LevelFromEnv()
	if err != nil || lvl != slog.LevelDebug {
		t.Errorf("LevelFromEnv = %v, %v", lvl, err)
	}
	t.Setenv(LevelEnv, "bogus")
	if _, err := LevelFromEnv(); err == nil {
		t.Error("want error for bogus level")
	}
}

func TestRequestID(t *testing.T) {
	var gotID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = RequestIDFrom(r.Context())
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	RequestID(next).ServeHTTP(rr, req)
	if gotID == "" || gotID != rr.Header().Get("X-Request-Id") {
		t.Errorf("request id mismatch: ctx=%q header=%q", gotID, rr.Header().Get("X-Request-Id"))
	}
	if len(gotID) != 32 {
		t.Errorf("request id length = %d, want 32", len(gotID))
	}
	if RequestIDFrom(context.Background()) != "" {
		t.Error("RequestIDFrom should return empty for background ctx")
	}
}

func TestRecover(t *testing.T) {
	var buf bytes.Buffer
	logger := New(slog.LevelDebug, &buf)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Recover(logger)(RequestID(next)).ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", rr.Code)
	}
	if !strings.Contains(buf.String(), "boom") || !strings.Contains(buf.String(), "http.panic") {
		t.Errorf("panic not logged: %s", buf.String())
	}

	// Subsequent requests must not be poisoned by the recovered panic.
	rr2 := httptest.NewRecorder()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	Recover(logger)(ok).ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNoContent {
		t.Errorf("code after recover = %d, want 204", rr2.Code)
	}
}
