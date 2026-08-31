package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/session"
)

func testStore(t *testing.T, idle, absolute time.Duration) *session.BboltStore {
	t.Helper()
	s, err := session.NewStore(filepath.Join(t.TempDir(), "sessions.db"), idle, absolute)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func middlewareOpts(store session.Store) MiddlewareOptions {
	return MiddlewareOptions{
		Store:         store,
		Logger:        testLogger(),
		ExpiredAction: config.ExpiredActionRetryBind,
		Profile:       "cn=admin,dc=example,dc=com",
	}
}

func captureSession(t *testing.T, rr *httptest.ResponseRecorder) *Session {
	t.Helper()
	resp := rr.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie set")
	}
	c := cookies[0]
	if c.Name != session.CookieName {
		t.Fatalf("cookie name = %q", c.Name)
	}
	return &Session{ID: c.Value}
}

func TestFirstRequestCreatesSession(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	var got *Session
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = SessionFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	Middleware(middlewareOpts(store))(next).ServeHTTP(rr, req)

	if got == nil || !got.Fresh {
		t.Fatalf("session not attached: %+v", got)
	}
	sess := captureSession(t, rr)
	if sess.ID == "" || !session.ValidID(sess.ID) {
		t.Errorf("invalid session id %q", sess.ID)
	}
	if got.Value.ProfileRef != "cn=admin,dc=example,dc=com" {
		t.Errorf("profile_ref = %q", got.Value.ProfileRef)
	}
}

func TestSecondRequestReusesSession(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(first, req)
	sid := captureSession(t, first).ID

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: session.CookieName, Value: sid})
	var got *Session
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = SessionFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(second, req2)
	if got == nil || got.Fresh || got.ID != sid {
		t.Fatalf("expected reused session %q, got %+v", sid, got)
	}
	if len(second.Result().Cookies()) != 0 {
		t.Error("GET must not rotate or set a new cookie")
	}
}

func TestStateChangingRotatesSession(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(first, req)
	oldID := captureSession(t, first).ID

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/entry", nil)
	req2.AddCookie(&http.Cookie{Name: session.CookieName, Value: oldID})
	var got *Session
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = SessionFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(second, req2)

	if got == nil || got.ID == oldID {
		t.Fatalf("session not rotated: old=%q new=%+v", oldID, got)
	}
	newID := captureSession(t, second).ID
	if newID != got.ID {
		t.Errorf("cookie id %q != context id %q", newID, got.ID)
	}
	if _, err := store.Get(oldID); err == nil {
		t.Error("old session ID must be invalidated")
	}
	if _, err := store.Get(newID); err != nil {
		t.Errorf("new session must be valid: %v", err)
	}
}

func TestIdleExpiryRetryBind(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(first, req)
	oldID := captureSession(t, first).ID

	// Advance the store clock past the 30-minute idle window.
	store.SetNow(func() time.Time { return time.Now().Add(31 * time.Minute) })

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.AddCookie(&http.Cookie{Name: session.CookieName, Value: oldID})
	var got *Session
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = SessionFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(second, req2)

	if got == nil || !got.Fresh {
		t.Fatalf("retry_bind should mint a fresh session, got %+v", got)
	}
	newID := captureSession(t, second).ID
	if newID == oldID {
		t.Error("expired session must not be reused")
	}
}

func TestIdleExpiryRedirectToLogin(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	opts := middlewareOpts(store)
	opts.ExpiredAction = config.ExpiredActionRedirectLogin
	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(first, req)
	oldID := captureSession(t, first).ID
	store.SetNow(func() time.Time { return time.Now().Add(31 * time.Minute) })

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.AddCookie(&http.Cookie{Name: session.CookieName, Value: oldID})
	Middleware(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run after redirect")
	})).ServeHTTP(second, req2)
	if second.Code != http.StatusFound {
		t.Fatalf("code = %d, want 302", second.Code)
	}
	loc := second.Header().Get("Location")
	if loc != "/login?next=%2Fprotected" {
		t.Errorf("Location = %q", loc)
	}
}

func TestMalformedCookieRejected(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "not-a-valid-id"})
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run for malformed cookie")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rr.Code)
	}
}

func TestStoreErrorReturns503(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	store.Close() // force store failure
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run on store failure")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rr.Code)
	}
}

func TestNilStorePassesThrough(t *testing.T) {
	var got bool
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware(MiddlewareOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)
	if !got || rr.Code != http.StatusNoContent {
		t.Fatal("nil store should pass through untouched")
	}
	if SessionFrom(context.Background()) != nil {
		t.Error("SessionFrom on empty ctx should be nil")
	}
}

func TestHealthzSkipsSession(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	var ran bool
	Middleware(middlewareOpts(store))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		if SessionFrom(r.Context()) != nil {
			t.Error("healthz must not carry a session")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)
	if !ran {
		t.Fatal("healthz handler did not run")
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Error("healthz must not set a session cookie")
	}
}
