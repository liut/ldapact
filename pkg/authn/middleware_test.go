package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/liut/ldapact/pkg/ldapx"
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

func testCipher(t *testing.T) *session.CredentialCipher {
	t.Helper()
	c, err := session.NewCredentialCipher("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}
	return c
}

func middlewareOpts(store session.Store, cipher *session.CredentialCipher) MiddlewareOptions {
	return MiddlewareOptions{Store: store, Cipher: cipher, Logger: testLogger()}
}

// createSession writes a session with an encrypted credential straight into
// the store and returns its ID.
func createSession(t *testing.T, store session.Store, cipher *session.CredentialCipher, dn, password string) string {
	t.Helper()
	id, err := session.NewID()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cipher.Encrypt([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(id, dn, "ldap://replica-1", enc); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestNoCookieRedirectsToLogin(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/search?q=(uid=x)", nil)
	Middleware(middlewareOpts(store, testCipher(t)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run without a session")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login?next=%2Fsearch%3Fq%3D%28uid%3Dx%29" {
		t.Errorf("Location = %q", loc)
	}
}

func TestValidSessionAttachesCredential(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	cipher := testCipher(t)
	sid := createSession(t, store, cipher, "cn=admin,dc=example,dc=com", "admin-password")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: sid})
	var gotSess *Session
	var gotCred ldapx.BindCredential
	Middleware(middlewareOpts(store, cipher))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSess = SessionFrom(r.Context())
		gotCred, _ = ldapx.CredentialFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)

	if gotSess == nil || gotSess.ID != sid {
		t.Fatalf("session not attached: %+v", gotSess)
	}
	if gotCred.DN != "cn=admin,dc=example,dc=com" || gotCred.Password != "admin-password" {
		t.Errorf("credential = %+v", gotCred)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Error("GET must not set a new cookie")
	}
}

func TestStateChangingRotatesSession(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	cipher := testCipher(t)
	oldID := createSession(t, store, cipher, "cn=admin,dc=example,dc=com", "admin-password")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/entry/x", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: oldID})
	var gotSess *Session
	Middleware(middlewareOpts(store, cipher))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSess = SessionFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, req)

	if gotSess == nil || gotSess.ID == oldID {
		t.Fatalf("session not rotated: old=%q got=%+v", oldID, gotSess)
	}
	newID := gotSess.ID
	if _, err := store.Get(oldID); err == nil {
		t.Error("old session ID must be invalidated")
	}
	v, err := store.Get(newID)
	if err != nil {
		t.Fatalf("new session must be valid: %v", err)
	}
	if v.ProfileRef != "cn=admin,dc=example,dc=com" || len(v.Credential) == 0 {
		t.Error("rotation must preserve the profile and credential")
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != newID {
		t.Errorf("cookie = %+v, want rotated id", cookies)
	}
}

func TestExpiredSessionRedirectsToLogin(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	cipher := testCipher(t)
	sid := createSession(t, store, cipher, "cn=admin,dc=example,dc=com", "admin-password")
	store.SetNow(func() time.Time { return time.Now().Add(31 * time.Minute) })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: sid})
	Middleware(middlewareOpts(store, cipher))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run for an expired session")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login?next=%2Fprotected" {
		t.Errorf("Location = %q", loc)
	}
	if cookie := sessionCookie(t, rr); cookie == nil || cookie.MaxAge >= 0 {
		t.Error("expired session must clear the cookie")
	}
}

func TestMissingSessionRedirectsToLogin(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sid, _ := session.NewID()
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: sid})
	Middleware(middlewareOpts(store, testCipher(t)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run for an unknown session")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code = %d, want 302", rr.Code)
	}
}

func TestUndecryptableCredentialForcesReLogin(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	cipher := testCipher(t)
	// Encrypt under a different key: R14 key rotation invalidates sessions.
	other, err := session.NewCredentialCipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	sid := createSession(t, store, other, "cn=admin,dc=example,dc=com", "admin-password")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: sid})
	Middleware(middlewareOpts(store, cipher))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run with an undecryptable credential")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code = %d, want 302", rr.Code)
	}
	if _, err := store.Get(sid); err == nil {
		t.Error("undecryptable session must be deleted")
	}
}

func TestMalformedCookieRejected(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: "not-a-valid-id"})
	Middleware(middlewareOpts(store, testCipher(t)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run for a malformed cookie")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rr.Code)
	}
}

func TestStoreErrorReturns503(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	cipher := testCipher(t)
	sid := createSession(t, store, cipher, "cn=admin,dc=example,dc=com", "admin-password")
	store.Close() // force store failure
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: sid})
	Middleware(middlewareOpts(store, cipher))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if SessionFrom(context.Background()) != nil || StoreFrom(context.Background()) != nil {
		t.Error("SessionFrom/StoreFrom on empty ctx should be nil")
	}
}

func TestPublicPathsSkipGate(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	for _, path := range []string{"/healthz", "/static/css/main.css", "/login"} {
		t.Run(path, func(t *testing.T) {
			var ran bool
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			Middleware(middlewareOpts(store, testCipher(t)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ran = true
				if SessionFrom(r.Context()) != nil {
					t.Error("public path must not carry a session")
				}
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(rr, req)
			if !ran {
				t.Fatal("public path handler did not run")
			}
			if len(rr.Result().Cookies()) != 0 {
				t.Error("public path must not set a session cookie")
			}
		})
	}
}

func TestInvalidCredentialsRedirectInvalidates(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	cipher := testCipher(t)
	sid := createSession(t, store, cipher, "cn=admin,dc=example,dc=com", "admin-password")
	ctx := context.WithValue(context.Background(), sessionKey, &Session{ID: sid})
	ctx = context.WithValue(ctx, storeKey, store)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/entry/x/password", nil).WithContext(ctx)
	InvalidCredentialsRedirect(rr, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	if _, err := store.Get(sid); err == nil {
		t.Error("invalidCredentials must delete the session")
	}
	if cookie := sessionCookie(t, rr); cookie == nil || cookie.MaxAge >= 0 {
		t.Error("invalidCredentials must clear the cookie")
	}
}

func sessionCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	return nil
}
