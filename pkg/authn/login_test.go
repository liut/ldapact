package authn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/liut/ldapact/internal/testldap"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/session"
	"github.com/liut/ldapact/pkg/web"
)

func newLoginHandler(t *testing.T, store session.Store, client *ldapx.Client, serverRef, bindDN string) *LoginHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewLogin(store, testCipher(t), client, web.New(web.MustParse(nil)), logger, serverRef, bindDN)
}

func TestLoginFormRenders(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	h := newLoginHandler(t, store, nil, "ldap://replica-1", "cn=admin,dc=example,dc=com")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login?next=%2Fsearch", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`name="bind_dn"`, `value="cn=admin,dc=example,dc=com"`, `name="password"`, `name="next"`, `value="/search"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login form missing %q", want)
		}
	}
}

func TestSanitizeNext(t *testing.T) {
	cases := map[string]string{
		"":                     "/",
		"/search?q=(uid=x)":    "/search?q=(uid=x)",
		"https://evil.com":     "/",
		"//evil.com":           "/",
		"javascript:alert(1)":  "/",
		`/\evil.com`:           "/",
		"/path\r\nLocation: x": "/",
	}
	for in, want := range cases {
		if got := sanitizeNext(in); got != want {
			t.Errorf("sanitizeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginSubmitRequiresFields(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	h := newLoginHandler(t, store, nil, "ldap://replica-1", "")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("bind_dn=&password="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "required") {
		t.Errorf("missing required-fields error: %s", rr.Body.String())
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Error("no session cookie expected on failed login")
	}
}

// TestLoginSubmitIntegration exercises the full login gate against a real
// LDAP backend: correct credentials mint a session carrying the encrypted
// credential (R6), wrong credentials render an error (AE6), and logout
// invalidates the session (R7/AE3).
func TestLoginSubmitIntegration(t *testing.T) {
	ctx := context.Background()
	inst, err := testldap.Start(ctx)
	if errors.Is(err, testldap.ErrUnavailable) {
		t.Skip("no LDAP backend available: " + err.Error())
	}
	if err != nil {
		t.Fatalf("start test LDAP: %v", err)
	}
	defer inst.Stop()

	cfg := inst.Config()
	client, err := ldapx.New(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	store := testStore(t, 30*time.Minute, 8*time.Hour)
	h := newLoginHandler(t, store, client, cfg.LDAP.URL, cfg.LDAP.BindDN)

	// Wrong password: error page, no cookie, no session created (AE6).
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("bind_dn="+cfg.LDAP.BindDN+"&password=wrong&next=%2F"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Login failed") {
		t.Fatalf("wrong password: code=%d body=%.200s", rr.Code, rr.Body.String())
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Error("no cookie expected after failed login")
	}

	// Correct password: redirect + session cookie + encrypted credential.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("bind_dn="+cfg.LDAP.BindDN+"&password="+inst.AdminPassword+"&next=%2Fentry%2Fdc%3Dexample"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("login code = %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/entry/dc=example" {
		t.Errorf("Location = %q", loc)
	}
	cookie := sessionCookie(t, rr)
	if cookie == nil || !session.ValidID(cookie.Value) {
		t.Fatalf("session cookie = %+v", cookie)
	}
	v, err := store.Get(cookie.Value)
	if err != nil {
		t.Fatalf("stored session missing: %v", err)
	}
	if v.ProfileRef != cfg.LDAP.BindDN || len(v.Credential) == 0 {
		t.Errorf("session fields: profile=%q credential=%d bytes", v.ProfileRef, len(v.Credential))
	}
	plain, err := testCipher(t).Decrypt(v.Credential)
	if err != nil || string(plain) != inst.AdminPassword {
		t.Errorf("credential round-trip failed: %v", err)
	}

	// Logout: session deleted, cookie cleared (AE3).
	rr = httptest.NewRecorder()
	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: session.CookieName, Value: cookie.Value})
	logoutReq = logoutReq.WithContext(context.WithValue(context.Background(), sessionKey, &Session{ID: cookie.Value}))
	h.Logout(rr, logoutReq)
	if rr.Code != http.StatusFound {
		t.Fatalf("logout code = %d", rr.Code)
	}
	if _, err := store.Get(cookie.Value); err == nil {
		t.Error("logout must delete the session record")
	}
	if c := sessionCookie(t, rr); c == nil || c.MaxAge >= 0 {
		t.Error("logout must clear the cookie")
	}
}

func TestLoginReplacesExistingSession(t *testing.T) {
	store := testStore(t, 30*time.Minute, 8*time.Hour)
	h := newLoginHandler(t, store, nil, "ldap://replica-1", "")
	h.verify = func(context.Context, string, string) error { return nil }
	oldID, err := session.NewID()
	if err != nil {
		t.Fatal(err)
	}
	oldEnc, _ := testCipher(t).Encrypt([]byte("old-password"))
	if _, err := store.Create(oldID, "old", "ldap://replica-1", oldEnc); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("bind_dn=cn=new,dc=example,dc=com&password=new-password&next=/"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: oldID})
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := store.Get(oldID); err == nil {
		t.Error("re-login must replace the old session")
	}
	cookie := sessionCookie(t, rr)
	if cookie == nil {
		t.Fatal("no session cookie after re-login")
	}
	v, err := store.Get(cookie.Value)
	if err != nil {
		t.Fatalf("new session missing: %v", err)
	}
	if v.ProfileRef != "cn=new,dc=example,dc=com" {
		t.Errorf("new session profile = %q", v.ProfileRef)
	}
}
