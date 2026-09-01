package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/internal/testldap"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/session"
)

// startTestApp assembles the full handler chain against a throwaway LDAP
// backend (skips when unavailable).
func startTestApp(t *testing.T) (*httptest.Server, *testldap.Instance, *session.BboltStore, *config.Config, *http.Client) {
	t.Helper()
	ctx := context.Background()
	inst, err := testldap.Start(ctx)
	if errors.Is(err, testldap.ErrUnavailable) {
		t.Skip("no LDAP backend available: " + err.Error())
	}
	if err != nil {
		t.Fatalf("start test LDAP: %v", err)
	}
	t.Cleanup(inst.Stop)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := inst.Config()
	client, err := ldapx.New(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(client.Close)

	store, err := session.NewStore(t.TempDir()+"/sessions.db", 30*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cipher, err := session.NewCredentialCipher("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewHandler(Deps{
		Logger: logger, LDAP: client, Store: store, Cipher: cipher, Cfg: cfg,
	}))
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	hc := srv.Client()
	hc.Jar = jar
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // observe 302s; the jar still collects cookies
	}
	return srv, inst, store, cfg, hc
}

func loginRequest(t *testing.T, srv *httptest.Server, hc *http.Client, bindDN, password string) *http.Response {
	t.Helper()
	form := url.Values{"bind_dn": {bindDN}, "password": {password}, "next": {"/"}}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", srv.URL)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestLoginGateFlow(t *testing.T) {
	srv, inst, _, cfg, hc := startTestApp(t)

	// No cookie → 302 to /login.
	resp, err := hc.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("gate: code=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Login page is public.
	resp, err = hc.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login page = %d", resp.StatusCode)
	}

	// Wrong password (AE6): error page, no session created.
	resp = loginRequest(t, srv, hc, cfg.LDAP.BindDN, "wrong-password")
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Login failed") {
		t.Fatalf("wrong password: %d %.200s", resp.StatusCode, body)
	}
	if len(hc.Jar.Cookies(mustURL(t, srv.URL))) != 0 {
		t.Error("no session cookie expected after failed login")
	}

	// Correct login → 302 + cookie; the cookie grants access to protected
	// tree fragments.
	resp = loginRequest(t, srv, hc, cfg.LDAP.BindDN, inst.AdminPassword)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if len(hc.Jar.Cookies(mustURL(t, srv.URL))) == 0 {
		t.Fatal("login must set a session cookie")
	}
	resp, err = hc.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	home := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("home after login = %d", resp.StatusCode)
	}
	for _, want := range []string{`action="/logout"`, "Logged in as", cfg.LDAP.BindDN} {
		if !strings.Contains(home, want) {
			t.Errorf("home missing %q", want)
		}
	}
	resp, err = hc.Get(srv.URL + "/api/tree/dc=example,dc=com/children?page=1&level=2")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tree fragment with session = %d", resp.StatusCode)
	}

	// Logout (R7/AE3): redirect, cookie cleared, session deleted.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/logout", nil)
	req.Header.Set("Origin", srv.URL)
	resp, err = hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	if len(hc.Jar.Cookies(mustURL(t, srv.URL))) != 0 {
		t.Error("logout must clear the session cookie")
	}
}

// TestLoginRateLimited verifies the dedicated login limiter (2/s, burst 5)
// rejects the sixth rapid POST /login with 429 while normal traffic stays
// unaffected (the global 60/s limiter does not fire).
func TestLoginRateLimited(t *testing.T) {
	srv, _, _, cfg, hc := startTestApp(t)
	var got429 bool
	for i := 0; i < 6; i++ {
		resp := loginRequest(t, srv, hc, cfg.LDAP.BindDN, "wrong-password-"+string(rune('a'+i)))
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusTooManyRequests {
			got429 = true
			break
		}
		if code != http.StatusOK {
			t.Fatalf("login attempt %d = %d, want 200 (error page) or 429", i, code)
		}
	}
	if !got429 {
		t.Fatal("rapid login attempts must be rate limited")
	}
	// The login limiter only wraps POST /login: GET /login stays reachable
	// even while the POST bucket is exhausted.
	resp, err := hc.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /login after throttling = %d, want 200", resp.StatusCode)
	}
}

func TestExpiredSessionRedirects(t *testing.T) {
	srv, inst, store, cfg, hc := startTestApp(t)
	resp := loginRequest(t, srv, hc, cfg.LDAP.BindDN, inst.AdminPassword)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	// Advance the store clock past the idle window (AE2).
	store.SetNow(func() time.Time { return time.Now().Add(31 * time.Minute) })
	resp, err := hc.Get(srv.URL + "/search?q=(objectClass=*)")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("expired: code=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestPublicPathsBypassGate(t *testing.T) {
	srv, _, _, _, hc := startTestApp(t)
	for _, path := range []string{"/healthz", "/static/htmx.min.js", "/login"} {
		resp, err := hc.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, resp.StatusCode)
		}
	}
}

// TestInvalidCredentialsInvalidatesSession is AE5: after the directory
// password changes, the next operation fails with invalidCredentials, the
// session is deleted, and the client is redirected to login.
func TestInvalidCredentialsInvalidatesSession(t *testing.T) {
	srv, inst, store, cfg, hc := startTestApp(t)
	ctx := ldapx.WithCredential(context.Background(), ldapx.BindCredential{
		DN:       cfg.LDAP.BindDN,
		Password: inst.AdminPassword,
	})
	adminClient, err := ldapx.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer adminClient.Close()
	userDN := "uid=ae5user,dc=example,dc=com"
	if err := adminClient.Add(ctx, userDN, map[string][]string{
		"objectClass":  {"top", "person", "inetOrgPerson"},
		"uid":          {"ae5user"},
		"cn":           {"ae5user"},
		"sn":           {"AE5"},
		"userPassword": {"first-password"},
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	defer func() { _ = adminClient.Delete(ctx, userDN) }()

	// Log in as the user.
	resp := loginRequest(t, srv, hc, userDN, "first-password")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("user login = %d", resp.StatusCode)
	}
	cookies := hc.Jar.Cookies(mustURL(t, srv.URL))
	if len(cookies) == 0 {
		t.Fatal("no session cookie")
	}
	sid := cookies[0].Value

	// The directory password changes out-of-band; the session credential is
	// now stale.
	if err := adminClient.Modify(ctx, userDN, []ldap.Change{{
		Operation:    ldap.ReplaceAttribute,
		Modification: ldap.PartialAttribute{Type: "userPassword", Vals: []string{"second-password"}},
	}}); err != nil {
		t.Fatalf("change user password: %v", err)
	}

	// The user's next operation fails with 49 → session invalidated →
	// redirect to /login.
	resp, err = hc.Get(srv.URL + "/search?q=(uid=ae5user)")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("stale credential request = %d, want 302", resp.StatusCode)
	}
	if _, err := store.Get(sid); err == nil {
		t.Error("AE5: session must be deleted after invalidCredentials")
	}
	if len(hc.Jar.Cookies(mustURL(t, srv.URL))) != 0 {
		t.Error("AE5: cookie must be cleared")
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return string(b)
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
