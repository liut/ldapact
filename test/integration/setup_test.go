// Package integration runs the end-to-end F1-F8 smoke test (U8) against a
// throwaway LDAP backend (Docker container or local ephemeral slapd, see
// internal/testldap). It exits cleanly (skip) when no backend is available.
package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liut/ldapact/internal/app"
	"github.com/liut/ldapact/internal/testldap"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/session"
)

var (
	envCtx    context.Context
	envCancel context.CancelFunc
	envClient *ldapx.Client
	envCfg    *config.Config
	envLogBuf *bytes.Buffer
	envLogger *slog.Logger
	envServer *httptest.Server
	envInst   *testldap.Instance
	envHTTP   *http.Client
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	inst, err := testldap.Start(ctx)
	if errors.Is(err, testldap.ErrUnavailable) {
		fmt.Fprintln(os.Stderr, "integration: no LDAP backend available — skipping end-to-end tests:", err)
		os.Exit(0)
	}
	if err != nil {
		panic(fmt.Sprintf("integration: start test LDAP: %v", err))
	}
	envInst = inst
	startEnv(ctx)
	code := m.Run()
	stopEnv()
	os.Exit(code)
}

func startEnv(ctx context.Context) {
	envCtx, envCancel = context.WithCancel(ctx)
	envCfg = envInst.Config()
	envCfg.LDAP.PoolSize = 4
	// U5: the client pool is unbound; seeding carries the admin bind
	// credential in the context (the login gate supplies it in production).
	envCtx = ldapx.WithCredential(envCtx, ldapx.BindCredential{
		DN:       envCfg.LDAP.BindDN,
		Password: envInst.AdminPassword,
	})
	envLogBuf = &bytes.Buffer{}
	envLogger = slog.New(slog.NewJSONHandler(envLogBuf, nil))
	var err error
	envClient, err = ldapx.New(envCtx, envCfg, envLogger)
	if err != nil {
		panic(fmt.Sprintf("integration: connect: %v", err))
	}
	seed()

	store, err := session.NewStore(filepath.Join(os.TempDir(), "ldapact-it-sessions.db"), 30*time.Minute, 8*time.Hour)
	if err != nil {
		panic(err)
	}
	cipher, err := session.NewCredentialCipher("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		panic(err)
	}
	envServer = httptest.NewServer(app.NewHandler(app.Deps{
		Logger: envLogger,
		LDAP:   envClient,
		Store:  store,
		Cipher: cipher,
		Cfg:    envCfg,
	}))
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	envHTTP = envServer.Client()
	envHTTP.Jar = jar
}

func stopEnv() {
	if envServer != nil {
		envServer.Close()
	}
	if envClient != nil {
		envClient.Close()
	}
	if envCancel != nil {
		envCancel()
	}
	if envInst != nil {
		envInst.Stop()
	}
	_ = os.Remove(filepath.Join(os.TempDir(), "ldapact-it-sessions.db"))
}

// seed populates the test directory: 5 OUs, 1210 users (paged tree),
// 3 groups (PickList candidates).
func seed() {
	ctx := envCtx
	base := "dc=example,dc=com"
	ous := []string{"People", "Groups", "Depts", "Services", "Archive"}
	for _, ou := range ous {
		if err := envClient.Add(ctx, "ou="+ou+","+base, map[string][]string{
			"objectClass": {"top", "organizationalUnit"}, "ou": {ou},
		}); err != nil {
			panic(fmt.Sprintf("seed ou %s: %v", ou, err))
		}
	}
	for i := 1; i <= 1210; i++ {
		uid := fmt.Sprintf("u%04d", i)
		if err := envClient.Add(ctx, "uid="+uid+",ou=People,"+base, map[string][]string{
			"objectClass":   {"top", "person", "inetOrgPerson", "posixAccount"},
			"uid":           {uid},
			"cn":            {uid},
			"sn":            {"User" + uid},
			"uidNumber":     {fmt.Sprintf("%d", 2000+i)},
			"gidNumber":     {"100"},
			"homeDirectory": {"/home/" + uid},
			"userPassword":  {"Seed#2026"},
		}); err != nil {
			panic(fmt.Sprintf("seed user %s: %v", uid, err))
		}
	}
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("group%d", i)
		if err := envClient.Add(ctx, "cn="+name+",ou=Groups,"+base, map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {name},
			"gidNumber":   {fmt.Sprintf("%d", 100+i)},
		}); err != nil {
			panic(fmt.Sprintf("seed group %s: %v", name, err))
		}
	}
}

// client returns an HTTP client that follows the session cookie and sends the
// same-origin header required by the CSRF middleware.
func client() *http.Client {
	return envHTTP
}

func serverURL() string { return envServer.URL }

// dialEnv returns a fresh unbound connection for bind-verification checks.
func dialEnv() (ldapx.Conn, error) {
	return ldapx.Dial(envCtx, ldapx.DialOptions{URL: envCfg.LDAP.URL, TLS: envCfg.LDAP.TLS, Logger: nil})
}
