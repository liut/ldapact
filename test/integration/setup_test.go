// Package integration runs the end-to-end F1-F8 smoke test (U8) against a
// testcontainers-go OpenLDAP instance. It exits cleanly (skip) when Docker is
// unavailable, per the plan's CI fallback.
package integration

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/liut/ldapact/internal/app"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/session"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	envCtx    context.Context
	envCancel context.CancelFunc
	envClient *ldapx.Client
	envCfg    *config.Config
	envLogBuf *bytes.Buffer
	envLogger *slog.Logger
	envServer *httptest.Server
)

func TestMain(m *testing.M) {
	if !dockerAvailable() {
		fmt.Fprintln(os.Stderr, "integration: docker unavailable — skipping end-to-end tests")
		os.Exit(0)
	}
	startEnv()
	code := m.Run()
	stopEnv()
	os.Exit(code)
}

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	return cmd.Run() == nil
}

func startEnv() {
	envCtx, envCancel = context.WithCancel(context.Background())
	req := testcontainers.ContainerRequest{
		Image:        "docker.io/bitnami/openldap:2.6",
		ExposedPorts: []string{"1389/tcp"},
		Env: map[string]string{
			"LDAP_ADMIN_USERNAME": "admin",
			"LDAP_ADMIN_PASSWORD": "admin_password",
			"LDAP_ROOT":           "dc=example,dc=com",
		},
		WaitingFor: wait.ForListeningPort("1389/tcp").WithStartupTimeout(120 * time.Second),
	}
	container, err := testcontainers.GenericContainer(envCtx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		panic(fmt.Sprintf("integration: start OpenLDAP: %v", err))
	}
	envContainer = container
	port, err := container.MappedPort(envCtx, "1389/tcp")
	if err != nil {
		panic(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port.Num())

	envCfg = &config.Config{}
	envCfg.LDAP.URL = "ldap://" + addr
	envCfg.LDAP.BaseDN = "dc=example,dc=com"
	envCfg.LDAP.BindDN = "cn=admin,dc=example,dc=com"
	envCfg.BindPassword = "admin_password"
	envCfg.LDAP.PoolSize = 4
	if err := envCfg.Validate(); err != nil {
		panic(err)
	}
	envLogBuf = &bytes.Buffer{}
	envLogger = slog.New(slog.NewJSONHandler(envLogBuf, nil))
	for i := 0; i < 10; i++ {
		cctx, cancel := context.WithTimeout(envCtx, 10*time.Second)
		envClient, err = ldapx.New(cctx, envCfg, envLogger)
		cancel()
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		panic(fmt.Sprintf("integration: connect: %v", err))
	}
	seed()

	store, err := session.NewStore(filepath.Join(os.TempDir(), "ldapact-it-sessions.db"), 30*time.Minute, 8*time.Hour)
	if err != nil {
		panic(err)
	}
	envServer = httptest.NewServer(app.NewHandler(app.Deps{
		Logger: envLogger,
		LDAP:   envClient,
		Store:  store,
		Cfg:    envCfg,
	}))
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
	if envContainer != nil {
		_ = testcontainers.TerminateContainer(envContainer)
	}
	_ = os.Remove(filepath.Join(os.TempDir(), "ldapact-it-sessions.db"))
}

var envContainer testcontainers.Container

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
	return envServer.Client()
}

func serverURL() string { return envServer.URL }

// dialEnv returns a fresh unbound connection for bind-verification checks.
func dialEnv() (ldapx.Conn, error) {
	return ldapx.Dial(envCtx, ldapx.DialOptions{URL: envCfg.LDAP.URL, TLS: envCfg.LDAP.TLS, Logger: nil})
}
