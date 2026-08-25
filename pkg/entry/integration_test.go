package entry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestIntegrationCreatePasswordRenameDelete exercises F2/F3/F5/F6 end to end
// against a real OpenLDAP container (AE3 + AE4 gates). Skips without Docker.
func TestIntegrationCreatePasswordRenameDelete(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()

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
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start OpenLDAP: %v", err)
	}
	defer func() { _ = testcontainers.TerminateContainer(container) }()
	port, err := container.MappedPort(ctx, "1389/tcp")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{}
	cfg.LDAP.URL = fmt.Sprintf("ldap://127.0.0.1:%d", port.Num())
	cfg.LDAP.BaseDN = "dc=example,dc=com"
	cfg.LDAP.BindDN = "cn=admin,dc=example,dc=com"
	cfg.BindPassword = "admin_password"
	cfg.LDAP.PoolSize = 2
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var client *ldapx.Client
	for i := 0; i < 10; i++ {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		client, err = ldapx.New(cctx, cfg, logger)
		cancel()
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	// Seed an OU container.
	if err := client.Add(ctx, "ou=People,dc=example,dc=com", map[string][]string{
		"objectClass": {"top", "organizationalUnit"}, "ou": {"People"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	renderer := web.New(web.MustParse(nil))
	loader := NewTemplateLoader(os.DirFS("../../templates"), "")
	h := New(client, renderer, logger, loader, nil, cfg)

	// F2: create a posixAccount user via the handler (AE3).
	form := url.Values{
		"container": {"ou=People,dc=example,dc=com"},
		"givenName": {"Alice"}, "sn": {"Smith"}, "cn": {"alice"}, "uid": {"alice"},
		"userPassword": {"NewPass#2026"}, "homeDirectory": {"/home/alice"},
		"uidNumber": {"1001"}, "gidNumber": {"100"}, "loginShell": {"/bin/bash"},
	}
	rr := httptest.NewRecorder()
	cReq := httptest.NewRequest(http.MethodPost, "/api/template/posixAccount/create", strings.NewReader(form.Encode()))
	cReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cReq.SetPathValue("name", "posixAccount")
	h.CreateSubmit(rr, cReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("create code = %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-Mutated-Subtree"); got != "ou=People,dc=example,dc=com" {
		t.Errorf("mutated header = %q", got)
	}

	// The new password must bind (AE4).
	conn, err := ldapx.Dial(ctx, ldapx.DialOptions{URL: cfg.LDAP.URL, TLS: cfg.LDAP.TLS, Logger: nil})
	if err != nil {
		t.Fatal(err)
	}
	if err := ldapx.Bind(conn, "cn=alice,ou=People,dc=example,dc=com", "NewPass#2026"); err != nil {
		t.Fatalf("new account bind: %v", err)
	}
	conn.Close()

	// F3: change the password through the handler.
	pwForm := url.Values{"new_password": {"Changed#2026"}, "confirm_password": {"Changed#2026"}}
	rr = httptest.NewRecorder()
	pReq := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/password", strings.NewReader(pwForm.Encode()))
	pReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pReq.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.PasswordChange(rr, pReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Password changed") {
		t.Fatalf("password change: %d %s", rr.Code, rr.Body.String())
	}
	conn, err = ldapx.Dial(ctx, ldapx.DialOptions{URL: cfg.LDAP.URL, TLS: cfg.LDAP.TLS, Logger: nil})
	if err != nil {
		t.Fatal(err)
	}
	if err := ldapx.Bind(conn, "cn=alice,ou=People,dc=example,dc=com", "Changed#2026"); err != nil {
		t.Fatalf("changed password bind: %v", err)
	}
	conn.Close()

	// F6: rename the entry.
	rForm := url.Values{"new_rdn": {"cn=alice2"}, "delete_old_rdn": {"1"}}
	rr = httptest.NewRecorder()
	rReq := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice,ou=People,dc=example,dc=com/rename", strings.NewReader(rForm.Encode()))
	rReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rReq.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	h.RenameSubmit(rr, rReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename code = %d: %s", rr.Code, rr.Body.String())
	}

	// F5: delete the (leaf) entry.
	dForm := url.Values{"confirm_dn": {"cn=alice2,ou=People,dc=example,dc=com"}}
	rr = httptest.NewRecorder()
	dReq := httptest.NewRequest(http.MethodPost, "/api/entry/cn=alice2,ou=People,dc=example,dc=com/delete", strings.NewReader(dForm.Encode()))
	dReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dReq.SetPathValue("dn", "cn=alice2,ou=People,dc=example,dc=com")
	h.DeleteSubmit(rr, dReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete code = %d: %s", rr.Code, rr.Body.String())
	}
}
