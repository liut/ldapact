package entry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/liut/ldapact/internal/testldap"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

// TestIntegrationCreatePasswordRenameDelete exercises F2/F3/F5/F6 end to end
// against a throwaway LDAP backend (AE3 + AE4 gates). Skips when no backend
// is available.
func TestIntegrationCreatePasswordRenameDelete(t *testing.T) {
	ctx := context.Background()
	inst, err := testldap.Start(ctx)
	if errors.Is(err, testldap.ErrUnavailable) {
		t.Skip("no LDAP backend available: " + err.Error())
	}
	if err != nil {
		t.Fatalf("start test LDAP: %v", err)
	}
	defer inst.Stop()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := inst.Config()
	client, err := ldapx.New(ctx, cfg, logger)
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
