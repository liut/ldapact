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

	"github.com/go-ldap/ldap/v3"
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

// TestIntegrationEditEntry exercises the R1 edit flow (form → review → apply
// → verify via re-fetch) against a throwaway LDAP backend.
func TestIntegrationEditEntry(t *testing.T) {
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

	if err := client.Add(ctx, "ou=People,dc=example,dc=com", map[string][]string{
		"objectClass": {"top", "organizationalUnit"}, "ou": {"People"},
	}); err != nil {
		t.Fatalf("seed OU: %v", err)
	}
	dn := "cn=alice,ou=People,dc=example,dc=com"
	if err := client.Add(ctx, dn, map[string][]string{
		"objectClass": {"top", "person", "inetOrgPerson"},
		"cn":          {"alice"}, "sn": {"Smith"}, "givenName": {"Alice"},
		"mail":      {"alice@example.com"},
		"jpegPhoto": {string([]byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10})},
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// bob matches no modification template (person + organizationalPerson),
	// so his edit form exercises the generic editor and its schema-driven
	// controls; postalAddress (Postal Address syntax) is core-schema MAY.
	bobDN := "cn=bob,ou=People,dc=example,dc=com"
	if err := client.Add(ctx, bobDN, map[string][]string{
		"objectClass":  {"top", "person", "organizationalPerson"},
		"cn":           {"bob"}, "sn": {"Jones"},
		"postalAddress": {"123 Main St\nSpringfield"},
	}); err != nil {
		t.Fatalf("seed generic-editor user: %v", err)
	}

	renderer := web.New(web.MustParse(nil))
	loader := NewTemplateLoader(os.DirFS("../../templates"), "")
	h := New(client, renderer, logger, loader, nil, cfg)

	// Detail page renders the photo attribute as an embedded image.
	rr := httptest.NewRecorder()
	dReq := httptest.NewRequest(http.MethodGet, "/api/entry/"+dn, nil)
	dReq.SetPathValue("dn", dn)
	h.Detail(rr, dReq)
	if !strings.Contains(rr.Body.String(), `/photo?idx=0"`) {
		t.Fatalf("detail photo rendering missing: %.300s", rr.Body.String())
	}
	prr := httptest.NewRecorder()
	pReq := httptest.NewRequest(http.MethodGet, "/api/entry/"+dn+"/photo?idx=0", nil)
	pReq.SetPathValue("dn", dn)
	h.Photo(prr, pReq)
	if prr.Code != http.StatusOK || prr.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("photo endpoint = %d ct=%q", prr.Code, prr.Header().Get("Content-Type"))
	}

	// The modification template matches and prefills current values.
	rr = httptest.NewRecorder()
	gReq := httptest.NewRequest(http.MethodGet, "/api/entry/"+dn+"/edit", nil)
	gReq.SetPathValue("dn", dn)
	h.EditForm(rr, gReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Generic: Address Book Entry") {
		t.Fatalf("edit form = %d: %.400s", rr.Code, rr.Body.String())
	}

	form := url.Values{
		"givenName":                {"Alice"},
		"sn":                       {"Smith"},
		"cn":                       {"alice"},
		"jpegPhoto":                {""},
		"o":                        {""},
		"street":                   {""},
		"l":                        {""},
		"st":                       {""},
		"postalCode":               {""},
		"telephoneNumber":          {"+1 555 0100"},
		"facsimileTelephoneNumber": {""},
		"mobile":                   {""},
		"mail":                     {"alice@new.example.com"},
		"stage":                    {"review"},
	}
	rr = httptest.NewRecorder()
	rReq := httptest.NewRequest(http.MethodPost, "/api/entry/"+dn+"/edit", strings.NewReader(form.Encode()))
	rReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rReq.SetPathValue("dn", dn)
	h.EditSubmit(rr, rReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Review changes") {
		t.Fatalf("review = %d: %.400s", rr.Code, rr.Body.String())
	}

	form.Set("stage", "apply")
	rr = httptest.NewRecorder()
	aReq := httptest.NewRequest(http.MethodPost, "/api/entry/"+dn+"/edit", strings.NewReader(form.Encode()))
	aReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	aReq.SetPathValue("dn", dn)
	h.EditSubmit(rr, aReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Entry updated") {
		t.Fatalf("apply = %d: %.400s", rr.Code, rr.Body.String())
	}

	res, err := client.Search(ctx, ldap.NewSearchRequest(dn, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"*"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("refetch entries = %d", len(res.Entries))
	}
	if got := res.Entries[0].GetAttributeValue("mail"); got != "alice@new.example.com" {
		t.Errorf("mail = %q", got)
	}
	if got := res.Entries[0].GetAttributeValue("telephoneNumber"); got != "+1 555 0100" {
		t.Errorf("telephoneNumber = %q", got)
	}

	// Generic editor: postalAddress renders as a textarea prefilled, sn
	// carries the schema-MUST marker, and no operational attrs leak in.
	rr = httptest.NewRecorder()
	bReq := httptest.NewRequest(http.MethodGet, "/api/entry/"+bobDN+"/edit", nil)
	bReq.SetPathValue("dn", bobDN)
	h.EditForm(rr, bReq)
	bobForm := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("bob edit form = %d: %.400s", rr.Code, bobForm)
	}
	for _, want := range []string{
		"the generic editor",
		`name="postalAddress"`,
		"<textarea",
		"123 Main St",
		`for="f-sn">sn <span class="schema-required">Required (schema)</span>`,
	} {
		if !strings.Contains(bobForm, want) {
			t.Errorf("generic edit form missing %q", want)
		}
	}

	// Change postalAddress through review → apply; re-fetch confirms.
	bobValues := url.Values{
		"postalAddress": {"456 Oak Ave\nSpringfield"},
		"sn":            {"Jones"},
		"stage":         {"review"},
	}
	rr = httptest.NewRecorder()
	bReq = httptest.NewRequest(http.MethodPost, "/api/entry/"+bobDN+"/edit", strings.NewReader(bobValues.Encode()))
	bReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bReq.SetPathValue("dn", bobDN)
	h.EditSubmit(rr, bReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "456 Oak Ave") {
		t.Fatalf("bob review = %d: %.400s", rr.Code, rr.Body.String())
	}
	bobValues.Set("stage", "apply")
	rr = httptest.NewRecorder()
	bReq = httptest.NewRequest(http.MethodPost, "/api/entry/"+bobDN+"/edit", strings.NewReader(bobValues.Encode()))
	bReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bReq.SetPathValue("dn", bobDN)
	h.EditSubmit(rr, bReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Entry updated") {
		t.Fatalf("bob apply = %d: %.400s", rr.Code, rr.Body.String())
	}
	bRes, err := client.Search(ctx, ldap.NewSearchRequest(bobDN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"*"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(bRes.Entries) != 1 || bRes.Entries[0].GetAttributeValue("postalAddress") != "456 Oak Ave\nSpringfield" {
		t.Errorf("bob postalAddress after edit = %q (entries %d)",
			bRes.Entries[0].GetAttributeValue("postalAddress"), len(bRes.Entries))
	}

	// Unchanged submit short-circuits to "No changes" (no Modify).
	rr = httptest.NewRecorder()
	bReq = httptest.NewRequest(http.MethodPost, "/api/entry/"+bobDN+"/edit", strings.NewReader(bobValues.Encode()))
	bReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bReq.SetPathValue("dn", bobDN)
	h.EditSubmit(rr, bReq)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "No changes") {
		t.Fatalf("bob unchanged apply = %d: %.400s", rr.Code, rr.Body.String())
	}
}
