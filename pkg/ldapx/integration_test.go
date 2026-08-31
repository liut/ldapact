package ldapx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/internal/testldap"
)

// testInstance starts a throwaway LDAP backend (Docker container or local
// ephemeral slapd) and skips when no backend is available.
func testInstance(t *testing.T, ctx context.Context) *testldap.Instance {
	t.Helper()
	inst, err := testldap.Start(ctx)
	if errors.Is(err, testldap.ErrUnavailable) {
		t.Skip("no LDAP backend available: " + err.Error())
	}
	if err != nil {
		t.Fatalf("start test LDAP: %v", err)
	}
	t.Cleanup(inst.Stop)
	return inst
}

func TestIntegrationRoundTrip(t *testing.T) {
	ctx := context.Background()
	inst := testInstance(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := New(ctx, inst.Config(), logger)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	// The main pool is unbound (R15): every operation uses the
	// request-scoped credential injected into the context (U5).
	ctx = WithCredential(ctx, BindCredential{DN: inst.AdminDN, Password: inst.AdminPassword})

	// The subschema cache loads lazily on the first authenticated
	// operation (U5); it must be populated after the first search.
	if _, err := client.Page(ctx, SearchOptions{
		BaseDN: "dc=example,dc=com",
		Scope:  ldap.ScopeSingleLevel,
	}, 1); err != nil {
		t.Fatalf("first authenticated Page: %v", err)
	}
	schema := client.Schema()
	if _, ok := schema.ObjectClass("inetOrgPerson"); !ok {
		t.Error("schema cache missing inetOrgPerson")
	}
	if _, ok := schema.Attribute("uidNumber"); !ok {
		t.Error("schema cache missing uidNumber")
	}

	// Empty tree returns an empty first page (R2).
	page, err := client.Page(ctx, SearchOptions{
		BaseDN: "dc=example,dc=com",
		Scope:  ldap.ScopeSingleLevel,
	}, 1)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if len(page.Entries) != 0 || page.HasMore {
		t.Errorf("unexpected page: %+v", page)
	}

	// Add / read / modify / rename / delete round-trip (R3).
	dn := "cn=alice,dc=example,dc=com"
	err = client.Add(ctx, dn, map[string][]string{
		"objectClass": {"top", "person", "inetOrgPerson"},
		"cn":          {"alice"},
		"sn":          {"Smith"},
		"uid":         {"alice"},
		"mail":        {"alice@example.com"},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	res, err := client.Search(ctx, ldap.NewSearchRequest(dn, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
		[]string{"cn", "sn", "mail"}, nil))
	if err != nil {
		t.Fatalf("Search after add: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("mail") != "alice@example.com" {
		t.Fatalf("read-back mismatch: %+v", res.Entries)
	}

	err = client.Modify(ctx, dn, []ldap.Change{{
		Operation:    ldap.ReplaceAttribute,
		Modification: ldap.PartialAttribute{Type: "description", Vals: []string{"updated by test"}},
	}})
	if err != nil {
		t.Fatalf("Modify: %v", err)
	}

	err = client.ModifyDN(ctx, dn, "cn=alice2", true, "")
	if err != nil {
		t.Fatalf("ModifyDN: %v", err)
	}
	if _, err := client.Search(ctx, ldap.NewSearchRequest("cn=alice2,dc=example,dc=com",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)); err != nil {
		t.Fatalf("search renamed entry: %v", err)
	}

	err = client.Delete(ctx, "cn=alice2,dc=example,dc=com")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestIntegrationVerifyBind(t *testing.T) {
	ctx := context.Background()
	inst := testInstance(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := inst.Config()
	dialOpts := DialOptions{URL: cfg.LDAP.URL, TLS: cfg.LDAP.TLS, Logger: logger}

	// Correct credentials: the login gate's check succeeds (R6).
	if err := VerifyBind(ctx, dialOpts, inst.AdminDN, inst.AdminPassword); err != nil {
		t.Fatalf("VerifyBind with correct credentials: %v", err)
	}

	// Wrong password: typed LDAP result code 49, never a network error.
	err := VerifyBind(ctx, dialOpts, inst.AdminDN, "wrong-password")
	if err == nil {
		t.Fatal("want bind failure with wrong password")
	}
	var lerr *LDAPError
	if !errors.As(err, &lerr) || lerr.Code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("want LDAP result code 49 (invalidCredentials), got %v", err)
	}
	if !IsInvalidCredentials(err) {
		t.Fatalf("IsInvalidCredentials must be true, got %v", err)
	}
}

func TestIntegrationPerRequestBind(t *testing.T) {
	ctx := context.Background()
	inst := testInstance(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := New(ctx, inst.Config(), logger)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	adminCtx := WithCredential(ctx, BindCredential{DN: inst.AdminDN, Password: inst.AdminPassword})

	// A non-admin user with its own password can bind and search, proving
	// the pool binds per request instead of keeping a configured identity.
	userDN := "cn=u5user,dc=example,dc=com"
	if err := client.Add(adminCtx, userDN, map[string][]string{
		"objectClass":  {"top", "person"},
		"cn":           {"u5user"},
		"sn":           {"User"},
		"userPassword": {"u5-password"},
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	defer func() { _ = client.Delete(adminCtx, userDN) }()

	userCtx := WithCredential(ctx, BindCredential{DN: userDN, Password: "u5-password"})
	res, err := client.Search(userCtx, ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	if err != nil {
		t.Fatalf("search with per-request user bind: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(res.Entries))
	}

	// Mutations still work with the admin identity on the same pool.
	if err := client.Modify(adminCtx, userDN, []ldap.Change{{
		Operation:    ldap.ReplaceAttribute,
		Modification: ldap.PartialAttribute{Type: "description", Vals: []string{"updated"}},
	}}); err != nil {
		t.Fatalf("admin modify after user bind on same pool: %v", err)
	}
}
