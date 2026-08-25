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

	// Subschema cache is populated at startup (R14).
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

func TestIntegrationInvalidCredentials(t *testing.T) {
	ctx := context.Background()
	inst := testInstance(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := inst.Config()
	cfg.BindPassword = "wrong-password"
	_, err := New(ctx, cfg, logger)
	if err == nil {
		t.Fatal("want bind failure with wrong password")
	}
	var lerr *LDAPError
	if !errors.As(err, &lerr) || lerr.Code != 49 {
		t.Fatalf("want LDAP result code 49 (invalidCredentials), got %v", err)
	}
}
