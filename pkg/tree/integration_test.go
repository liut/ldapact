package tree

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liut/ldapact/internal/testldap"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

func TestIntegrationTreeAndSchema(t *testing.T) {
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
	client, err := ldapx.New(ctx, inst.Config(), logger)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	seed(t, ctx, client)

	renderer := web.New(web.MustParse(nil))
	tree := NewTree(client, renderer, logger)

	// Root children: the seeded OUs.
	rr := httptest.NewRecorder()
	rootReq := httptest.NewRequest(http.MethodGet, "/api/tree/dc=example,dc=com/children?page=1&level=2", nil)
	rootReq.SetPathValue("dn", "dc=example,dc=com")
	tree.Children(rr, rootReq)
	body := rr.Body.String()
	for _, want := range []string{">People<", ">Groups<", `aria-expanded="false"`} {
		if !strings.Contains(body, want) {
			t.Errorf("root children missing %q: %s", want, body)
		}
	}

	// A leaf user's branch is empty.
	rr = httptest.NewRecorder()
	leafReq := httptest.NewRequest(http.MethodGet, "/api/tree/cn=alice,ou=People,dc=example,dc=com/children", nil)
	leafReq.SetPathValue("dn", "cn=alice,ou=People,dc=example,dc=com")
	tree.Children(rr, leafReq)
	if !strings.Contains(rr.Body.String(), "(no children)") {
		t.Errorf("leaf branch: %s", rr.Body.String())
	}

	// Schema cache came up with the core schema (R5).
	schema := client.Schema()
	if _, ok := schema.ObjectClass("person"); !ok {
		t.Error("schema cache missing person objectClass")
	}
	if _, ok := schema.Attribute("cn"); !ok {
		t.Error("schema cache missing cn attribute")
	}

	// Breadcrumb trail stops at the base DN.
	crumbs := Breadcrumbs("cn=alice,ou=People,dc=example,dc=com", client.BaseDN(), 5)
	if len(crumbs) != 3 || crumbs[len(crumbs)-1].DN != "cn=alice,ou=People,dc=example,dc=com" {
		t.Errorf("breadcrumbs = %+v", crumbs)
	}
}

func seed(t *testing.T, ctx context.Context, client *ldapx.Client) {
	t.Helper()
	entries := []struct {
		dn    string
		attrs map[string][]string
	}{
		{"ou=People,dc=example,dc=com", map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"People"}}},
		{"ou=Groups,dc=example,dc=com", map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"Groups"}}},
		{"cn=alice,ou=People,dc=example,dc=com", map[string][]string{
			"objectClass": {"top", "person", "inetOrgPerson"}, "cn": {"alice"}, "sn": {"Smith"}, "uid": {"alice"},
		}},
		{"cn=bob,ou=People,dc=example,dc=com", map[string][]string{
			"objectClass": {"top", "person", "inetOrgPerson"}, "cn": {"bob"}, "sn": {"Jones"}, "uid": {"bob"},
		}},
	}
	for _, e := range entries {
		if err := client.Add(ctx, e.dn, e.attrs); err != nil {
			t.Fatalf("seed %s: %v", e.dn, err)
		}
	}
}
