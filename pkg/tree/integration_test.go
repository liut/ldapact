package tree

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegrationTreeAndSchema(t *testing.T) {
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

	seed(t, ctx, client)

	renderer := web.New(web.MustParse(nil))
	tree := NewTree(client, renderer, logger)

	// Root children: the seeded OUs.
	rr := httptest.NewRecorder()
	tree.Children(rr, httptest.NewRequest(http.MethodGet, "/api/tree/dc=example,dc=com/children?page=1&level=2", nil))
	body := rr.Body.String()
	for _, want := range []string{">People<", ">Groups<", `aria-expanded="false"`} {
		if !strings.Contains(body, want) {
			t.Errorf("root children missing %q: %s", want, body)
		}
	}

	// A leaf user's branch is empty.
	rr = httptest.NewRecorder()
	tree.Children(rr, httptest.NewRequest(http.MethodGet, "/api/tree/cn=alice,ou=People,dc=example,dc=com/children", nil))
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
