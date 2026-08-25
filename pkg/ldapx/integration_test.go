package ldapx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/config"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// newOpenLDAPContainer starts a fresh OpenLDAP 2.6 container for the test.
// The plan's Execution note requires testcontainers-go; when Docker is
// unavailable the test skips (plan-sanctioned fallback to unit tests only).
func newOpenLDAPContainer(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)

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
		t.Fatalf("start OpenLDAP container: %v", err)
	}
	port, err := container.MappedPort(ctx, "1389/tcp")
	if err != nil {
		_ = testcontainers.TerminateContainer(container)
		t.Fatalf("mapped port: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port.Num())
	return addr, func() { _ = testcontainers.TerminateContainer(container) }
}

// newIntegrationClient dials with a short retry loop so the container's
// slapd has a moment to accept binds after the port is mapped.
func newIntegrationClient(t *testing.T, addr string) *Client {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{}
	cfg.LDAP.URL = "ldap://" + addr
	cfg.LDAP.BaseDN = "dc=example,dc=com"
	cfg.LDAP.BindDN = "cn=admin,dc=example,dc=com"
	cfg.BindPassword = "admin_password"
	cfg.LDAP.PoolSize = 2
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	var client *Client
	var lastErr error
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		client, lastErr = New(ctx, cfg, logger)
		cancel()
		if lastErr == nil {
			return client
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("connect to OpenLDAP at %s: %v", addr, lastErr)
	return nil
}

func TestIntegrationRoundTrip(t *testing.T) {
	ctx := context.Background()
	addr, stop := newOpenLDAPContainer(t, ctx)
	defer stop()

	client := newIntegrationClient(t, addr)
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
	addr, stop := newOpenLDAPContainer(t, ctx)
	defer stop()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{}
	cfg.LDAP.URL = "ldap://" + addr
	cfg.LDAP.BaseDN = "dc=example,dc=com"
	cfg.LDAP.BindDN = "cn=admin,dc=example,dc=com"
	cfg.BindPassword = "wrong-password"
	cfg.LDAP.PoolSize = 1
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := New(ctx2, cfg, logger)
	if err == nil {
		t.Fatal("want bind failure with wrong password")
	}
	var lerr *LDAPError
	if !errors.As(err, &lerr) || lerr.Code != 49 {
		t.Fatalf("want LDAP result code 49 (invalidCredentials), got %v", err)
	}
}
