package ldif

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
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

// TestIntegrationImportExportSearch covers F4/F7/F8 against a real OpenLDAP
// container (AE5-style partial success). Skips without Docker.
func TestIntegrationImportExportSearch(t *testing.T) {
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

	// F4: import entries through the handler; one entry violates schema
	// (missing required sn) and should fail while others succeed (AE5).
	renderer := web.New(web.MustParse(nil))
	imp := NewImportHandler(client, renderer, logger)
	ldifContent := `version: 1
dn: cn=alice,dc=example,dc=com
objectClass: inetOrgPerson
cn: alice
sn: Smith

dn: cn=bob,dc=example,dc=com
objectClass: inetOrgPerson
cn: bob
sn: Jones

dn: cn=bad,dc=example,dc=com
objectClass: inetOrgPerson
cn: bad
`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("ldif", "users.ldif")
	_, _ = fw.Write([]byte(ldifContent))
	_ = mw.Close()
	rr := httptest.NewRecorder()
	impReq := httptest.NewRequest(http.MethodPost, "/api/import", &buf)
	impReq.Header.Set("Content-Type", mw.FormDataContentType())
	imp.Submit(rr, impReq)
	body := rr.Body.String()
	if !strings.Contains(body, "Success: <strong>2</strong>") || !strings.Contains(body, "Failed: <strong>1</strong>") {
		t.Fatalf("import summary: %s", body)
	}

	// F7: export the subtree; userPassword-free, both entries present.
	exp := NewExportHandler(client, logger)
	rr = httptest.NewRecorder()
	expReq := httptest.NewRequest(http.MethodGet, "/api/export?dn=dc=example,dc=com&scope=subtree", nil)
	exp.Export(rr, expReq)
	export := rr.Body.String()
	for _, want := range []string{"dn: cn=alice,dc=example,dc=com", "dn: cn=bob,dc=example,dc=com"} {
		if !strings.Contains(export, want) {
			t.Errorf("export missing %q", want)
		}
	}
}
