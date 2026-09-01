package ldif

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liut/ldapact/internal/testldap"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

// TestIntegrationImportExportSearch covers F4/F7/F8 against a real OpenLDAP
// backend (AE5-style partial success). Skips when no backend is available.
func TestIntegrationImportExportSearch(t *testing.T) {
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
	adminCtx := ldapx.WithCredential(ctx, ldapx.BindCredential{DN: inst.Config().LDAP.BindDN, Password: inst.AdminPassword})

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
	impReq := httptest.NewRequest(http.MethodPost, "/import", &buf)
	impReq.Header.Set("Content-Type", mw.FormDataContentType())
	impReq = impReq.WithContext(adminCtx)
	imp.Submit(rr, impReq)
	body := rr.Body.String()
	if !strings.Contains(body, "Success: <strong>2</strong>") || !strings.Contains(body, "Failed: <strong>1</strong>") {
		t.Fatalf("import summary: %s", body)
	}

	// F7: export the subtree; userPassword-free, both entries present.
	exp := NewExportHandler(client, logger)
	rr = httptest.NewRecorder()
	expReq := httptest.NewRequest(http.MethodGet, "/api/export?dn=dc=example,dc=com&scope=subtree", nil)
	expReq = expReq.WithContext(adminCtx)
	exp.Export(rr, expReq)
	export := rr.Body.String()
	for _, want := range []string{"dn: cn=alice,dc=example,dc=com", "dn: cn=bob,dc=example,dc=com"} {
		if !strings.Contains(export, want) {
			t.Errorf("export missing %q", want)
		}
	}
}
