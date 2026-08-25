package ldif

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
)

type fakeExporter struct {
	entries []*ldap.Entry
	pages   []*ldapx.PageResult
}

func (f *fakeExporter) Search(_ context.Context, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return &ldap.SearchResult{Entries: f.entries}, nil
}

func (f *fakeExporter) Page(_ context.Context, _ ldapx.SearchOptions, page int) (*ldapx.PageResult, error) {
	if page <= len(f.pages) {
		return f.pages[page-1], nil
	}
	return &ldapx.PageResult{HasMore: false}, nil
}

func TestExportEntryRedactsPassword(t *testing.T) {
	client := &fakeExporter{entries: []*ldap.Entry{{
		DN: "cn=alice,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"alice"}},
			{Name: "userPassword", Values: []string{"{SSHA512}secret-hash"}},
		},
	}}}
	h := NewExportHandler(client, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export?dn=cn=alice,dc=example,dc=com&scope=entry", nil)
	h.Export(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, "secret-hash") {
		t.Error("userPassword must be redacted by default")
	}
	if !strings.Contains(body, "dn: cn=alice,dc=example,dc=com") || !strings.Contains(body, "cn: alice") {
		t.Errorf("entry missing: %s", body)
	}
}

func TestExportEntryWithSecrets(t *testing.T) {
	client := &fakeExporter{entries: []*ldap.Entry{{
		DN: "cn=alice,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "userPassword", Values: []string{"{SSHA512}secret-hash"}},
		},
	}}}
	h := NewExportHandler(client, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export?dn=cn=alice,dc=example,dc=com&scope=entry&include_secrets=1", nil)
	h.Export(rr, req)
	if !strings.Contains(rr.Body.String(), "secret-hash") {
		t.Error("include_secrets=1 must include userPassword")
	}
}

func TestExportSubtreeStreams(t *testing.T) {
	client := &fakeExporter{pages: []*ldapx.PageResult{
		{Entries: []*ldap.Entry{{DN: "cn=a,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"a"}}}}}, HasMore: true, Page: 1},
		{Entries: []*ldap.Entry{{DN: "cn=b,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "cn", Values: []string{"b"}}}}}, HasMore: false, Page: 2},
	}}
	h := NewExportHandler(client, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export?dn=dc=x&scope=subtree", nil)
	h.Export(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"version: 1", "dn: cn=a,dc=x", "dn: cn=b,dc=x"} {
		if !strings.Contains(body, want) {
			t.Errorf("subtree export missing %q:\n%s", want, body)
		}
	}
}

func TestExportInvalidScope(t *testing.T) {
	h := NewExportHandler(&fakeExporter{}, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export?dn=x&scope=bogus", nil)
	h.Export(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestExportBinaryAttribute(t *testing.T) {
	client := &fakeExporter{entries: []*ldap.Entry{{
		DN: "cn=alice,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "userCertificate;binary", Values: []string{"cert"}, ByteValues: [][]byte{{0x30, 0x82, 0x01}}},
		},
	}}}
	h := NewExportHandler(client, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export?dn=cn=alice,dc=example,dc=com&scope=entry", nil)
	h.Export(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "userCertificate;binary::") {
		t.Errorf("binary attr must be base64: %s", body)
	}
}
