package tree

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func sampleSchema() *ldapx.Schema {
	entry := &ldap.Entry{
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClasses", Values: []string{
				"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP person STRUCTURAL MUST ( cn $ sn ) MAY ( mail $ telephoneNumber ) )",
				"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY userPassword )",
			}},
			{Name: "attributeTypes", Values: []string{
				"( 2.5.4.3 NAME 'cn' DESC 'common name' SUP name EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'user id' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
				"( 2.5.4.4 NAME 'sn' SUP name SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
				"( 2.5.4.20 NAME 'telephoneNumber' EQUALITY telephoneNumberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
				"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
			}},
		},
	}
	s, err := ldapx.ParseSchema(entry)
	if err != nil {
		panic(err)
	}
	return s
}

func schemaBrowser(t *testing.T) *SchemaBrowser {
	t.Helper()
	renderer := web.New(web.MustParse(nil))
	return NewSchemaBrowser(&fakeLister{schema: sampleSchema()}, renderer)
}

func TestObjectClassesList(t *testing.T) {
	rr := httptest.NewRecorder()
	schemaBrowser(t).ObjectClasses(rr, httptest.NewRequest(http.MethodGet, "/api/schema/objectclass", nil))
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	// Sorted: inetOrgPerson before person.
	if strings.Index(body, "inetOrgPerson") > strings.Index(body, `>person<`) {
		t.Errorf("list not sorted: %s", body)
	}
	for _, want := range []string{"/api/schema/objectclass/inetOrgPerson", "STRUCTURAL"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestObjectClassDetail(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/objectclass/inetOrgPerson", nil)
	req.SetPathValue("name", "inetOrgPerson")
	schemaBrowser(t).ObjectClassDetail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{
		"2.16.840.1.113730.3.2.2",
		`/api/schema/objectclass/person`,
		`/api/schema/attribute/cn`,
		`/api/schema/attribute/sn`,
		`/api/schema/attribute/mail`,
		"MAY",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q: %s", want, body)
		}
	}
}

func TestObjectClassDetail404(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/objectclass/nope", nil)
	req.SetPathValue("name", "nope")
	schemaBrowser(t).ObjectClassDetail(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestAttributesList(t *testing.T) {
	rr := httptest.NewRecorder()
	schemaBrowser(t).Attributes(rr, httptest.NewRequest(http.MethodGet, "/api/schema/attribute", nil))
	body := rr.Body.String()
	for _, want := range []string{"/api/schema/attribute/cn", "single-value", "multi-value"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q: %s", want, body)
		}
	}
}

func TestAttributeDetail(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/attribute/uidNumber", nil)
	req.SetPathValue("name", "uidNumber")
	schemaBrowser(t).AttributeDetail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"1.3.6.1.4.1.1466.115.121.1.27", "<dd>yes</dd>", "uidNumber"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q: %s", want, body)
		}
	}
}

func TestAttributeDetail404(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/attribute/nope", nil)
	req.SetPathValue("name", "nope")
	schemaBrowser(t).AttributeDetail(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestSchemaNilReturns503(t *testing.T) {
	renderer := web.New(web.MustParse(nil))
	b := NewSchemaBrowser(&fakeLister{}, renderer)
	rr := httptest.NewRecorder()
	b.ObjectClasses(rr, httptest.NewRequest(http.MethodGet, "/api/schema/objectclass", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d", rr.Code)
	}
}
