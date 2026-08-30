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
				"( 2.5.6.0 NAME 'top' ABSTRACT )",
				"( 2.5.6.16 NAME 'applicationEntity' SUP top STRUCTURAL MUST ( cn $ presentationAddress ) MAY ( knowledgeInformation $ description $ l $ o $ ou $ seeAlso $ supportedApplicationContext ) )",
				"( 2.5.6.13 NAME 'dSA' SUP applicationEntity STRUCTURAL )",
				"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY userPassword )",
				"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP person STRUCTURAL MUST ( cn $ sn ) MAY ( mail $ telephoneNumber ) )",
			}},
			{Name: "attributeTypes", Values: []string{
				"( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'common name' SUP name EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )",
				"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'user id' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
				"( 2.5.4.4 NAME 'sn' SUP name SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
				"( 2.5.4.20 NAME 'telephoneNumber' EQUALITY telephoneNumberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
				"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
				"( 2.5.4.4 NAME 'presentationAddress' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
				"( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			}},
			{Name: "ldapSyntaxes", Values: []string{
				"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
				"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )",
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
		"Inherits from",
		"Parent to",
		"Required Attributes",
		"Optional Attributes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q: %s", want, body)
		}
	}
	// cn/sn/mail/telephoneNumber are declared by inetOrgPerson itself and keep
	// their own declaration (person's duplicates lose the dedup); userPassword
	// comes only from person and must be annotated as inherited.
	if strings.Count(body, "Inherited from") != 1 ||
		!strings.Contains(body, ">userPassword</a><br><small>(Inherited from") {
		t.Errorf("expected only userPassword to be inherited: %s", body)
	}
	for _, own := range []string{"cn", "sn", "mail", "telephoneNumber"} {
		if strings.Contains(body, ">"+own+"</a><br><small>(Inherited from") {
			t.Errorf("%s should not be inherited: %s", own, body)
		}
	}
}

func TestObjectClassDetailInheritedAttrs(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/objectclass/dSA", nil)
	req.SetPathValue("name", "dSA")
	schemaBrowser(t).ObjectClassDetail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{
		"2.5.6.13",
		`/api/schema/objectclass/applicationEntity`,
		`/api/schema/attribute/cn`,
		`/api/schema/attribute/presentationAddress`,
		"(Inherited from",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dSA detail missing %q: %s", want, body)
		}
	}
	// Declared order is preserved (phpLDAPadmin parity): the MAY list starts
	// with knowledgeInformation, not an alphabetical sort.
	if !strings.Contains(body, "knowledgeInformation") ||
		strings.Index(body, "knowledgeInformation") > strings.Index(body, ">description<") {
		t.Errorf("dSA MAY order should follow the declaration: %s", body)
	}
}

func TestObjectClassDetailParentTo(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/objectclass/applicationEntity", nil)
	req.SetPathValue("name", "applicationEntity")
	schemaBrowser(t).ObjectClassDetail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{`/api/schema/objectclass/dSA`, ">dSA<"} {
		if !strings.Contains(body, want) {
			t.Errorf("applicationEntity detail missing %q: %s", want, body)
		}
	}
}

func TestObjectClassDetailTop(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/objectclass/top", nil)
	req.SetPathValue("name", "top")
	schemaBrowser(t).ObjectClassDetail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{`<a href="/api/schema/objectclass">all</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("top detail missing %q: %s", want, body)
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
	for _, want := range []string{
		"1.3.6.1.4.1.1466.115.121.1.27",
		"<td>Yes</td>",
		"uidNumber",
		"Single Valued",
		"(not applicable)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q: %s", want, body)
		}
	}
}

func TestAttributeDetailRich(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/schema/attribute/cn", nil)
	req.SetPathValue("name", "cn")
	schemaBrowser(t).AttributeDetail(rr, req)
	body := rr.Body.String()
	for _, want := range []string{
		`/api/schema/attribute/name`,                       // SUP resolved to canonical name
		`/api/schema/attribute/commonName`,                 // alias link
		"Directory String (1.3.6.1.4.1.1466.115.121.1.15)", // syntax desc + OID
		"64 characters",                                    // max length from {64}
		"Used by objectClasses",
		`/api/schema/objectclass/person`,
		`/api/schema/objectclass/applicationEntity`,
		"(not specified)", // ordering/substring/usage
	} {
		if !strings.Contains(body, want) {
			t.Errorf("cn detail missing %q: %s", want, body)
		}
	}
	// cn is used directly by applicationEntity, person, inetOrgPerson — but
	// not by dSA (which only inherits it via applicationEntity).
	if strings.Contains(body, "/api/schema/objectclass/dSA") {
		t.Errorf("cn should not be used by dSA (inherited only): %s", body)
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
