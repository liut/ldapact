package ldapx

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func sampleSchemaEntry() *ldap.Entry {
	return &ldap.Entry{
		DN: "cn=Subschema",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClasses", Values: []string{
				"( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
				"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP person STRUCTURAL MAY ( audio $ businessCategory $ mail $ uid $ userCertificate ) )",
				"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )",
			}},
			{Name: "attributeTypes", Values: []string{
				"( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )",
				"( 2.5.4.4 NAME ( 'sn' 'surname' ) DESC 'RFC4519: last (family) name(s)' SUP name EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )",
				"( 2.5.4.41 NAME 'name' DESC 'RFC4519: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
				"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'An integer uniquely identifying a user' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
				"( 2.5.4.35 NAME 'userPassword' DESC 'RFC4519/2307: password of user' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
			}},
			{Name: "ldapSyntaxes", Values: []string{
				"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
			}},
			{Name: "matchingRules", Values: []string{
				"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			}},
		},
	}
}

func TestParseSchema(t *testing.T) {
	s, err := ParseSchema(sampleSchemaEntry())
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}

	person, ok := s.ObjectClass("person")
	if !ok {
		t.Fatal("person objectClass missing")
	}
	if person.Kind != "STRUCTURAL" || len(person.Must) != 2 || person.Must[0] != "sn" || person.Must[1] != "cn" {
		t.Errorf("person = %+v", person)
	}
	if !contains(person.May, "userPassword") {
		t.Errorf("person MAY missing userPassword: %v", person.May)
	}

	inet, ok := s.ObjectClass("inetOrgPerson")
	if !ok {
		t.Fatal("inetOrgPerson missing")
	}
	if len(inet.Sup) != 1 || inet.Sup[0] != "person" {
		t.Errorf("inetOrgPerson SUP = %v", inet.Sup)
	}

	posix, ok := s.ObjectClass("posixAccount")
	if !ok || posix.Kind != "AUXILIARY" {
		t.Errorf("posixAccount = %+v", posix)
	}

	cn, ok := s.Attribute("commonName")
	if !ok || cn.Name != "cn" {
		t.Fatalf("commonName -> %+v", cn)
	}
	if len(cn.Names) != 2 || cn.Names[1] != "commonName" {
		t.Errorf("cn Names = %v", cn.Names)
	}
	if !strings.Contains(cn.Syntax, "1.3.6.1.4.1.1466.115.121.1.15") {
		t.Errorf("cn Syntax = %q", cn.Syntax)
	}

	uid, ok := s.Attribute("uidNumber")
	if !ok || !uid.SingleValue {
		t.Errorf("uidNumber = %+v", uid)
	}

	canon, ok := s.CanonicalAttribute("UIDNUMBER")
	if !ok || canon != "uidNumber" {
		t.Errorf("CanonicalAttribute(UIDNUMBER) = %q, %v", canon, ok)
	}
	if canon, ok := s.CanonicalAttribute("sn"); !ok || canon != "sn" {
		t.Errorf("CanonicalAttribute(sn) = %q, %v", canon, ok)
	}

	if _, ok := s.LDAPSyntaxes["1.3.6.1.4.1.1466.115.121.1.15"]; !ok {
		t.Error("ldapSyntax missing")
	}
	if _, ok := s.MatchingRules["caseIgnoreMatch"]; !ok {
		t.Error("matchingRule missing")
	}
}

func TestCanonicalAttributes(t *testing.T) {
	s, err := ParseSchema(sampleSchemaEntry())
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string][]string{"CN": {"Alice"}, "SN": {"Smith"}, "UIDNUMBER": {"1001"}}
	s.CanonicalAttributes(attrs)
	if _, ok := attrs["CN"]; ok {
		t.Error("CN should be canonicalized away")
	}
	if _, ok := attrs["cn"]; !ok {
		t.Error("cn missing")
	}
	if _, ok := attrs["uidNumber"]; !ok {
		t.Error("uidNumber missing")
	}
}

func TestParseObjectClassErrors(t *testing.T) {
	if _, err := ParseObjectClass("( 1.2.3 NAME )"); err == nil {
		t.Error("want error for missing NAME value")
	}
	if _, err := ParseObjectClass("garbage"); err == nil {
		t.Error("want error for malformed description")
	}
	if _, err := ParseAttributeType("( 1.2.3 DESC 'x' )"); err == nil {
		t.Error("want error for attributeType without NAME")
	}
}

func TestParseQuotedEscapes(t *testing.T) {
	oc, err := ParseObjectClass("( 1.2.3 NAME 'weird' DESC 'John''s class' SUP top STRUCTURAL MUST cn )")
	if err != nil {
		t.Fatalf("ParseObjectClass: %v", err)
	}
	if oc.Desc != "John's class" {
		t.Errorf("Desc = %q", oc.Desc)
	}
}

func TestParseMatchingRuleAndSyntax(t *testing.T) {
	name, oid, err := ParseMatchingRule("( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )")
	if err != nil || name != "caseIgnoreMatch" || oid != "2.5.13.2" {
		t.Errorf("matching rule = %q %q, %v", name, oid, err)
	}
	if _, _, err := ParseMatchingRule("( 1.2.3 )"); err == nil {
		t.Error("want error for matching rule without NAME")
	}
	oid2, desc, err := ParseLDAPSyntax("( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )")
	if err != nil || oid2 != "1.3.6.1.4.1.1466.115.121.1.15" || desc != "Directory String" {
		t.Errorf("ldap syntax = %q %q, %v", oid2, desc, err)
	}
}

func contains(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
