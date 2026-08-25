package ldapx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// ObjectClass is a parsed RFC 4512 objectClass definition (R5).
type ObjectClass struct {
	OID   string
	Name  string
	Names []string
	Desc  string
	Sup   []string
	Must  []string
	May   []string
	Kind  string // STRUCTURAL | AUXILIARY | ABSTRACT
}

// AttributeType is a parsed RFC 4512 attributeType definition (R5).
type AttributeType struct {
	OID         string
	Name        string
	Names       []string
	Desc        string
	Sup         []string
	Equality    string
	Ordering    string
	Substr      string
	Syntax      string
	SingleValue bool
	Usage       string
}

// Schema is the process-lifetime cache of the LDAP subschema (R14). It is
// populated once at startup and treated as immutable afterwards.
type Schema struct {
	mu             sync.RWMutex
	ObjectClasses  map[string]*ObjectClass
	AttributeTypes map[string]*AttributeType
	LDAPSyntaxes   map[string]string
	MatchingRules  map[string]string
	ocByAnyName    map[string]*ObjectClass
	atByAnyName    map[string]*AttributeType
}

// NewSchema builds an empty Schema.
func NewSchema() *Schema {
	return &Schema{
		ObjectClasses:  make(map[string]*ObjectClass),
		AttributeTypes: make(map[string]*AttributeType),
		LDAPSyntaxes:   make(map[string]string),
		MatchingRules:  make(map[string]string),
		ocByAnyName:    make(map[string]*ObjectClass),
		atByAnyName:    make(map[string]*AttributeType),
	}
}

// loadSchema fetches the subschema subentry and caches it. Failure is
// fail-fast: the process must not start with an empty schema cache (R14).
func (c *Client) loadSchema(ctx context.Context) error {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"subschemaSubentry"}, nil)
	res, err := c.Search(ctx, req)
	if err != nil {
		return fmt.Errorf("ldapx: fetch root DSE: %w", err)
	}
	if len(res.Entries) == 0 {
		return errors.New("ldapx: root DSE returned no entries")
	}
	subDN := res.Entries[0].GetAttributeValue("subschemaSubentry")
	if subDN == "" {
		return errors.New("ldapx: root DSE has no subschemaSubentry")
	}

	subReq := ldap.NewSearchRequest(subDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)",
		[]string{"objectClasses", "attributeTypes", "ldapSyntaxes", "matchingRules"}, nil)
	subRes, err := c.Search(ctx, subReq)
	if err != nil {
		return fmt.Errorf("ldapx: fetch subschema %s: %w", subDN, err)
	}
	if len(subRes.Entries) == 0 {
		return fmt.Errorf("ldapx: subschema %s returned no entries", subDN)
	}
	s, err := ParseSchema(subRes.Entries[0])
	if err != nil {
		return fmt.Errorf("ldapx: parse subschema %s: %w", subDN, err)
	}
	c.schema = s
	return nil
}

// Schema returns the cached subschema.
func (c *Client) Schema() *Schema {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.schema
}

// ParseSchema builds a Schema from a subschema entry.
func ParseSchema(entry *ldap.Entry) (*Schema, error) {
	s := NewSchema()
	for _, v := range entry.GetAttributeValues("objectClasses") {
		oc, err := ParseObjectClass(v)
		if err != nil {
			return nil, fmt.Errorf("objectClass %q: %w", v, err)
		}
		s.ObjectClasses[oc.Name] = oc
		for _, n := range oc.Names {
			s.ocByAnyName[strings.ToLower(n)] = oc
		}
	}
	for _, v := range entry.GetAttributeValues("attributeTypes") {
		at, err := ParseAttributeType(v)
		if err != nil {
			return nil, fmt.Errorf("attributeType %q: %w", v, err)
		}
		s.AttributeTypes[at.Name] = at
		for _, n := range at.Names {
			s.atByAnyName[strings.ToLower(n)] = at
		}
	}
	for _, v := range entry.GetAttributeValues("ldapSyntaxes") {
		oid, desc, err := ParseLDAPSyntax(v)
		if err != nil {
			return nil, fmt.Errorf("ldapSyntax %q: %w", v, err)
		}
		s.LDAPSyntaxes[oid] = desc
	}
	for _, v := range entry.GetAttributeValues("matchingRules") {
		name, oid, err := ParseMatchingRule(v)
		if err != nil {
			return nil, fmt.Errorf("matchingRule %q: %w", v, err)
		}
		s.MatchingRules[name] = oid
	}
	return s, nil
}

// CanonicalAttribute maps any case/alias of an attribute name to the schema's
// primary name (R14 canonicalization).
func (s *Schema) CanonicalAttribute(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	at, ok := s.atByAnyName[strings.ToLower(name)]
	if !ok {
		return name, false
	}
	return at.Name, true
}

// Attribute returns the attributeType for any of its names.
func (s *Schema) Attribute(name string) (*AttributeType, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	at, ok := s.atByAnyName[strings.ToLower(name)]
	return at, ok
}

// ObjectClass returns the objectClass for any of its names.
func (s *Schema) ObjectClass(name string) (*ObjectClass, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	oc, ok := s.ocByAnyName[strings.ToLower(name)]
	return oc, ok
}

// CanonicalAttributes canonicalizes every key of attrs in place.
func (s *Schema) CanonicalAttributes(attrs map[string][]string) {
	for k, v := range attrs {
		if canon, ok := s.CanonicalAttribute(k); ok && canon != k {
			delete(attrs, k)
			attrs[canon] = v
		}
	}
}
