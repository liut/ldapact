package ldapx

import (
	"fmt"
	"strconv"
	"strings"
)

// This file implements the small RFC 4512 description parser needed for the
// subschema entries returned by OpenLDAP/389-DS. go-ldap v3.4.14 ships no
// schema parsers, so the description grammar is parsed here (structure only;
// X-* extensions and OBSOLETE are tolerated and ignored).

func tokenize(s string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'':
			if inQuote && i+1 < len(s) && s[i+1] == '\'' {
				cur.WriteByte('\'')
				i++
				continue
			}
			inQuote = !inQuote
		case (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') && !inQuote:
			flush()
		case (ch == '(' || ch == ')') && !inQuote:
			flush()
			toks = append(toks, string(ch))
		default:
			cur.WriteByte(ch)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	flush()
	return toks, nil
}

// ParseObjectClass parses an objectClasses value.
func ParseObjectClass(s string) (*ObjectClass, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	if len(toks) < 3 || toks[0] != "(" {
		return nil, fmt.Errorf("malformed objectClass description %q", s)
	}
	oc := &ObjectClass{OID: toks[1]}
	for i := 2; i < len(toks); i++ {
		switch toks[i] {
		case "NAME":
			names, next, err := nameList(toks, i+1)
			if err != nil {
				return nil, err
			}
			oc.Names = names
			if len(names) > 0 {
				oc.Name = names[0]
			}
			i = next - 1
		case "DESC":
			if i+1 < len(toks) {
				oc.Desc = toks[i+1]
				i++
			}
		case "SUP":
			vals, next, err := valueList(toks, i+1)
			if err != nil {
				return nil, err
			}
			oc.Sup = vals
			i = next - 1
		case "MUST":
			vals, next, err := valueList(toks, i+1)
			if err != nil {
				return nil, err
			}
			oc.Must = vals
			i = next - 1
		case "MAY":
			vals, next, err := valueList(toks, i+1)
			if err != nil {
				return nil, err
			}
			oc.May = vals
			i = next - 1
		case "STRUCTURAL", "AUXILIARY", "ABSTRACT":
			oc.Kind = toks[i]
		}
	}
	if oc.Name == "" {
		return nil, fmt.Errorf("objectClass %q has no NAME", s)
	}
	return oc, nil
}

// ParseAttributeType parses an attributeTypes value.
func ParseAttributeType(s string) (*AttributeType, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	if len(toks) < 3 || toks[0] != "(" {
		return nil, fmt.Errorf("malformed attributeType description %q", s)
	}
	at := &AttributeType{OID: toks[1]}
	for i := 2; i < len(toks); i++ {
		switch toks[i] {
		case "NAME":
			names, next, err := nameList(toks, i+1)
			if err != nil {
				return nil, err
			}
			at.Names = names
			if len(names) > 0 {
				at.Name = names[0]
			}
			i = next - 1
		case "DESC":
			if i+1 < len(toks) {
				at.Desc = toks[i+1]
				i++
			}
		case "SUP":
			vals, next, err := valueList(toks, i+1)
			if err != nil {
				return nil, err
			}
			at.Sup = vals
			i = next - 1
		case "EQUALITY":
			if i+1 < len(toks) {
				at.Equality = toks[i+1]
				i++
			}
		case "ORDERING":
			if i+1 < len(toks) {
				at.Ordering = toks[i+1]
				i++
			}
		case "SUBSTR":
			if i+1 < len(toks) {
				at.Substr = toks[i+1]
				i++
			}
		case "SYNTAX":
			if i+1 < len(toks) {
				at.Syntax = toks[i+1]
				at.SyntaxOID = at.Syntax
				if j := strings.IndexByte(at.Syntax, '{'); j >= 0 {
					if end := strings.IndexByte(at.Syntax, '}'); end > j {
						if n, err := strconv.Atoi(at.Syntax[j+1 : end]); err == nil {
							at.MaxLength = n
						}
						at.SyntaxOID = at.Syntax[:j]
					}
				}
				i++
			}
		case "SINGLE-VALUE":
			at.SingleValue = true
		case "COLLECTIVE":
			at.Collective = true
		case "OBSOLETE":
			at.Obsolete = true
		case "NO-USER-MODIFICATION":
			at.NoUserModification = true
		case "USAGE":
			if i+1 < len(toks) {
				at.Usage = toks[i+1]
				i++
			}
		}
	}
	if at.Name == "" {
		return nil, fmt.Errorf("attributeType %q has no NAME", s)
	}
	return at, nil
}

// ParseLDAPSyntax parses an ldapSyntaxes value, returning OID and description.
func ParseLDAPSyntax(s string) (oid, desc string, err error) {
	toks, err := tokenize(s)
	if err != nil {
		return "", "", err
	}
	if len(toks) < 2 || toks[0] != "(" {
		return "", "", fmt.Errorf("malformed ldapSyntax description %q", s)
	}
	oid = toks[1]
	for i := 2; i+1 < len(toks); i++ {
		if toks[i] == "DESC" {
			desc = toks[i+1]
			break
		}
	}
	return oid, desc, nil
}

// ParseMatchingRule parses a matchingRules value, returning name and OID.
func ParseMatchingRule(s string) (name, oid string, err error) {
	toks, err := tokenize(s)
	if err != nil {
		return "", "", err
	}
	if len(toks) < 2 || toks[0] != "(" {
		return "", "", fmt.Errorf("malformed matchingRule description %q", s)
	}
	oid = toks[1]
	for i := 2; i < len(toks); i++ {
		switch toks[i] {
		case "NAME":
			names, next, err := nameList(toks, i+1)
			if err != nil {
				return "", "", err
			}
			if len(names) > 0 {
				name = names[0]
			}
			i = next - 1
		}
	}
	if name == "" {
		return "", "", fmt.Errorf("matchingRule %q has no NAME", s)
	}
	return name, oid, nil
}

// nameList parses NAME 'x' or NAME ( 'x' 'y' ), returning the names and the
// index just past the parsed region.
func nameList(toks []string, start int) ([]string, int, error) {
	return list(toks, start)
}

// valueList parses SUP/MUST/MAY which accept either a single token or a
// parenthesized $-separated list.
func valueList(toks []string, start int) ([]string, int, error) {
	if start >= len(toks) {
		return nil, start, nil
	}
	if toks[start] == ")" {
		return nil, start, fmt.Errorf("expected value or list, got %q", toks[start])
	}
	if toks[start] == "(" {
		var vals []string
		for i := start + 1; i < len(toks); i++ {
			if toks[i] == ")" {
				return vals, i + 1, nil
			}
			if toks[i] != "$" {
				vals = append(vals, toks[i])
			}
		}
		return nil, start, fmt.Errorf("unterminated list")
	}
	return []string{toks[start]}, start + 1, nil
}

func list(toks []string, start int) ([]string, int, error) {
	if start >= len(toks) {
		return nil, start, nil
	}
	if toks[start] == ")" {
		return nil, start, fmt.Errorf("expected name or list, got %q", toks[start])
	}
	if toks[start] == "(" {
		var vals []string
		for i := start + 1; i < len(toks); i++ {
			if toks[i] == ")" {
				return vals, i + 1, nil
			}
			vals = append(vals, toks[i])
		}
		return nil, start, fmt.Errorf("unterminated list")
	}
	return []string{toks[start]}, start + 1, nil
}
