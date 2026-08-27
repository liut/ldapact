package ldapx

import (
	"sort"
	"strings"
)

// RFC 4517 attribute syntax OIDs used by the edit-form control classifier.
const (
	SyntaxBoolean            = "1.3.6.1.4.1.1466.115.121.1.7"
	SyntaxBinary             = "1.3.6.1.4.1.1466.115.121.1.5"
	SyntaxCertificate        = "1.3.6.1.4.1.1466.115.121.1.8"
	SyntaxCertificateList    = "1.3.6.1.4.1.1466.115.121.1.9"
	SyntaxCertificatePair    = "1.3.6.1.4.1.1466.115.121.1.10"
	SyntaxDistinguishedName  = "1.3.6.1.4.1.1466.115.121.1.12"
	SyntaxJPEG               = "1.3.6.1.4.1.1466.115.121.1.28"
	SyntaxNameAndOptionalUID = "1.3.6.1.4.1.1466.115.121.1.34"
	SyntaxPostalAddress      = "1.3.6.1.4.1.1466.115.121.1.41"
)

// ControlKind is the edit-form control rendered for an attributeType.
type ControlKind string

const (
	ControlKindText     ControlKind = "text"
	ControlKindSelect   ControlKind = "select"
	ControlKindReadonly ControlKind = "readonly"
	ControlKindTextarea ControlKind = "textarea"
	// ControlKindDN renders as a text input with a DN hint (no picker in v1).
	ControlKindDN ControlKind = "dn"
)

// binarySyntaxes are RFC 4517 syntaxes whose values must not round-trip
// through a text input (mirrors the phpLDAPadmin AttributeFactory binary
// classification).
var binarySyntaxes = map[string]bool{
	SyntaxBinary:          true,
	SyntaxCertificate:     true,
	SyntaxCertificateList: true,
	SyntaxCertificatePair: true,
	SyntaxJPEG:            true,
}

// ControlKind returns the edit-form control kind for an attribute, derived
// from its RFC 4517 syntax. ok is false when the attribute is not present in
// the schema; callers fall back to their default rendering (text).
func (s *Schema) ControlKind(name string) (ControlKind, bool) {
	at, ok := s.Attribute(name)
	if !ok {
		return ControlKindText, false
	}
	switch {
	case at.Syntax == SyntaxBoolean:
		return ControlKindSelect, true
	case at.Syntax == SyntaxDistinguishedName || at.Syntax == SyntaxNameAndOptionalUID:
		return ControlKindDN, true
	case binarySyntaxes[at.Syntax]:
		return ControlKindReadonly, true
	case at.Syntax == SyntaxPostalAddress:
		return ControlKindTextarea, true
	default:
		return ControlKindText, true
	}
}

// IsOperational reports whether an attribute is operational per its schema
// USAGE declaration (RFC 4512). Schema-unknown names return false so callers
// can apply their own fallback exclusions.
func (s *Schema) IsOperational(name string) bool {
	at, ok := s.Attribute(name)
	if !ok {
		return false
	}
	usage := strings.ToLower(strings.TrimSpace(at.Usage))
	return usage != "" && usage != "userapplications"
}

// EffectiveMust returns the canonical MUST attribute names for the given
// objectClasses, resolved through SUP inheritance, deduplicated and sorted.
func (s *Schema) EffectiveMust(objectClasses []string) []string {
	return s.effectiveAttrs(objectClasses, func(oc *ObjectClass) []string { return oc.Must })
}

// EffectiveMay returns the canonical MAY attribute names for the given
// objectClasses, resolved through SUP inheritance, deduplicated and sorted.
func (s *Schema) EffectiveMay(objectClasses []string) []string {
	return s.effectiveAttrs(objectClasses, func(oc *ObjectClass) []string { return oc.May })
}

// effectiveAttrs walks each objectClass and its SUP chain, collecting the
// selected attribute list. Unknown classes are skipped best-effort; a visited
// set guards against malformed SUP cycles.
func (s *Schema) effectiveAttrs(objectClasses []string, pick func(*ObjectClass) []string) []string {
	seenOC := map[string]bool{}
	seenAttr := map[string]bool{}
	var out []string
	var walk func(name string)
	walk = func(name string) {
		if name == "" || seenOC[strings.ToLower(name)] {
			return
		}
		seenOC[strings.ToLower(name)] = true
		oc, ok := s.ObjectClass(name)
		if !ok {
			return
		}
		for _, v := range pick(oc) {
			canon := v
			if c, ok := s.CanonicalAttribute(v); ok {
				canon = c
			}
			if !seenAttr[strings.ToLower(canon)] {
				seenAttr[strings.ToLower(canon)] = true
				out = append(out, canon)
			}
		}
		for _, sup := range oc.Sup {
			walk(sup)
		}
	}
	for _, oc := range objectClasses {
		walk(oc)
	}
	sort.Strings(out)
	return out
}
