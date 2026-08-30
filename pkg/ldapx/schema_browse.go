package ldapx

import (
	"sort"
	"strings"
)

// ObjectClassAttr is one MUST/MAY attribute contributed by an objectClass
// definition, tagged with the objectClass that declared it (phpLDAPadmin
// ObjectClass_ObjectClassAttribute parity). Source drives the "Inherited
// from" annotation on the schema browser pages (R5.x).
type ObjectClassAttr struct {
	Name   string
	Source string
}

// EffectiveMustAttrs returns the MUST attributes of an objectClass resolved
// through SUP inheritance, each tagged with its declaring objectClass.
// Order matches phpLDAPadmin's getMustAttrs(true): the class's own attributes
// first, then each ancestor's in SUP traversal order, deduplicated by name
// keeping the first (declared) occurrence.
func (s *Schema) EffectiveMustAttrs(name string) []ObjectClassAttr {
	return s.effectiveTaggedAttrs([]string{name}, func(oc *ObjectClass) []string { return oc.Must })
}

// EffectiveMayAttrs behaves like EffectiveMustAttrs for MAY attributes.
func (s *Schema) EffectiveMayAttrs(name string) []ObjectClassAttr {
	return s.effectiveTaggedAttrs([]string{name}, func(oc *ObjectClass) []string { return oc.May })
}

// ChildObjectClasses returns the names of objectClasses that list name in
// their SUP (direct children), sorted. Used by the "Parent to" row of the
// objectClass detail page (phpLDAPadmin children_objectclasses).
func (s *Schema) ChildObjectClasses(name string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, oc := range s.ObjectClasses {
		for _, sup := range oc.Sup {
			if strings.EqualFold(sup, name) && !strings.EqualFold(oc.Name, name) {
				out = append(out, oc.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// ObjectClassesUsing returns the names of objectClasses whose own (direct)
// MUST or MAY list includes the attribute, resolved case-insensitively and
// through aliases. Sorted. Drives the "Used by objectClasses" row of the
// attribute detail page (phpLDAPadmin getUsedInObjectClasses parity).
func (s *Schema) ObjectClassesUsing(name string) []string {
	canon := strings.ToLower(name)
	if at, ok := s.atByAnyName[canon]; ok {
		canon = at.Name
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, oc := range s.ObjectClasses {
		if s.classUses(oc, canon) {
			out = append(out, oc.Name)
		}
	}
	sort.Strings(out)
	return out
}

// classUses reports whether an objectClass's direct MUST/MAY lists include the
// canonical attribute name, resolving class-side aliases through the schema.
// Callers must hold s.mu.
func (s *Schema) classUses(oc *ObjectClass, canon string) bool {
	for _, list := range [][]string{oc.Must, oc.May} {
		for _, a := range list {
			ca := a
			if at, ok := s.atByAnyName[strings.ToLower(a)]; ok {
				ca = at.Name
			}
			if strings.EqualFold(ca, canon) {
				return true
			}
		}
	}
	return false
}

// effectiveTaggedAttrs walks each objectClass and its SUP chain, collecting
// the selected attribute list with its declaring objectClass. Unknown classes
// are skipped best-effort; a visited set guards against malformed SUP cycles.
func (s *Schema) effectiveTaggedAttrs(objectClasses []string, pick func(*ObjectClass) []string) []ObjectClassAttr {
	seenOC := map[string]bool{}
	seenAttr := map[string]bool{}
	var out []ObjectClassAttr
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
			key := strings.ToLower(v)
			if !seenAttr[key] {
				seenAttr[key] = true
				out = append(out, ObjectClassAttr{Name: v, Source: oc.Name})
			}
		}
		for _, sup := range oc.Sup {
			walk(sup)
		}
	}
	for _, oc := range objectClasses {
		walk(oc)
	}
	return out
}
