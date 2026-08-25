// Package tplengine ports phpLDAPadmin's XML template engine (R6/R7/R8):
// a typed model parsed from template.dtd-compatible XML, server macros
// evaluated at render time, and the autoFill client-macro compiler.
package tplengine

import (
	"sort"
	"strings"
)

// AttributeKind is the rendered control type for an attribute.
type AttributeKind int

const (
	KindText AttributeKind = iota
	KindPassword
	KindSelect
	KindTextarea
)

func (k AttributeKind) String() string {
	switch k {
	case KindPassword:
		return "password"
	case KindSelect:
		return "select"
	case KindTextarea:
		return "textarea"
	default:
		return "text"
	}
}

// Template is a parsed creation template.
type Template struct {
	Name          string // base file name without extension
	Path          string // source (for error messages)
	Title         string
	Description   string
	RDN           string
	Visible       bool
	AskContainer  bool
	ObjectClasses []string
	Pages         []int // sorted page numbers
	Attributes    []*Attribute
	byID          map[string]*Attribute
}

// Attribute is one field of the form (R7 attribute element).
type Attribute struct {
	ID        string
	Kind      AttributeKind
	Display   string
	HelpText  string
	Order     int
	Page      int
	Readonly  bool
	Hidden    bool
	Spacer    bool
	Verify    bool
	Cols      int
	Rows      int
	Size      int
	MaxLength int
	Default   string
	Values    []Value
	PostHooks []string // raw =php.Func(...) macro strings
	OnChange  []string // raw =autoFill(...) macro strings
	Helper    *Helper
	// Evaluated is a server-side macro result (PickList/GetNextNumber)
	// produced at render time.
	Evaluated *Evaluated
}

// Value is one <value> option of a select attribute.
type Value struct {
	ID       string
	Display  string
	Selected bool
}

// Helper mirrors the <helper> element (R7).
type Helper struct {
	ID      string
	Display string
	Default string
	Values  []Value
}

// Evaluated holds the render-time result of a value macro.
type Evaluated struct {
	Kind      string // "picklist" | "nextnumber" | "text"
	Values    []Value
	Text      string
	MaxHit    bool   // GetNextNumber ceiling reached (R8.y)
	NoMatches bool   // PickList returned zero candidates (R8.x)
	Notice    string // rendered notice, e.g. "未找到候选"
}

// Attribute returns the attribute with the given id (canonicalized to the
// schema primary name at parse time).
func (t *Template) Attribute(id string) (*Attribute, bool) {
	a, ok := t.byID[strings.ToLower(id)]
	return a, ok
}

// RequiredAttributes returns attributes that are not readonly, hidden, or
// spacers, in form order — the fields a submitter must supply.
func (t *Template) RequiredAttributes() []*Attribute {
	var out []*Attribute
	for _, a := range t.Attributes {
		if a.Hidden || a.Readonly || a.Spacer || a.Kind == KindSelect {
			continue
		}
		out = append(out, a)
	}
	return out
}

// SortFormFields orders attributes by (Page, Order, original position).
func (t *Template) SortFormFields() {
	sort.SliceStable(t.Attributes, func(i, j int) bool {
		if t.Attributes[i].Page != t.Attributes[j].Page {
			return t.Attributes[i].Page < t.Attributes[j].Page
		}
		return t.Attributes[i].Order < t.Attributes[j].Order
	})
}
