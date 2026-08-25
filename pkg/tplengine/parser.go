package tplengine

import (
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

// XML structs mirror template.dtd (R7 element set). encoding/xml is
// deliberately strict: unknown element types are errors, not silently
// ignored, so template drift is caught at load time.

type xmlTemplate struct {
	AskContainer  string         `xml:"askcontainer"`
	Description   string         `xml:"description"`
	Icon          string         `xml:"icon"`
	Invalid       string         `xml:"invalid"`
	RDN           string         `xml:"rdn"`
	Regexp        string         `xml:"regexp"`
	Title         string         `xml:"title"`
	Visible       string         `xml:"visible"`
	ObjectClasses []xmlObjectRef `xml:"objectClasses>objectClass"`
	Attributes    []xmlAttribute `xml:"attributes>attribute"`
}

type xmlObjectRef struct {
	ID string `xml:"id,attr"`
}

type xmlAttribute struct {
	ID        string     `xml:"id,attr"`
	Cols      string     `xml:"cols"`
	Default   string     `xml:"default"`
	Display   string     `xml:"display"`
	Helper    *xmlHelper `xml:"helper"`
	Hidden    string     `xml:"hidden"`
	Hint      string     `xml:"hint"`
	Icon      string     `xml:"icon"`
	MaxLength string     `xml:"maxlength"`
	OnChange  []string   `xml:"onchange"`
	Order     string     `xml:"order"`
	Page      string     `xml:"page"`
	Post      string     `xml:"post"`
	PreSubmit string     `xml:"presubmit"`
	Readonly  string     `xml:"readonly"`
	Rows      string     `xml:"rows"`
	Size      string     `xml:"size"`
	Spacer    string     `xml:"spacer"`
	Type      string     `xml:"type"`
	Values    []xmlValue `xml:"value"`
	Verify    string     `xml:"verify"`
}

type xmlHelper struct {
	Default string     `xml:"default"`
	Display string     `xml:"display"`
	ID      string     `xml:"id"`
	Values  []xmlValue `xml:"value"`
}

type xmlValue struct {
	ID   string `xml:"id,attr"`
	Text string `xml:",chardata"`
}

// Parse reads a template.dtd-compatible XML document. name is used in error
// messages. Macros referencing unknown php. functions fail here (R8: no
// runtime fallback for unknown functions).
func Parse(r io.Reader, name string) (*Template, error) {
	dec := xml.NewDecoder(r)
	var raw xmlTemplate
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("tplengine: parse %s: %w", name, err)
	}
	if raw.Title == "" {
		return nil, fmt.Errorf("tplengine: %s: missing <title>", name)
	}
	if raw.RDN == "" {
		return nil, fmt.Errorf("tplengine: %s: missing <rdn>", name)
	}
	if len(raw.ObjectClasses) == 0 {
		return nil, fmt.Errorf("tplengine: %s: no <objectClass> entries", name)
	}

	t := &Template{
		Name:         strings.TrimSuffix(path.Base(name), path.Ext(name)),
		Path:         name,
		Title:        raw.Title,
		Description:  raw.Description,
		RDN:          raw.RDN,
		Visible:      truthy(raw.Visible),
		AskContainer: truthy(raw.AskContainer),
		byID:         make(map[string]*Attribute),
	}
	for _, oc := range raw.ObjectClasses {
		if strings.TrimSpace(oc.ID) == "" {
			return nil, fmt.Errorf("tplengine: %s: objectClass without id", name)
		}
		t.ObjectClasses = append(t.ObjectClasses, oc.ID)
	}

	seenPages := map[int]bool{}
	for i, xa := range raw.Attributes {
		if strings.TrimSpace(xa.ID) == "" {
			return nil, fmt.Errorf("tplengine: %s: attribute %d without id", name, i)
		}
		attr, err := convertAttribute(xa, name)
		if err != nil {
			return nil, err
		}
		if _, dup := t.byID[strings.ToLower(attr.ID)]; dup {
			return nil, fmt.Errorf("tplengine: %s: duplicate attribute id %q", name, attr.ID)
		}
		t.byID[strings.ToLower(attr.ID)] = attr
		t.Attributes = append(t.Attributes, attr)
		seenPages[attr.Page] = true
	}
	for p := range seenPages {
		t.Pages = append(t.Pages, p)
	}
	t.SortFormFields()
	return t, nil
}

func convertAttribute(xa xmlAttribute, name string) (*Attribute, error) {
	a := &Attribute{
		ID:        xa.ID,
		Display:   xa.Display,
		HelpText:  xa.Hint,
		Order:     atoi(xa.Order),
		Page:      atoi(xa.Page),
		Cols:      atoi(xa.Cols),
		Rows:      atoi(xa.Rows),
		Size:      atoi(xa.Size),
		MaxLength: atoi(xa.MaxLength),
		Default:   xa.Default,
		Hidden:    truthy(xa.Hidden),
		Readonly:  truthy(xa.Readonly),
		Spacer:    truthy(xa.Spacer),
		Verify:    truthy(xa.Verify),
	}
	if a.Page == 0 {
		a.Page = 1
	}
	switch strings.ToLower(strings.TrimSpace(xa.Type)) {
	case "select":
		a.Kind = KindSelect
	case "textarea":
		a.Kind = KindTextarea
	case "password":
		a.Kind = KindPassword
	default:
		a.Kind = KindText
	}
	if a.Verify && a.Kind == KindText {
		a.Kind = KindPassword
	}

	for _, v := range xa.Values {
		id := v.ID
		if id == "" {
			id = v.Text
		}
		display := v.Text
		if v.ID != "" && v.Text == "" {
			display = id
		}
		a.Values = append(a.Values, Value{ID: id, Display: display})
	}
	if xa.Helper != nil {
		h := &Helper{ID: xa.Helper.ID, Display: xa.Helper.Display, Default: xa.Helper.Default}
		for _, v := range xa.Helper.Values {
			id := v.ID
			if id == "" {
				id = v.Text
			}
			h.Values = append(h.Values, Value{ID: id, Display: v.Text})
		}
		a.Helper = h
	}
	for _, raw := range []string{xa.Post, xa.PreSubmit} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if err := validateMacro(raw); err != nil {
			return nil, fmt.Errorf("tplengine: %s: attribute %q: %w", name, a.ID, err)
		}
		if strings.HasPrefix(strings.TrimSpace(raw), "=php.") {
			a.PostHooks = append(a.PostHooks, strings.TrimSpace(raw))
		}
	}
	for _, oc := range xa.OnChange {
		if err := validateMacro(oc); err != nil {
			return nil, fmt.Errorf("tplengine: %s: attribute %q onchange: %w", name, a.ID, err)
		}
		a.OnChange = append(a.OnChange, strings.TrimSpace(oc))
	}
	for _, v := range xa.Values {
		if strings.HasPrefix(strings.TrimSpace(v.Text), "=php.") {
			if err := validateMacro(v.Text); err != nil {
				return nil, fmt.Errorf("tplengine: %s: attribute %q value: %w", name, a.ID, err)
			}
		}
	}
	if xa.Helper != nil {
		for _, v := range xa.Helper.Values {
			if strings.HasPrefix(strings.TrimSpace(v.Text), "=php.") {
				if err := validateMacro(v.Text); err != nil {
					return nil, fmt.Errorf("tplengine: %s: attribute %q helper: %w", name, a.ID, err)
				}
			}
		}
	}
	return a, nil
}

// validateMacro rejects unknown =php.Func(...) and =autoFill(...) references
// at load time (R8, no runtime fallback).
func validateMacro(raw string) error {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "=php.") {
		funcName := macroFuncName(s)
		if !ServerFuncsAllowlist[funcName] {
			return fmt.Errorf("unknown server macro %q", funcName)
		}
	}
	if strings.HasPrefix(s, "=autoFill") {
		if _, err := ParseAutoFill(s); err != nil {
			return err
		}
	}
	return nil
}

// macroFuncName extracts the function name from "=php.Func(args)".
func macroFuncName(raw string) string {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "=php.")
	if i := strings.IndexByte(s, '('); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// macroArgs splits "=php.Func(a;b;c)" into ["a","b","c"] preserving empty
// entries (PHP-style ; separators).
func macroArgs(raw string) []string {
	s := strings.TrimSpace(raw)
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[i+1:]
		if j := strings.LastIndexByte(s, ')'); j >= 0 {
			s = s[:j]
		}
	}
	return strings.Split(s, ";")
}
