package tplengine

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// tokenRE matches the documented %var|substart-end/modifier% grammar.
var tokenRE = regexp.MustCompile(`%([^%|/]+)(?:\|[^%|/]*)?(?:/[a-zA-Z]+)?%`)

// AutoFill is a compiled client macro (R8): source fields drive a target
// field through a token template.
type AutoFill struct {
	Target   string
	Template string
	Sources  []string
}

// ParseAutoFill parses "=autoFill(target;template)" and extracts the source
// field names from the template tokens.
func ParseAutoFill(raw string) (*AutoFill, error) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "=autoFill(") || !strings.HasSuffix(s, ")") {
		return nil, errors.New("tplengine: malformed autoFill macro")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(s, "=autoFill("), ")")
	parts := strings.SplitN(body, ";", 2)
	if len(parts) != 2 {
		return nil, errors.New("tplengine: autoFill requires target;template")
	}
	target := strings.TrimSpace(parts[0])
	tpl := strings.TrimSpace(parts[1])
	if target == "" || tpl == "" {
		return nil, errors.New("tplengine: autoFill target and template must be non-empty")
	}
	a := &AutoFill{Target: target, Template: tpl}
	seen := map[string]bool{}
	for _, m := range tokenRE.FindAllStringSubmatch(tpl, -1) {
		name := strings.ToLower(m[1])
		if !seen[name] {
			seen[name] = true
			a.Sources = append(a.Sources, name)
		}
	}
	if len(a.Sources) == 0 {
		return nil, errors.New("tplengine: autoFill template has no %var% tokens")
	}
	return a, nil
}

// Emit returns the JS fragment wiring the compiled macro (U4 autofill.js
// runtime consumes this shape).
func (a *AutoFill) Emit() string {
	sources := make([]string, 0, len(a.Sources))
	for _, s := range a.Sources {
		sources = append(sources, fmt.Sprintf("%q", s))
	}
	return fmt.Sprintf(
		"LDAPAutofill.bind({sources:[%s], target:%q, template:%q});",
		strings.Join(sources, ","), a.Target, a.Template)
}
