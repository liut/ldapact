package tplengine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func parseFixture(t *testing.T, name string) *Template {
	t.Helper()
	f, err := os.Open(filepath.Join("fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tmpl, err := Parse(f, name)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return tmpl
}

func TestParsePosixAccount(t *testing.T) {
	tmpl := parseFixture(t, "posixAccount.xml")
	if len(tmpl.ObjectClasses) != 2 || tmpl.ObjectClasses[0] != "inetOrgPerson" || tmpl.ObjectClasses[1] != "posixAccount" {
		t.Errorf("objectClasses = %v", tmpl.ObjectClasses)
	}
	if tmpl.RDN != "cn" || tmpl.Title != "Generic: User Account" {
		t.Errorf("rdn/title = %q/%q", tmpl.RDN, tmpl.Title)
	}
	if !tmpl.Visible || !tmpl.AskContainer {
		t.Error("visible/askcontainer flags")
	}
	if len(tmpl.Attributes) != 9 {
		t.Fatalf("attributes = %d, want 9", len(tmpl.Attributes))
	}
	// Form order: givenName(1), sn(2), cn(3), uid(4), userPassword(5),
	// uidNumber(6), gidNumber(7), homeDirectory(8), loginShell(9).
	order := []string{"givenName", "sn", "cn", "uid", "userPassword", "uidNumber", "gidNumber", "homeDirectory", "loginShell"}
	for i, want := range order {
		if got := tmpl.Attributes[i].ID; got != want {
			t.Errorf("attr[%d] = %q, want %q", i, got, want)
		}
	}

	userPassword, _ := tmpl.Attribute("userPassword")
	if userPassword.Kind != KindPassword || !userPassword.Verify {
		t.Errorf("userPassword kind/verify = %v/%v", userPassword.Kind, userPassword.Verify)
	}
	if len(userPassword.PostHooks) != 1 || !strings.Contains(userPassword.PostHooks[0], "PasswordEncrypt") {
		t.Errorf("post hooks = %v", userPassword.PostHooks)
	}
	if len(userPassword.OnChange) != 0 {
		t.Errorf("userPassword onchange = %v", userPassword.OnChange)
	}

	givenName, _ := tmpl.Attribute("givenName")
	if len(givenName.OnChange) != 2 || !strings.Contains(givenName.OnChange[0], "autoFill(cn;%givenName% %sn%)") {
		t.Errorf("givenName onchange = %v", givenName.OnChange)
	}

	loginShell, _ := tmpl.Attribute("loginShell")
	if loginShell.Kind != KindSelect || len(loginShell.Values) != 7 {
		t.Errorf("loginShell = %+v", loginShell)
	}

	uidNumber, _ := tmpl.Attribute("uidNumber")
	if !uidNumber.Readonly || len(uidNumber.Values) != 1 || !strings.HasPrefix(uidNumber.Values[0].ID, "=php.GetNextNumber") {
		t.Errorf("uidNumber = %+v", uidNumber)
	}

	gidNumber, _ := tmpl.Attribute("gidNumber")
	if len(gidNumber.Values) != 1 || !strings.HasPrefix(gidNumber.Values[0].ID, "=php.PickList") {
		t.Errorf("gidNumber = %+v", gidNumber)
	}
}

// The plan's most important quality gate: every fixture parses unmodified.
func TestRegressionAllFixtures(t *testing.T) {
	fixtures := []string{
		"posixAccount.xml", "inetOrgPerson.xml", "posixGroup.xml",
		"alias.xml", "customAccount.xml", "dNSDomain.xml",
		"organizationalRole.xml", "ou.xml", "simpleSecurityObject.xml",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("fixtures", name))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := Parse(f, name); err != nil {
				t.Fatalf("fixture %s failed to parse: %v", name, err)
			}
		})
	}
}

func TestUnknownMacroFailsAtParse(t *testing.T) {
	src := `
<template><title>x</title><rdn>cn</rdn>
<objectClasses><objectClass id="inetOrgPerson"/></objectClasses>
<attributes>
<attribute id="cn"><display>CN</display><value>=php.UnknownFunc(1;2)</value></attribute>
</attributes></template>`
	if _, err := Parse(strings.NewReader(src), "bad.xml"); err == nil || !strings.Contains(err.Error(), "unknown server macro") {
		t.Fatalf("want unknown-macro error, got %v", err)
	}
}

func TestMalformedAutoFillFails(t *testing.T) {
	src := `
<template><title>x</title><rdn>cn</rdn>
<objectClasses><objectClass id="inetOrgPerson"/></objectClasses>
<attributes>
<attribute id="givenName"><display>G</display><onchange>=autoFill(cn;no-tokens-here)</onchange></attribute>
</attributes></template>`
	if _, err := Parse(strings.NewReader(src), "bad.xml"); err == nil {
		t.Fatal("want autoFill parse error")
	}
}

func TestDuplicateAttributeFails(t *testing.T) {
	src := `
<template><title>x</title><rdn>cn</rdn>
<objectClasses><objectClass id="inetOrgPerson"/></objectClasses>
<attributes>
<attribute id="cn"><display>A</display></attribute>
<attribute id="CN"><display>B</display></attribute>
</attributes></template>`
	if _, err := Parse(strings.NewReader(src), "dup.xml"); err == nil {
		t.Fatal("want duplicate attribute error")
	}
}

func TestMissingTitleFails(t *testing.T) {
	src := `<template><rdn>cn</rdn><objectClasses><objectClass id="x"/></objectClasses><attributes/></template>`
	if _, err := Parse(strings.NewReader(src), "x.xml"); err == nil {
		t.Fatal("want missing title error")
	}
}

func TestParseAutoFill(t *testing.T) {
	a, err := ParseAutoFill("=autoFill(cn;%givenName|0-2/l% %sn%)")
	if err != nil {
		t.Fatal(err)
	}
	if a.Target != "cn" || a.Template != "%givenName|0-2/l% %sn%" {
		t.Errorf("autofill = %+v", a)
	}
	if len(a.Sources) != 2 || a.Sources[0] != "givenname" || a.Sources[1] != "sn" {
		t.Errorf("sources = %v", a.Sources)
	}
	if !strings.Contains(a.Emit(), `sources:["givenname","sn"]`) {
		t.Errorf("emit = %s", a.Emit())
	}
}

func TestEvaluateSimpleMacros(t *testing.T) {
	ctx := &MacroContext{ParentDN: "ou=People,dc=example,dc=com"}
	cases := []struct {
		raw  string
		want string
	}{
		{"=php.Join(;a;b;c)", "abc"},
		{"=php.Join(-;a;;c)", "a-c"},
		{"=php.Default(hello)", "hello"},
		{"=php.DN()", "ou=People,dc=example,dc=com"},
		{"=php.Escape(a*b)", `a\2ab`},
		{"=php.Encoded(hi)", "aGk="},
		{"=php.HasMultiples(a;b)", "1"},
		{"=php.HasMultiples(single)", "0"},
		{"=php.Binary(x)", "x"},
	}
	for _, tc := range cases {
		got, err := Evaluate(ctx, tc.raw)
		if err != nil {
			t.Errorf("Evaluate(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Evaluate(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	rp, err := Evaluate(ctx, "=php.RandomPassword(20)")
	if err != nil || len(rp.(string)) != 20 {
		t.Errorf("RandomPassword = %v, %v", rp, err)
	}
}

func TestSubstitutePattern(t *testing.T) {
	got := substitutePattern("%cn% (%uid%)", map[string]string{"cn": "Alice", "uid": "alice"})
	if got != "Alice (alice)" {
		t.Errorf("got %q", got)
	}
	if got := substitutePattern("50%", map[string]string{}); got != "50%" {
		t.Errorf("unclosed token: %q", got)
	}
	if got := substitutePattern("%%", map[string]string{}); got != "" {
		t.Errorf("empty key: %q", got)
	}
}

// fakeSearcher returns canned entries for macro tests.
type fakeSearcher struct {
	entries []*ldap.Entry
	err     error
}

func (f *fakeSearcher) Search(_ context.Context, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ldap.SearchResult{Entries: f.entries}, nil
}

func TestPickListBuildsValues(t *testing.T) {
	searcher := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "cn=staff,ou=Groups,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "gidNumber", Values: []string{"100"}}, {Name: "cn", Values: []string{"staff"}}}},
		{DN: "cn=dev,ou=Groups,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "gidNumber", Values: []string{"101"}}, {Name: "cn", Values: []string{"dev"}}}},
	}}
	ctx := &MacroContext{Client: searcher, BaseDN: "dc=x"}
	res, err := Evaluate(ctx, "=php.PickList(/;(&(objectClass=posixGroup));gidNumber;%cn%;;;;cn)")
	if err != nil {
		t.Fatal(err)
	}
	ev := res.(*Evaluated)
	if ev.NoMatches || len(ev.Values) != 2 {
		t.Fatalf("picklist = %+v", ev)
	}
	if ev.Values[0].ID != "101" || ev.Values[0].Display != "dev" {
		t.Errorf("values = %+v", ev.Values)
	}
}

func TestPickListZeroResults(t *testing.T) {
	ctx := &MacroContext{Client: &fakeSearcher{}, BaseDN: "dc=x"}
	res, err := Evaluate(ctx, "=php.PickList(/;(objectClass=posixGroup);gidNumber;%cn%)")
	if err != nil {
		t.Fatal(err)
	}
	ev := res.(*Evaluated)
	if !ev.NoMatches || ev.Notice != "未找到候选" {
		t.Errorf("zero-result picklist = %+v", ev)
	}
}

func TestGetNextNumberFillsGap(t *testing.T) {
	searcher := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "uid=1,ou=People,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"1001"}}}},
		{DN: "uid=2,ou=People,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"1002"}}}},
		{DN: "uid=3,ou=People,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"1004"}}}},
	}}
	ctx := &MacroContext{Client: searcher, BaseDN: "dc=x"}
	res, err := Evaluate(ctx, "=php.GetNextNumber(/;uidNumber)")
	if err != nil {
		t.Fatal(err)
	}
	ev := res.(*Evaluated)
	if ev.Text != "1003" || ev.MaxHit {
		t.Errorf("nextnumber = %+v", ev)
	}
}

func TestGetNextNumberMaxHit(t *testing.T) {
	searcher := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "uid=1,ou=People,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"5"}}}},
	}}
	ctx := &MacroContext{Client: searcher, BaseDN: "dc=x"}
	res, err := Evaluate(ctx, "=php.GetNextNumber(/;uidNumber;;;;;5)")
	if err != nil {
		t.Fatal(err)
	}
	ev := res.(*Evaluated)
	if !ev.MaxHit || ev.Text != "5" {
		t.Errorf("max-hit = %+v", ev)
	}
}

func TestEvaluateMacrosOnTemplate(t *testing.T) {
	tmpl := parseFixture(t, "posixAccount.xml")
	searcher := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "cn=staff,ou=Groups,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{{Name: "gidNumber", Values: []string{"100"}}, {Name: "cn", Values: []string{"staff"}}}},
	}}
	ctx := &MacroContext{Client: searcher, BaseDN: "dc=example,dc=com"}
	if err := tmpl.EvaluateMacros(ctx); err != nil {
		t.Fatal(err)
	}
	uidNumber, _ := tmpl.Attribute("uidNumber")
	if uidNumber.Evaluated == nil || uidNumber.Evaluated.Text == "" {
		t.Errorf("uidNumber evaluated = %+v", uidNumber.Evaluated)
	}
	gidNumber, _ := tmpl.Attribute("gidNumber")
	if gidNumber.Evaluated == nil || len(gidNumber.Evaluated.Values) != 1 {
		t.Errorf("gidNumber evaluated = %+v", gidNumber.Evaluated)
	}
}

func TestSearchErrorPropagates(t *testing.T) {
	ctx := &MacroContext{Client: &fakeSearcher{err: errors.New("down")}, BaseDN: "dc=x"}
	if _, err := Evaluate(ctx, "=php.PickList(/;f;gidNumber)"); err == nil {
		t.Fatal("want search error")
	}
}
