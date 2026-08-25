package tplengine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestEvaluatePasswordMacros(t *testing.T) {
	ctx := &MacroContext{}
	// PasswordEncrypt with explicit scheme.
	res, err := Evaluate(ctx, "=php.PasswordEncrypt(SSHA;secret)")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.(string), "{SSHA}") {
		t.Errorf("PasswordEncrypt = %q", res)
	}
	// PasswordEncrypt with empty scheme defaults to SSHA512.
	res, err = Evaluate(ctx, "=php.PasswordEncrypt(;secret)")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.(string), "{SSHA512}") {
		t.Errorf("default scheme = %q", res)
	}
	// Empty password yields empty.
	res, err = Evaluate(ctx, "=php.PasswordEncrypt(SSHA;)")
	if err != nil || res.(string) != "" {
		t.Errorf("empty password = %q, %v", res, err)
	}
	// PLAIN rejected without override.
	if _, err := Evaluate(ctx, "=php.PasswordEncrypt(PLAIN;x)"); err == nil {
		t.Error("PLAIN must be rejected without override")
	}
	// PLAIN allowed with override.
	ctx.PlainAllowed = true
	res, err = Evaluate(ctx, "=php.PasswordEncrypt(PLAIN;x)")
	if err != nil || res.(string) != "x" {
		t.Errorf("PLAIN override = %q, %v", res, err)
	}

	types, err := Evaluate(ctx, "=php.PasswordEncryptionTypes()")
	if err != nil {
		t.Fatal(err)
	}
	if len(types.([]Value)) == 0 {
		t.Error("empty scheme list")
	}
}

func TestEvaluateHashAndRandom(t *testing.T) {
	ctx := &MacroContext{}
	h, err := Evaluate(ctx, "=php.HashPassword(SSHA256;pw)")
	if err != nil || !strings.HasPrefix(h.(string), "{SSHA256}") {
		t.Errorf("HashPassword = %v, %v", h, err)
	}
	if _, err := Evaluate(ctx, "=php.HashPassword(BAD;pw)"); err == nil {
		t.Error("HashPassword with bad scheme should error")
	}
	rp, err := Evaluate(ctx, "=php.RandomPassword(8)")
	if err != nil || len(rp.(string)) != 8 {
		t.Errorf("RandomPassword = %v, %v", rp, err)
	}
	if _, err := Evaluate(ctx, "=php.RandomPassword(0)"); err != nil {
		t.Errorf("RandomPassword default: %v", err)
	}
}

func TestEvaluateEdgeCases(t *testing.T) {
	ctx := &MacroContext{ParentDN: "ou=x,dc=y"}
	cases := []struct {
		raw  string
		want string
	}{
		{"=php.Join(-)", ""},
		{"=php.Default()", ""},
		{"=php.DN()", "ou=x,dc=y"},
		{"=php.Encoded()", ""},
		{"=php.Escape()", ""},
		{"=php.Binary()", ""},
		{"=php.HasMultiples(single)", "0"},
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
	if _, err := Evaluate(ctx, "=php.NoSuchFunc()"); err == nil {
		t.Error("unknown function should error")
	}
}

func TestEvaluateMacrosHelperAndErrors(t *testing.T) {
	src := `
<template><title>x</title><rdn>cn</rdn>
<objectClasses><objectClass id="inetOrgPerson"/></objectClasses>
<attributes>
<attribute id="cn"><display>CN</display>
  <helper><display>Encryption</display><id>enc</id><value>=php.PasswordEncryptionTypes()</value></helper>
</attribute>
</attributes></template>`
	tmpl, err := Parse(strings.NewReader(src), "helper.xml")
	if err != nil {
		t.Fatal(err)
	}
	ctx := &MacroContext{BaseDN: "dc=x"}
	if err := tmpl.EvaluateMacros(ctx); err != nil {
		t.Fatal(err)
	}
	cn, _ := tmpl.Attribute("cn")
	if cn.Helper == nil || len(cn.Helper.Values) == 0 || cn.Helper.Values[0].ID != "SSHA512" {
		t.Errorf("helper values = %+v", cn.Helper)
	}

	// Macro evaluation failure propagates.
	src2 := `
<template><title>x</title><rdn>cn</rdn>
<objectClasses><objectClass id="x"/></objectClasses>
<attributes><attribute id="cn"><display>CN</display><value>=php.PickList(/;filter)</value></attribute></attributes></template>`
	tmpl2, _ := Parse(strings.NewReader(src2), "bad2.xml")
	if err := tmpl2.EvaluateMacros(&MacroContext{Client: &fakeSearcher{err: errors.New("boom")}, BaseDN: "dc=x"}); err == nil {
		t.Error("want macro evaluation error")
	}
}

func TestGetNextNumberErrors(t *testing.T) {
	if _, err := Evaluate(&MacroContext{}, "=php.GetNextNumber(/)"); err == nil {
		t.Error("want missing attr error")
	}
	multi := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "cn=a,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"1"}}}},
		{DN: "cn=b,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"2"}}}},
	}}
	ctx := &MacroContext{Client: multi, BaseDN: "dc=x"}
	if _, err := Evaluate(ctx, "=php.GetNextNumber(/;uidNumber;pool;(objectClass=uidPool))"); err == nil {
		t.Error("pool mode with multiple matches should error")
	}
	single := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "cn=pool,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"41"}}}},
	}}
	res, err := Evaluate(&MacroContext{Client: single, BaseDN: "dc=x"}, "=php.GetNextNumber(/;uidNumber;pool;(objectClass=uidPool))")
	if err != nil {
		t.Fatal(err)
	}
	if ev := res.(*Evaluated); ev.Text != "42" {
		t.Errorf("pool next = %+v", ev)
	}

	// Pool mode with zero matches starts at the configured minimum.
	empty := &fakeSearcher{}
	res, err = Evaluate(&MacroContext{Client: empty, BaseDN: "dc=x"}, "=php.GetNextNumber(/;uidNumber;pool;(objectClass=uidPool);;100)")
	if err != nil {
		t.Fatal(err)
	}
	if ev := res.(*Evaluated); ev.Text != "100" {
		t.Errorf("pool zero = %+v", ev)
	}

	// Explicit startmin is honored in search mode.
	gap := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "uid=1,ou=People,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"1001"}}}},
	}}
	res, err = Evaluate(&MacroContext{Client: gap, BaseDN: "dc=x"}, "=php.GetNextNumber(/;uidNumber;;; ;900;65535)")
	if err != nil {
		t.Fatal(err)
	}
	if ev := res.(*Evaluated); ev.Text != "900" || ev.MaxHit {
		t.Errorf("startmin = %+v", ev)
	}

	// Explicit base DN (not "/") resolves to itself.
	res, err = Evaluate(&MacroContext{Client: empty, BaseDN: "dc=x"}, "=php.GetNextNumber(ou=Numbers,dc=x;uidNumber)")
	if err != nil {
		t.Fatal(err)
	}
	if ev := res.(*Evaluated); ev.Text != "1" {
		t.Errorf("explicit base = %+v", ev)
	}
}

func TestGetNextNumberUsesAutoSearcher(t *testing.T) {
	admin := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "uid=1,ou=People,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"1001"}}}},
	}}
	auto := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "uid=a,ou=People,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "uidNumber", Values: []string{"5001"}}}},
	}}
	ctx := &MacroContext{Client: admin, AutoSearcher: auto, BaseDN: "dc=x"}
	res, err := Evaluate(ctx, "=php.GetNextNumber(/;uidNumber)")
	if err != nil {
		t.Fatal(err)
	}
	if ev := res.(*Evaluated); ev.Text != "5002" {
		t.Errorf("auto pool next = %+v, want 5002", ev)
	}
}

func TestPickListErrors(t *testing.T) {
	if _, err := Evaluate(&MacroContext{}, "=php.PickList(/)"); err == nil {
		t.Error("want missing args error")
	}
}

func TestPickListEmptyFilterAndDisplay(t *testing.T) {
	searcher := &fakeSearcher{entries: []*ldap.Entry{
		{DN: "cn=g1,ou=Groups,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "gidNumber", Values: []string{"10"}}}},
	}}
	ctx := &MacroContext{Client: searcher, BaseDN: "dc=x"}
	res, err := Evaluate(ctx, "=php.PickList(/;(objectClass=posixGroup);gidNumber)")
	if err != nil {
		t.Fatal(err)
	}
	ev := res.(*Evaluated)
	if len(ev.Values) != 1 || ev.Values[0].Display != "10" {
		t.Errorf("empty display falls back to value: %+v", ev)
	}
	// Empty filter defaults to (objectClass=*).
	res, err = Evaluate(ctx, "=php.PickList(/;;gidNumber)")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.(*Evaluated).Values) != 1 {
		t.Errorf("empty filter = %+v", res)
	}
	// MultiList behaves like PickList.
	res, err = Evaluate(ctx, "=php.MultiList(/;(objectClass=posixGroup);gidNumber)")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.(*Evaluated).Values) != 1 {
		t.Errorf("multilist = %+v", res)
	}
}

func TestMacroContextWithRequestCtx(t *testing.T) {
	ctx := context.Background()
	mc := &MacroContext{Ctx: ctx, Client: &fakeSearcher{}, BaseDN: "dc=x"}
	if _, err := Evaluate(mc, "=php.PickList(/;f;gidNumber)"); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluateMacrosMultiValueAndHelperNonList(t *testing.T) {
	src := `
<template><title>x</title><rdn>cn</rdn>
<objectClasses><objectClass id="x"/></objectClasses>
<attributes>
<attribute id="shell"><display>Shell</display><type>select</type><value id="/bin/sh">Shell</value><value id="/bin/false">False</value></attribute>
<attribute id="cn"><display>CN</display><helper><id>h</id><display>H</display><value>=php.Default(SSHA)</value></helper></attribute>
</attributes></template>`
	tmpl, err := Parse(strings.NewReader(src), "m.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := tmpl.EvaluateMacros(&MacroContext{BaseDN: "dc=x"}); err != nil {
		t.Fatal(err)
	}
	shell, _ := tmpl.Attribute("shell")
	if shell.Evaluated != nil || len(shell.Values) != 2 {
		t.Errorf("multi-value attribute must not be macro-evaluated: %+v", shell)
	}
	cn, _ := tmpl.Attribute("cn")
	if cn.Helper == nil || len(cn.Helper.Values) != 1 || cn.Helper.Values[0].ID != "SSHA" {
		t.Errorf("helper non-list macro = %+v", cn.Helper)
	}
}
