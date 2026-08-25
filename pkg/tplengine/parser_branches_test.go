package tplengine

import (
	"strings"
	"testing"
)

func parseString(t *testing.T, name, src string) (*Template, error) {
	t.Helper()
	return Parse(strings.NewReader(src), name)
}

func TestParseMissingRDN(t *testing.T) {
	src := `<template><title>x</title><objectClasses><objectClass id="x"/></objectClasses><attributes/></template>`
	if _, err := parseString(t, "x.xml", src); err == nil || !strings.Contains(err.Error(), "rdn") {
		t.Fatalf("want missing rdn error, got %v", err)
	}
}

func TestParseObjectClassWithoutID(t *testing.T) {
	src := `<template><title>x</title><rdn>cn</rdn><objectClasses><objectClass/></objectClasses><attributes/></template>`
	if _, err := parseString(t, "x.xml", src); err == nil {
		t.Fatal("want objectClass id error")
	}
}

func TestParseAttributeWithoutID(t *testing.T) {
	src := `<template><title>x</title><rdn>cn</rdn><objectClasses><objectClass id="x"/></objectClasses>
<attributes><attribute><display>no id</display></attribute></attributes></template>`
	if _, err := parseString(t, "x.xml", src); err == nil {
		t.Fatal("want attribute id error")
	}
}

func TestParseAttributeKinds(t *testing.T) {
	src := `<template><title>x</title><rdn>cn</rdn><objectClasses><objectClass id="x"/></objectClasses>
<attributes>
<attribute id="a"><display>A</display><type>select</type><value id="1">One</value><value id="2">Two</value></attribute>
<attribute id="b"><display>B</display><type>textarea</type><rows>3</rows></attribute>
<attribute id="c"><display>C</display><type>password</type></attribute>
<attribute id="d"><display>D</display><verify>1</verify></attribute>
<attribute id="e"><display>E</display><hidden>1</hidden><readonly>1</readonly><spacer>1</spacer></attribute>
<attribute id="f"><display>F</display><helper><id>enc</id><display>Enc</display><default>SSHA</default></helper><presubmit>=php.HashPassword(SSHA;x)</presubmit></attribute>
</attributes></template>`
	tmpl, err := parseString(t, "kinds.xml", src)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := tmpl.Attribute("a")
	if a.Kind != KindSelect || len(a.Values) != 2 || a.Values[0].ID != "1" || a.Values[0].Display != "One" {
		t.Errorf("select attr = %+v", a)
	}
	b, _ := tmpl.Attribute("b")
	if b.Kind != KindTextarea || b.Rows != 3 {
		t.Errorf("textarea attr = %+v", b)
	}
	c, _ := tmpl.Attribute("c")
	if c.Kind != KindPassword {
		t.Errorf("password attr = %+v", c)
	}
	d, _ := tmpl.Attribute("d")
	if d.Kind != KindPassword || !d.Verify {
		t.Errorf("verify attr = %+v", d)
	}
	e, _ := tmpl.Attribute("e")
	if !e.Hidden || !e.Readonly || !e.Spacer {
		t.Errorf("flags attr = %+v", e)
	}
	f, _ := tmpl.Attribute("f")
	if f.Helper == nil || f.Helper.ID != "enc" || f.Helper.Default != "SSHA" || len(f.PostHooks) != 1 {
		t.Errorf("helper attr = %+v", f)
	}
}

func TestParseHelperMacroError(t *testing.T) {
	src := `<template><title>x</title><rdn>cn</rdn><objectClasses><objectClass id="x"/></objectClasses>
<attributes><attribute id="a"><display>A</display><helper><id>h</id><value>=php.Nope()</value></helper></attribute></attributes></template>`
	if _, err := parseString(t, "x.xml", src); err == nil {
		t.Fatal("want helper macro error")
	}
}

func TestParseValueMacroError(t *testing.T) {
	src := `<template><title>x</title><rdn>cn</rdn><objectClasses><objectClass id="x"/></objectClasses>
<attributes><attribute id="a"><display>A</display><value>=php.Nope()</value></attribute></attributes></template>`
	if _, err := parseString(t, "x.xml", src); err == nil {
		t.Fatal("want value macro error")
	}
}

func TestParseMultiplePages(t *testing.T) {
	src := `<template><title>x</title><rdn>cn</rdn><objectClasses><objectClass id="x"/></objectClasses>
<attributes>
<attribute id="a"><display>A</display><page>1</page><order>2</order></attribute>
<attribute id="b"><display>B</display><page>2</page><order>1</order></attribute>
<attribute id="c"><display>C</display><page>1</page><order>1</order></attribute>
</attributes></template>`
	tmpl, err := parseString(t, "pages.xml", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.Pages) != 2 {
		t.Errorf("pages = %v", tmpl.Pages)
	}
	// Sort by page then order: c(1,1), a(1,2), b(2,1).
	if tmpl.Attributes[0].ID != "c" || tmpl.Attributes[1].ID != "a" || tmpl.Attributes[2].ID != "b" {
		t.Errorf("order = %v,%v,%v", tmpl.Attributes[0].ID, tmpl.Attributes[1].ID, tmpl.Attributes[2].ID)
	}
}
