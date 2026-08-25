package ldif

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func collect(t *testing.T, src string, opts Options) ([]*Entry, []*EntryError, error) {
	t.Helper()
	it := NewIterator(strings.NewReader(src), opts)
	var entries []*Entry
	var errs []*EntryError
	for {
		e, perr, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if perr != nil {
			errs = append(errs, perr)
			continue
		}
		entries = append(entries, e)
	}
	return entries, errs, nil
}

const sampleLDIF = `version: 1
# a comment
dn: cn=alice,ou=People,dc=example,dc=com
objectClass: top
objectClass: person
cn: Alice
sn: Smith
description: line one
 line two folded

dn: cn=bob,ou=People,dc=example,dc=com
objectClass: person
cn: Bob
sn: Jones
userPassword:: e1NTSEF9c2VjcmV0
`

func TestParseHappyPath(t *testing.T) {
	entries, errs, err := collect(t, sampleLDIF, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("errors: %+v", errs)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d", len(entries))
	}
	e := entries[0]
	if e.DN != "cn=alice,ou=People,dc=example,dc=com" {
		t.Errorf("dn = %q", e.DN)
	}
	if len(e.Attrs) != 4 {
		t.Fatalf("attrs = %+v", e.Attrs)
	}
	if got := attr(e, "description"); got != "line one\nline two folded" {
		t.Errorf("folded value = %q", got)
	}
	bob := entries[1]
	if got := attr(bob, "userPassword"); got != "{SSHA}secret" {
		t.Errorf("base64 value = %q", got)
	}
}

func TestParseContinuesAfterBadEntry(t *testing.T) {
	src := `dn: cn=ok,dc=x
cn: Ok

dn: cn=bad,dc=x
this line has no colon

dn: cn=also-ok,dc=x
cn: Also Ok
`
	entries, errs, err := collect(t, src, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 1 || errs[0].Line != 4 {
		t.Fatalf("errs = %+v", errs)
	}
	if len(entries) != 2 || entries[1].DN != "cn=also-ok,dc=x" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestParseMissingDN(t *testing.T) {
	_, errs, err := collect(t, "cn: no dn\n", DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Err.Error(), "missing dn") {
		t.Fatalf("errs = %+v", errs)
	}
}

func TestParseRejectsURLReference(t *testing.T) {
	src := "dn: cn=x,dc=y\njpegPhoto:< file:///etc/passwd\n"
	_, errs, err := collect(t, src, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Err.Error(), "URL value") {
		t.Fatalf("errs = %+v", errs)
	}
}

func TestParseRejectsInvalidUTF8(t *testing.T) {
	src := "dn: cn=x,dc=y\ncn: \xff\xfe\n"
	_, errs, err := collect(t, src, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %+v", errs)
	}
}

func TestParseAttributeCap(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxAttrsPerEntry = 2
	src := "dn: cn=x,dc=y\ncn: a\nsn: b\nuid: c\n"
	_, errs, err := collect(t, src, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Err.Error(), "attribute count exceeds") {
		t.Fatalf("errs = %+v", errs)
	}
}

func TestParseEntryCap(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxEntries = 2
	src := "dn: cn=1,dc=x\ncn: 1\n\ndn: cn=2,dc=x\ncn: 2\n\ndn: cn=3,dc=x\ncn: 3\n"
	_, _, err := collect(t, src, opts)
	if err == nil || !strings.Contains(err.Error(), "entry count exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseBinaryMultiValued(t *testing.T) {
	src := "dn: cn=x,dc=y\nuserCertificate;binary:: dGVzdA==\nuserCertificate;binary:: bW9yZQ==\n"
	entries, errs, err := collect(t, src, DefaultOptions())
	if err != nil || len(errs) != 0 {
		t.Fatalf("err=%v errs=%+v", err, errs)
	}
	vals := multiAttr(entries[0], "userCertificate;binary")
	if len(vals) != 2 || vals[0] != "test" || vals[1] != "more" {
		t.Errorf("binary multi = %v", vals)
	}
}

func attr(e *Entry, name string) string {
	for _, a := range e.Attrs {
		if strings.EqualFold(a.Name, name) {
			if len(a.Values) > 0 {
				return a.Values[0]
			}
		}
	}
	return ""
}

func multiAttr(e *Entry, name string) []string {
	for _, a := range e.Attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}
