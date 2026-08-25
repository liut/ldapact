package ldif

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriterRoundTrip(t *testing.T) {
	e := &Entry{
		DN: "cn=alice,ou=People,dc=example,dc=com",
		Attrs: []Attribute{
			{Name: "objectClass", Values: []string{"top", "person"}},
			{Name: "cn", Values: []string{"Alice"}},
			{Name: "userCertificate;binary", Values: []string{"raw\x00bytes"}},
			{Name: "description", Values: []string{"a very long value that should be folded across multiple lines " + strings.Repeat("x", 120)}},
		},
	}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteEntry(e); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "dn: cn=alice,ou=People,dc=example,dc=com\n") {
		t.Errorf("dn line: %q", out)
	}
	if !strings.Contains(out, "userCertificate;binary:: cmF3AGJ5dGVz") {
		t.Errorf("binary base64 missing:\n%s", out)
	}
	if !strings.Contains(out, "\n ") {
		t.Errorf("no folded line:\n%s", out)
	}

	// Round-trip through the parser.
	entries, errs, err := collect(t, out, DefaultOptions())
	if err != nil || len(errs) != 0 {
		t.Fatalf("round trip: err=%v errs=%+v", err, errs)
	}
	got := entries[0]
	if got.DN != e.DN {
		t.Errorf("dn = %q", got.DN)
	}
	if string([]byte(attr(got, "userCertificate;binary"))) != "raw\x00bytes" {
		t.Errorf("binary round trip = %q", attr(got, "userCertificate;binary"))
	}
}

func TestWriterBase64ForLeadingSpace(t *testing.T) {
	var buf bytes.Buffer
	e := &Entry{DN: "cn=x,dc=y", Attrs: []Attribute{{Name: "description", Values: []string{" leading space"}}}}
	if err := NewWriter(&buf).WriteEntry(e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "description::") {
		t.Errorf("leading space must be base64: %q", buf.String())
	}
}

func TestWriterRejectsEmptyDN(t *testing.T) {
	var buf bytes.Buffer
	if err := NewWriter(&buf).WriteEntry(&Entry{}); err == nil {
		t.Fatal("want error for empty dn")
	}
}
