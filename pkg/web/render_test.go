package web

import (
	"bytes"
	"strings"
	"testing"
)

func renderer(t *testing.T) *Renderer {
	t.Helper()
	return New(MustParse(nil))
}

type treeRowData struct {
	Level, SetSize, PosInSet int
	HasChildren              bool
	DN, Label                string
}

func TestRenderTreeRowFragment(t *testing.T) {
	var buf bytes.Buffer
	err := renderer(t).Fragment(&buf, "tree-row.html", treeRowData{
		Level: 1, SetSize: 3, PosInSet: 2, HasChildren: true, DN: "ou=People,dc=example,dc=com", Label: "People",
	})
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`<li role="treeitem"`,
		`aria-level="1"`,
		`aria-setsize="3"`,
		`aria-posinset="2"`,
		`aria-expanded="false"`,
		`data-dn="ou=People,dc=example,dc=com"`,
		`>People<`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fragment missing %q:\n%s", want, out)
		}
	}
}

func TestRenderFullPage(t *testing.T) {
	var buf bytes.Buffer
	err := renderer(t).Page(&buf, "ldapact", "home-content", nil)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`class="skip-link" href="#main-content"`,
		`role="main"`,
		`role="contentinfo"`,
		`role="banner"`,
		`/static/htmx.min.js`,
		`/static/js/tree-keys.js`,
		`/static/js/autofill.js`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestRenderAuthenticatedPageShowsActorAndLogout(t *testing.T) {
	var buf bytes.Buffer
	err := renderer(t).PageAuth(&buf, "ldapact", "home-content", nil, "cn=admin,dc=example,dc=com")
	if err != nil {
		t.Fatalf("PageAuth: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`Logged in as <code>cn=admin,dc=example,dc=com</code>`,
		`action="/logout"`,
		`>Log out</button>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("authenticated page missing %q:\n%s", want, out)
		}
	}

	// The plain Page (login form) must not show the session identity.
	var plain bytes.Buffer
	if err := renderer(t).Page(&plain, "Login — ldapact", "login-content", nil); err != nil {
		t.Fatalf("Page: %v", err)
	}
	for _, banned := range []string{"Logged in as", `action="/logout"`} {
		if strings.Contains(plain.String(), banned) {
			t.Errorf("public page must not render %q", banned)
		}
	}
}

func TestRenderMissingTemplate(t *testing.T) {
	var buf bytes.Buffer
	err := renderer(t).Fragment(&buf, "nope.html", nil)
	if err == nil || !strings.Contains(err.Error(), `template "nope.html" not found`) {
		t.Fatalf("want not-found error, got %v", err)
	}
}

func TestRenderErrorBox(t *testing.T) {
	var buf bytes.Buffer
	err := renderer(t).Fragment(&buf, "error-box.html", "Something failed")
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	if !strings.Contains(buf.String(), `role="alert"`) || !strings.Contains(buf.String(), "Something failed") {
		t.Errorf("error box: %s", buf.String())
	}
}

func TestDict(t *testing.T) {
	m, err := dict("a", 1, "b", "two")
	if err != nil || m["a"] != 1 || m["b"] != "two" {
		t.Errorf("dict = %v, %v", m, err)
	}
	if _, err := dict("a"); err == nil {
		t.Error("want error for odd args")
	}
	if _, err := dict(1, 2); err == nil {
		t.Error("want error for non-string key")
	}
}
