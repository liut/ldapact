package tree

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

type fakeLister struct {
	pageFn func(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error)
	filter string
	baseDN string
	schema *ldapx.Schema
}

func (f *fakeLister) Page(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error) {
	return f.pageFn(ctx, opts, page)
}
func (f *fakeLister) TreeFilter() string    { return f.filter }
func (f *fakeLister) BaseDN() string        { return f.baseDN }
func (f *fakeLister) Schema() *ldapx.Schema { return f.schema }

func testTree(t *testing.T, l Lister) *Tree {
	t.Helper()
	renderer := web.New(web.MustParse(nil))
	logger := testLogger(t)
	return NewTree(l, renderer, logger)
}

func twoEntries() []*ldap.Entry {
	return []*ldap.Entry{
		{DN: "cn=alice,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
			{Name: "hassubordinates", Values: []string{"false"}},
		}},
		{DN: "cn=bob,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
			{Name: "hassubordinates", Values: []string{"true"}},
		}},
	}
}

func childrenRequest(dn string, query string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/tree/"+dn+"/children"+query, nil)
	r.SetPathValue("dn", dn)
	return r
}

func TestChildrenRendersNodes(t *testing.T) {
	l := &fakeLister{
		filter: "(objectClass=*)",
		pageFn: func(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error) {
			if opts.Scope != ldap.ScopeSingleLevel {
				t.Errorf("scope = %d", opts.Scope)
			}
			if len(opts.Attrs) != 2 || opts.Attrs[1] != "hassubordinates" {
				t.Errorf("attrs = %v", opts.Attrs)
			}
			return &ldapx.PageResult{Entries: twoEntries(), HasMore: false, Page: 1}, nil
		},
	}
	tr := testTree(t, l)
	rr := httptest.NewRecorder()
	tr.Children(rr, childrenRequest("ou=People,dc=example,dc=com", "?page=1&level=2&id=children-x"))

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`data-dn="cn=alice,ou=People,dc=example,dc=com"`,
		`aria-level="2"`,
		`aria-setsize="2"`,
		`aria-posinset="1"`,
		">alice<",
		">bob<",
		`aria-expanded="false"`,
		`id="children-n1"`,
		`/api/tree/cn%3Dbob%2Cou%3DPeople%2Cdc%3Dexample%2Cdc%3Dcom/children`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fragment missing %q", want)
		}
	}
	if strings.Count(body, `aria-expanded="false"`) != 1 {
		t.Errorf("leaf must not be expandable: %s", body)
	}
	if got := rr.Header().Get("HX-Trigger"); got != "subtree-loaded" {
		t.Errorf("HX-Trigger = %q", got)
	}
}

func TestChildrenEmpty(t *testing.T) {
	l := &fakeLister{
		pageFn: func(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error) {
			return &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}, nil
		},
	}
	rr := httptest.NewRecorder()
	testTree(t, l).Children(rr, childrenRequest("cn=alice,dc=example,dc=com", ""))
	body := rr.Body.String()
	if !strings.Contains(body, "(no children)") || !strings.Contains(body, `aria-disabled="true"`) {
		t.Errorf("empty branch: %s", body)
	}
}

func TestChildrenLoadMore(t *testing.T) {
	l := &fakeLister{
		pageFn: func(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error) {
			return &ldapx.PageResult{Entries: twoEntries(), HasMore: true, Page: 1}, nil
		},
	}
	rr := httptest.NewRecorder()
	testTree(t, l).Children(rr, childrenRequest("ou=People,dc=example,dc=com", "?page=1&level=3&id=children-x"))
	body := rr.Body.String()
	for _, want := range []string{"Load more", "page=2", "level=3", `hx-target="#children-x"`} {
		if !strings.Contains(body, want) {
			t.Errorf("paging fragment missing %q: %s", want, body)
		}
	}
}

func TestChildrenSizeLimitError(t *testing.T) {
	l := &fakeLister{
		pageFn: func(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error) {
			return nil, &ldapx.LDAPError{Op: "search", Code: ldap.LDAPResultSizeLimitExceeded, DN: "dc=example,dc=com", Err: errors.New("size limit")}
		},
	}
	rr := httptest.NewRecorder()
	testTree(t, l).Children(rr, childrenRequest("dc=example,dc=com", ""))
	body := rr.Body.String()
	if !strings.Contains(body, "narrow the filter") || !strings.Contains(body, `role="alert"`) {
		t.Errorf("size-limit error state: %s", body)
	}
}

func TestChildrenNetworkError(t *testing.T) {
	l := &fakeLister{
		pageFn: func(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error) {
			return nil, errors.New("connection reset")
		},
	}
	rr := httptest.NewRecorder()
	testTree(t, l).Children(rr, childrenRequest("dc=example,dc=com", ""))
	body := rr.Body.String()
	if !strings.Contains(body, "unreachable") || !strings.Contains(body, "Retry") {
		t.Errorf("network error state: %s", body)
	}
}

func TestChildrenMissingDN(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/tree//children", nil)
	testTree(t, &fakeLister{}).Children(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestRDNLabel(t *testing.T) {
	cases := map[string]string{
		"cn=alice,ou=People,dc=example,dc=com": "alice",
		"dc=example,dc=com":                    "example",
		"uid=jdoe,ou=Users,dc=x":               "jdoe",
	}
	for dn, want := range cases {
		if got := rdnLabel(dn); got != want {
			t.Errorf("rdnLabel(%q) = %q, want %q", dn, got, want)
		}
	}
	if rdnLabel("not a dn") == "" {
		t.Error("fallback should return the input")
	}
}

func TestHomePage(t *testing.T) {
	l := &fakeLister{baseDN: "dc=example,dc=com"}
	rr := httptest.NewRecorder()
	testTree(t, l).HomePage(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rr.Body.String()
	for _, want := range []string{`role="tree"`, "dc=example,dc=com", "children-root", `role="status"`} {
		if !strings.Contains(body, want) {
			t.Errorf("tree page missing %q", want)
		}
	}
}
