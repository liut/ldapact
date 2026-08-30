package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

type fakeSearcher struct {
	res     *ldapx.PageResult
	err     error
	gotOpts ldapx.SearchOptions
}

func (f *fakeSearcher) Page(_ context.Context, opts ldapx.SearchOptions, _ int) (*ldapx.PageResult, error) {
	f.gotOpts = opts
	return f.res, f.err
}
func (f *fakeSearcher) BaseDN() string { return "dc=example,dc=com" }

func searchHandler(t *testing.T, s Searcher) *Handler {
	t.Helper()
	renderer := web.New(web.MustParse(nil))
	return New(s, renderer)
}

func TestSearchResults(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{res: &ldapx.PageResult{
		Entries: []*ldap.Entry{
			{DN: "uid=alice,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
				{Name: "objectClass", Values: []string{"inetOrgPerson", "posixAccount"}},
				{Name: "modifyTimestamp", Values: []string{"20260825000000Z"}},
			}},
			{DN: "uid=bob,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
				{Name: "objectClass", Values: []string{"inetOrgPerson"}},
			}},
		},
		HasMore: false, Page: 1,
	}})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=alice)&scope=subtree", nil)
	h.Search(rr, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	for _, want := range []string{"uid=alice,ou=People,dc=example,dc=com", "inetOrgPerson, posixAccount", "uid=bob"} {
		if !strings.Contains(body, want) {
			t.Errorf("results missing %q", want)
		}
	}
	// Sorted by DN: alice before bob.
	if strings.Index(body, "uid=alice") > strings.Index(body, "uid=bob") {
		t.Error("results not sorted by DN")
	}
}

func TestSearchInvalidFilter(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=alice", nil)
	h.Search(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "filter syntax error at position") || !strings.Contains(body, `aria-invalid="true"`) {
		t.Errorf("invalid filter feedback: %s", body)
	}
}

func TestSearchWrapsBareFilter(t *testing.T) {
	// phpLDAPadmin parity: "uid=alice" / "objectClass=*" are accepted and
	// wrapped into complete LDAP filters before the search is issued.
	for _, tc := range []struct {
		query string
		want  string
	}{
		{"uid=alice", "(uid=alice)"},
		{"objectClass=*", "(objectClass=*)"},
		{"(&(sn=Smith)(givenName=David))", "(&(sn=Smith)(givenName=David))"},
		{"(uid=alice)", "(uid=alice)"},
	} {
		fake := &fakeSearcher{res: &ldapx.PageResult{}}
		h := searchHandler(t, fake)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/search?q="+url.QueryEscape(tc.query)+"&scope=subtree", nil)
		h.Search(rr, req)
		if fake.gotOpts.Filter != tc.want {
			t.Errorf("query %q: filter sent = %q, want %q", tc.query, fake.gotOpts.Filter, tc.want)
		}
		if rr.Code != http.StatusOK {
			t.Errorf("query %q: code = %d, body %.200s", tc.query, rr.Code, rr.Body.String())
		}
	}
}

func TestSearchEmptyQuery(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search", nil)
	h.Search(rr, req)
	if !strings.Contains(rr.Body.String(), "Enter a search filter") {
		t.Errorf("empty query feedback: %s", rr.Body.String())
	}
}

func TestSearchNoResults(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=nobody)", nil)
	h.Search(rr, req)
	if !strings.Contains(rr.Body.String(), "0 results") {
		t.Errorf("zero results message: %s", rr.Body.String())
	}
}

func TestSearchPagination(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{res: &ldapx.PageResult{
		Entries: []*ldap.Entry{{DN: "cn=a,dc=x", Attributes: []*ldap.EntryAttribute{{Name: "objectClass", Values: []string{"top"}}}}},
		HasMore: true, Page: 1,
	}})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(objectClass=*)&page=1", nil)
	h.Search(rr, req)
	if !strings.Contains(rr.Body.String(), "Next page") {
		t.Errorf("pagination missing: %s", rr.Body.String())
	}
}

func TestFilterErrorPositions(t *testing.T) {
	if got := filterError("(uid=x", nil); !strings.Contains(got, "position 6") {
		t.Errorf("unclosed: %q", got)
	}
	if got := filterError("uid=x)", nil); !strings.Contains(got, "position 5") {
		t.Errorf("extra close: %q", got)
	}
}

func TestSearchGlobalUsesRootBase(t *testing.T) {
	fake := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=alice)&scope=global", nil)
	h.Search(rr, req)
	if fake.gotOpts.BaseDN != "" || !fake.gotOpts.AllowEmptyBase {
		t.Errorf("global scope opts = %+v", fake.gotOpts)
	}
}

func TestSearchPageSize(t *testing.T) {
	fake := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&page_size=25", nil)
	h.Search(rr, req)
	if fake.gotOpts.PageSize != 25 {
		t.Errorf("page_size = %d", fake.gotOpts.PageSize)
	}
}

func TestSearchScopes(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  int
	}{
		{"base", ldap.ScopeBaseObject},
		{"one", ldap.ScopeSingleLevel},
		{"subtree", ldap.ScopeWholeSubtree},
		{"global", ldap.ScopeWholeSubtree},
	} {
		fake := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
		h := searchHandler(t, fake)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/search?q=(objectClass=*)&scope="+tc.scope, nil)
		h.Search(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: code = %d", tc.scope, rr.Code)
		}
		if fake.gotOpts.Scope != tc.want {
			t.Errorf("%s: scope = %d, want %d", tc.scope, fake.gotOpts.Scope, tc.want)
		}
		if tc.scope == "global" && fake.gotOpts.BaseDN != "" {
			t.Errorf("global base = %q, want empty", fake.gotOpts.BaseDN)
		}
	}
}

func TestSearchUnknownScope(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&scope=two", nil)
	h.Search(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rr.Code)
	}
}

func TestSearchSortParams(t *testing.T) {
	fake := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&sort=modified&dir=desc", nil)
	h.Search(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if fake.gotOpts.Sort == nil || fake.gotOpts.Sort.Attribute != "modifyTimestamp" || !fake.gotOpts.Sort.Reverse {
		t.Errorf("sort opts = %+v", fake.gotOpts.Sort)
	}
}

func TestSearchSortDefaults(t *testing.T) {
	fake := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)", nil)
	h.Search(rr, req)
	if fake.gotOpts.Sort != nil {
		t.Errorf("default dn sort must not attach a server control: %+v", fake.gotOpts.Sort)
	}
	// dir absent defaults asc: objectclass sort requests the ascending key.
	fake2 := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
	h2 := searchHandler(t, fake2)
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&sort=objectclass", nil)
	h2.Search(rr2, req2)
	if fake2.gotOpts.Sort == nil || fake2.gotOpts.Sort.Reverse {
		t.Errorf("objectclass default dir = %+v", fake2.gotOpts.Sort)
	}
}

func TestSearchUnknownSort(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&sort=telephone", nil)
	h.Search(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rr.Code)
	}
}

func TestSearchLimitsAndAttrs(t *testing.T) {
	fake := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&size_limit=20&time_limit=5&attrs=cn,mail", nil)
	h.Search(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, rr.Body.String())
	}
	if fake.gotOpts.SizeLimit != 20 || fake.gotOpts.TimeLimit != 5 {
		t.Errorf("limits = %+v", fake.gotOpts)
	}
	if !containsString(fake.gotOpts.Attrs, "cn") || !containsString(fake.gotOpts.Attrs, "mail") {
		t.Errorf("attrs = %v", fake.gotOpts.Attrs)
	}
	if strings.Contains(rr.Body.String(), "objectClass") && strings.Contains(rr.Body.String(), "Last modified") {
		t.Error("custom attrs mode must not render default columns")
	}
}

func TestSearchInvalidLimit(t *testing.T) {
	h := searchHandler(t, &fakeSearcher{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&size_limit=-1", nil)
	h.Search(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rr.Code)
	}
}

func TestSearchPageSizeCap(t *testing.T) {
	fake := &fakeSearcher{res: &ldapx.PageResult{Entries: []*ldap.Entry{}, HasMore: false, Page: 1}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=x)&page_size=501", nil)
	h.Search(rr, req)
	if fake.gotOpts.PageSize != DefaultPageSize {
		t.Errorf("page_size = %d, want cap at %d", fake.gotOpts.PageSize, DefaultPageSize)
	}
}

func TestSearchClientSortFallback(t *testing.T) {
	// The directory rejected server-side sorting; the handler must still
	// order the page client-side (SortFallback contract).
	fake := &fakeSearcher{res: &ldapx.PageResult{
		Entries: []*ldap.Entry{
			{DN: "uid=b,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
				{Name: "modifyTimestamp", Values: []string{"20260825010000Z"}},
			}},
			{DN: "uid=a,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
				{Name: "modifyTimestamp", Values: []string{"20260825020000Z"}},
			}},
		},
		SortFallback: true, HasMore: false, Page: 1,
	}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=*)&sort=modified&dir=desc", nil)
	h.Search(rr, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d: %s", rr.Code, body)
	}
	if strings.Index(body, "uid=b") < strings.Index(body, "uid=a") {
		t.Error("modified desc: newest first expected on the page")
	}
	if !strings.Contains(body, "does not support server-side sorting") {
		t.Error("sort fallback note missing from the results page")
	}
}

func TestSearchCustomAttrsColumns(t *testing.T) {
	fake := &fakeSearcher{res: &ldapx.PageResult{
		Entries: []*ldap.Entry{{
			DN: "uid=alice,ou=People,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"alice"}},
				{Name: "mail", Values: []string{"alice@example.com"}},
			},
		}},
		HasMore: false, Page: 1,
	}}
	h := searchHandler(t, fake)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=(uid=alice)&attrs=cn,mail", nil)
	h.Search(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"alice@example.com", ">cn<", ">mail<"} {
		if !strings.Contains(body, want) {
			t.Errorf("custom attrs page missing %q: %.400s", want, body)
		}
	}
}

func TestSortPageDesc(t *testing.T) {
	entries := []*ldap.Entry{
		{DN: "uid=b,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
			{Name: "modifyTimestamp", Values: []string{"20260825010000Z"}},
		}},
		{DN: "uid=a,ou=People,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
			{Name: "modifyTimestamp", Values: []string{"20260825020000Z"}},
		}},
	}
	sortPage(entries, "modified", "desc")
	if !strings.HasPrefix(entries[0].DN, "uid=a,") {
		t.Fatalf("desc order = %q, %q", entries[0].DN, entries[1].DN)
	}
}
