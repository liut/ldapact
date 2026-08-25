package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

type fakeSearcher struct {
	res *ldapx.PageResult
	err error
}

func (f *fakeSearcher) Page(_ context.Context, _ ldapx.SearchOptions, _ int) (*ldapx.PageResult, error) {
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
