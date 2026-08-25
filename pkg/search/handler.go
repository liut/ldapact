// Package search implements F8: scoped, filtered, paginated search.
package search

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

// DefaultPageSize is the F8 page size (plan: 50).
const DefaultPageSize = 50

// Searcher is the LDAP surface F8 needs; *ldapx.Client implements it.
type Searcher interface {
	Page(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error)
	BaseDN() string
}

// Row is one result-table row.
type Row struct {
	DN            string
	ObjectClasses string
	Modified      string
}

// Data drives the F8 page.
type Data struct {
	Query   string
	Scope   string
	Base    string
	Page    int
	HasMore bool
	Rows    []Row
	Total   int
	Error   string
}

// Handler serves GET /api/search.
type Handler struct {
	client   Searcher
	renderer *web.Renderer
	pageSize int
}

// New builds the F8 handler.
func New(client Searcher, renderer *web.Renderer) *Handler {
	return &Handler{client: client, renderer: renderer, pageSize: DefaultPageSize}
}

// Search handles GET /api/search?q=&scope=subtree|global&base=&page=N.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	scope := strings.ToLower(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "subtree"
	}
	base := r.URL.Query().Get("base")
	if base == "" {
		base = h.client.BaseDN()
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	data := Data{Query: q, Scope: scope, Base: base, Page: page}
	if q == "" {
		data.Error = "Enter a search filter."
		h.renderPage(w, data)
		return
	}
	if _, err := ldap.CompileFilter(q); err != nil {
		data.Error = filterError(q, err)
		h.renderPage(w, data)
		return
	}
	scopeInt := ldap.ScopeWholeSubtree
	if scope == "global" {
		base = ""
	}
	res, err := h.client.Page(r.Context(), ldapx.SearchOptions{
		BaseDN:   base,
		Scope:    scopeInt,
		Filter:   q,
		Attrs:    []string{"objectClass", "modifyTimestamp"},
		PageSize: h.pageSize,
	}, page)
	if err != nil {
		data.Error = "Search failed: " + err.Error()
		h.renderPage(w, data)
		return
	}
	sort.SliceStable(res.Entries, func(i, j int) bool { return res.Entries[i].DN < res.Entries[j].DN })
	data.HasMore = res.HasMore
	for _, e := range res.Entries {
		data.Rows = append(data.Rows, Row{
			DN:            e.DN,
			ObjectClasses: strings.Join(e.GetAttributeValues("objectClass"), ", "),
			Modified:      e.GetAttributeValue("modifyTimestamp"),
		})
	}
	data.Total = len(data.Rows)
	h.renderPage(w, data)
}

func (h *Handler) renderPage(w http.ResponseWriter, data Data) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.renderer.Page(w, "Search — ldapact", "search-content", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// filterError turns a CompileFilter failure into the R4-style message with a
// position (first unbalanced parenthesis, or a generic message).
func filterError(f string, _ error) string {
	depth := 0
	for i, r := range f {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "filter syntax error at position " + strconv.Itoa(i) + " (unbalanced ')'"
			}
		}
	}
	if depth > 0 {
		return "filter syntax error at position " + strconv.Itoa(len(f)) + " (unclosed '('"
	}
	return "filter syntax error — check the filter syntax."
}
