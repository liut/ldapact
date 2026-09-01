// Package search implements F8: scoped, filtered, paginated search.
package search

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/authn"
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
	AttrValues    []string // aligned with Data.AttrColumns
}

// Data drives the F8 page.
type Data struct {
	Query        string
	Scope        string
	Base         string
	Page         int
	HasMore      bool
	Rows         []Row
	Total        int
	Error        string
	Sort         string
	Dir          string
	SortFallback bool
	AttrColumns  []string
	Columns      []Column
	NextHref     string
}

// Column is one sortable table header.
type Column struct {
	Label  string
	Href   string
	Active bool
	Dir    string
}

// Handler serves GET /search.
type Handler struct {
	client   Searcher
	renderer *web.Renderer
	pageSize int
}

// New builds the F8 handler.
func New(client Searcher, renderer *web.Renderer) *Handler {
	return &Handler{client: client, renderer: renderer, pageSize: DefaultPageSize}
}

// sortAttrs maps the public sort keys to LDAP attribute names. DN has no
// SortKey attribute; it sorts client-side.
var sortAttrs = map[string]string{
	"dn":          "",
	"objectclass": "objectClass",
	"modified":    "modifyTimestamp",
}

// Search handles GET /search with scope=base|one|subtree|global,
// sort=dn|objectclass|modified, dir=asc|desc, size_limit, time_limit, and
// attrs (R4 completion).
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
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 500 {
		pageSize = DefaultPageSize
	}
	sortKey := strings.ToLower(r.URL.Query().Get("sort"))
	if sortKey == "" {
		sortKey = "dn"
	}
	dir := strings.ToLower(r.URL.Query().Get("dir"))
	if dir == "" {
		dir = "asc"
	}
	sizeLimit, err := nonNegativeIntParam(r, "size_limit")
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}
	timeLimit, err := nonNegativeIntParam(r, "time_limit")
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}
	attrs := parseAttrs(r.URL.Query().Get("attrs"))
	if _, ok := sortAttrs[sortKey]; !ok {
		http.Error(w, "Bad Request: unknown sort — use dn, objectclass, or modified", http.StatusBadRequest)
		return
	}
	if dir != "asc" && dir != "desc" {
		http.Error(w, "Bad Request: dir must be asc or desc", http.StatusBadRequest)
		return
	}
	data := Data{Query: q, Scope: scope, Base: base, Page: page, Sort: sortKey, Dir: dir}
	if q == "" {
		data.Error = "Enter a search filter."
		h.renderPage(w, r, data)
		return
	}
	// phpLDAPadmin parity: accept a bare attribute filter ("uid=alice",
	// "objectClass=*") and wrap it into a complete LDAP filter; complete
	// filters like "(uid=alice)" pass through unchanged.
	if !strings.HasPrefix(q, "(") {
		q = "(" + q + ")"
		data.Query = q
	}
	if _, err := ldap.CompileFilter(q); err != nil {
		data.Error = filterError(q, err)
		h.renderPage(w, r, data)
		return
	}
	scopeInt, ok := map[string]int{
		"base":    ldap.ScopeBaseObject,
		"one":     ldap.ScopeSingleLevel,
		"subtree": ldap.ScopeWholeSubtree,
	}[scope]
	if scope == "global" {
		scopeInt = ldap.ScopeWholeSubtree
		base = ""
		ok = true
	}
	if !ok {
		http.Error(w, "Bad Request: unknown scope — use base, one, subtree, or global", http.StatusBadRequest)
		return
	}
	reqAttrs := attrs
	if len(reqAttrs) == 0 {
		reqAttrs = []string{"objectClass", "modifyTimestamp"}
	}
	// The client-side fallback sort needs the sort attribute present, so
	// request it even when the user's attrs list omits it.
	if sortAttr := sortAttrs[sortKey]; sortAttr != "" && !containsString(reqAttrs, sortAttr) {
		reqAttrs = append(reqAttrs, sortAttr)
	}
	opts := ldapx.SearchOptions{
		BaseDN:         base,
		Scope:          scopeInt,
		Filter:         q,
		Attrs:          reqAttrs,
		PageSize:       pageSize,
		SizeLimit:      sizeLimit,
		TimeLimit:      timeLimit,
		AllowEmptyBase: scope == "global",
	}
	if sortKey != "dn" {
		opts.Sort = &ldapx.SortSpec{Attribute: sortAttrs[sortKey], Reverse: dir == "desc"}
	}
	res, err := h.client.Page(r.Context(), opts, page)
	if err != nil {
		if authn.IsInvalidCredentials(err) {
			authn.InvalidCredentialsRedirect(w, r)
			return
		}
		data.Error = "Search failed: " + err.Error()
		h.renderPage(w, r, data)
		return
	}
	sortPage(res.Entries, sortKey, dir)
	data.HasMore = res.HasMore
	data.SortFallback = res.SortFallback
	for _, e := range res.Entries {
		row := Row{
			DN:            e.DN,
			ObjectClasses: strings.Join(e.GetAttributeValues("objectClass"), ", "),
			Modified:      e.GetAttributeValue("modifyTimestamp"),
		}
		for _, a := range attrs {
			row.AttrValues = append(row.AttrValues, strings.Join(e.GetAttributeValues(a), ", "))
		}
		data.Rows = append(data.Rows, row)
	}
	data.Total = len(data.Rows)
	data.AttrColumns = attrs
	sp := searchParams{
		query: q, scope: scope, base: base, sort: sortKey, dir: dir,
		attrs: strings.Join(attrs, ","), sizeLimit: sizeLimit, timeLimit: timeLimit,
	}
	if data.HasMore {
		data.NextHref = sp.href(page+1, sortKey, dir)
	}
	if len(attrs) == 0 {
		for _, col := range []struct{ label, key string }{
			{"DN", "dn"}, {"Object classes", "objectclass"}, {"Last modified", "modified"},
		} {
			nextDir := "asc"
			if sortKey == col.key && dir == "asc" {
				nextDir = "desc"
			}
			data.Columns = append(data.Columns, Column{
				Label:  col.label,
				Href:   sp.href(1, col.key, nextDir),
				Active: sortKey == col.key,
				Dir:    dir,
			})
		}
	} else {
		nextDir := "asc"
		if sortKey == "dn" && dir == "asc" {
			nextDir = "desc"
		}
		data.Columns = append(data.Columns, Column{
			Label:  "DN",
			Href:   sp.href(1, "dn", nextDir),
			Active: sortKey == "dn",
			Dir:    dir,
		})
	}
	h.renderPage(w, r, data)
}

// searchParams carries the current search URL state so pagination and sort
// links preserve every parameter.
type searchParams struct {
	query, scope, base, sort, dir, attrs string
	sizeLimit, timeLimit                 int
}

func (p searchParams) href(page int, sortKey, dir string) string {
	v := url.Values{}
	v.Set("q", p.query)
	if p.scope != "" {
		v.Set("scope", p.scope)
	}
	if p.base != "" {
		v.Set("base", p.base)
	}
	if page > 0 {
		v.Set("page", strconv.Itoa(page))
	}
	if sortKey != "" {
		v.Set("sort", sortKey)
		v.Set("dir", dir)
	}
	if p.sizeLimit > 0 {
		v.Set("size_limit", strconv.Itoa(p.sizeLimit))
	}
	if p.timeLimit > 0 {
		v.Set("time_limit", strconv.Itoa(p.timeLimit))
	}
	if p.attrs != "" {
		v.Set("attrs", p.attrs)
	}
	return "/search?" + v.Encode()
}

// sortPage orders one result page by the requested key/direction. It is
// applied on every response so the fallback path (directory refused the
// server-side sort control) still returns ordered rows; when the server
// honored the control the page is already ordered and this is idempotent.
func sortPage(entries []*ldap.Entry, key, dir string) {
	less := func(i, j int) bool {
		switch key {
		case "modified":
			return entries[i].GetAttributeValue("modifyTimestamp") < entries[j].GetAttributeValue("modifyTimestamp")
		case "objectclass":
			return strings.Join(entries[i].GetAttributeValues("objectClass"), ", ") < strings.Join(entries[j].GetAttributeValues("objectClass"), ", ")
		default:
			return entries[i].DN < entries[j].DN
		}
	}
	if dir == "desc" {
		sort.SliceStable(entries, func(i, j int) bool { return less(j, i) })
		return
	}
	sort.SliceStable(entries, less)
}

func nonNegativeIntParam(r *http.Request, name string) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return n, nil
}

func parseAttrs(raw string) []string {
	var out []string
	for _, a := range strings.Split(raw, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

func containsString(vs []string, want string) bool {
	for _, v := range vs {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func (h *Handler) renderPage(w http.ResponseWriter, r *http.Request, data Data) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.renderer.PageAuth(w, "Search — ldapact", "search-content", data, web.ActorFrom(r.Context())); err != nil {
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
