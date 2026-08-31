// Package tree implements F1 (tree browse) and R5 (schema browser) with the
// ARIA tree pattern from KTD 14/R18.
package tree

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/authn"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/web"
)

// Lister is the LDAP surface the tree handlers need; *ldapx.Client satisfies
// it. Tests use a fake.
type Lister interface {
	Page(ctx context.Context, opts ldapx.SearchOptions, page int) (*ldapx.PageResult, error)
	TreeFilter() string
	BaseDN() string
	Schema() *ldapx.Schema
}

// Node is one treeitem row.
type Node struct {
	ID          string // stable id used for the children container
	DN          string
	Label       string
	Level       int
	HasChildren bool
}

// ChildrenData drives the tree-children.html fragment.
type ChildrenData struct {
	ID       string // id of the children container being filled
	ParentDN string
	Nodes    []Node
	SetSize  int
	Page     int
	HasMore  bool
	Status   string // StatusEmpty | StatusInaccessible
	Error    string
}

// TreePageData drives the full-page tree scaffold (home).
type TreePageData struct {
	RootDN    string
	RootLabel string
}

// Tree renders tree browse endpoints.
type Tree struct {
	client   Lister
	render   *web.Renderer
	logger   *slog.Logger
	pageSize int
}

// NewTree builds the F1 handler set.
func NewTree(client Lister, renderer *web.Renderer, logger *slog.Logger) *Tree {
	return &Tree{client: client, render: renderer, logger: logger, pageSize: ldapx.DefaultPageSize}
}

// HomePage renders the tree scaffold rooted at the configured base DN (AE1).
func (t *Tree) HomePage(w http.ResponseWriter, r *http.Request) {
	root := t.client.BaseDN()
	data := TreePageData{
		RootDN:    root,
		RootLabel: rdnLabel(root),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.render.Page(w, "ldapact — Directory", "tree-page-content", data); err != nil {
		t.logger.Error("render tree page", "event", "web.render_failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Children handles GET /api/tree/{dn...}/children?page=N&level=L&id=ID (F1).
// It returns an HTMX fragment for the node's direct children, paged.
func (t *Tree) Children(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	if dn == "" {
		http.Error(w, "Bad Request: missing DN", http.StatusBadRequest)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	level, _ := strconv.Atoi(r.URL.Query().Get("level"))
	if level < 1 {
		level = 1
	}
	containerID := r.URL.Query().Get("id")
	if containerID == "" {
		containerID = "children-root"
	}

	res, err := t.client.Page(r.Context(), ldapx.SearchOptions{
		BaseDN:   dn,
		Scope:    ldap.ScopeSingleLevel,
		Filter:   t.client.TreeFilter(),
		Attrs:    []string{"*", "hassubordinates"},
		PageSize: t.pageSize,
	}, page)
	if err != nil {
		if authn.IsInvalidCredentials(err) {
			authn.InvalidCredentialsRedirect(w, r)
			return
		}
		t.renderFragment(w, ChildrenData{
			ID:       containerID,
			ParentDN: dn,
			Page:     page,
			Error:    friendlyError(err),
		})
		return
	}

	data := ChildrenData{
		ID:       containerID,
		ParentDN: dn,
		Page:     page,
		HasMore:  res.HasMore,
		Nodes:    buildNodes(res.Entries, level),
		SetSize:  len(res.Entries),
	}
	if len(res.Entries) == 0 {
		data.Status = StatusEmpty
	}
	w.Header().Set("HX-Trigger", "subtree-loaded")
	t.renderFragment(w, data)
}

func (t *Tree) renderFragment(w http.ResponseWriter, data ChildrenData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.render.Fragment(w, "tree-children.html", data); err != nil {
		t.logger.Error("render tree fragment", "event", "web.render_failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// buildNodes converts search entries into treeitem rows. Leaf detection
// mirrors phpLDAPadmin's use of the hassubordinates operational attribute.
func buildNodes(entries []*ldap.Entry, level int) []Node {
	nodes := make([]Node, 0, len(entries))
	for i, e := range entries {
		hasChildren := e.GetAttributeValue("hassubordinates") != "false"
		nodes = append(nodes, Node{
			ID:          fmt.Sprintf("n%d", i),
			DN:          e.DN,
			Label:       rdnLabel(e.DN),
			Level:       level,
			HasChildren: hasChildren,
		})
	}
	return nodes
}

// friendlyError maps LDAP errors to inline, user-facing messages (F1 error
// state: distinguish size-limit-exceeded from network failures).
func friendlyError(err error) string {
	var lerr *ldapx.LDAPError
	if errors.As(err, &lerr) {
		switch lerr.Code {
		case ldap.LDAPResultSizeLimitExceeded:
			return "Size limit exceeded — narrow the filter."
		case ldap.LDAPResultInsufficientAccessRights:
			return "Access denied by the directory server."
		default:
			return fmt.Sprintf("Directory error (result code %d).", lerr.Code)
		}
	}
	return "LDAP server unreachable — retry."
}

// rdnLabel returns the value of the first RDN attribute (e.g. "alice" for
// cn=alice,ou=People,...), falling back to the full DN.
func rdnLabel(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return dn
	}
	return parsed.RDNs[0].Attributes[0].Value
}
