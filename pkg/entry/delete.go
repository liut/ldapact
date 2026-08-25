package entry

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/tree"
)

// MaxRecursiveDelete is the subtree-delete ceiling (default 1000 per plan).
const MaxRecursiveDelete = 1000

// DeleteConfirmData drives the F5 confirmation page.
type DeleteConfirmData struct {
	DN         string
	RDN        string
	ChildCount int
	Crumbs     []tree.Crumb
	Error      string
}

// DeleteForm handles GET /api/entry/{dn...}/delete (F5 confirmation).
func (h *Handler) DeleteForm(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	count, err := h.childCount(r, dn)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	h.renderPage(w, "Delete entry — ldapact", "delete-confirm-content", DeleteConfirmData{
		DN: dn, RDN: rdnValue(dn), ChildCount: count,
		Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
	})
}

// DeleteSubmit handles POST /api/entry/{dn...}/delete (F5).
func (h *Handler) DeleteSubmit(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	count, err := h.childCount(r, dn)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	recursive := r.FormValue("recursive") == "1"
	confirmDN := strings.TrimSpace(r.FormValue("confirm_dn"))

	confirm := DeleteConfirmData{
		DN: dn, RDN: rdnValue(dn), ChildCount: count,
		Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
	}
	switch {
	case count == 0:
		if err := h.client.Delete(r.Context(), dn); err != nil {
			h.dnError(w, r, err)
			return
		}
	case recursive:
		if count > MaxRecursiveDelete {
			confirm.Error = fmt.Sprintf("Subtree exceeds the recursive delete ceiling (%d entries).", MaxRecursiveDelete)
			h.renderPage(w, "Delete entry — ldapact", "delete-confirm-content", confirm)
			return
		}
		if err := h.recursiveDelete(r, dn); err != nil {
			confirm.Error = "Delete failed: " + err.Error()
			h.renderPage(w, "Delete entry — ldapact", "delete-confirm-content", confirm)
			return
		}
	default:
		if !strings.EqualFold(confirmDN, dn) {
			confirm.Error = "Non-leaf entries require typing the full DN to confirm."
			h.renderPage(w, "Delete entry — ldapact", "delete-confirm-content", confirm)
			return
		}
		// Single delete of a non-leaf will be rejected by the server
		// (notAllowedOnNonLeaf); the error surfaces on the confirmation page.
		if err := h.client.Delete(r.Context(), dn); err != nil {
			confirm.Error = "Delete failed: " + err.Error()
			h.renderPage(w, "Delete entry — ldapact", "delete-confirm-content", confirm)
			return
		}
	}
	h.audit(r, "ldap.delete", dn, "delete")
	parent := parentDN(dn)
	w.Header().Set("X-Mutated-Subtree", parent)
	h.renderPage(w, "Entry deleted — ldapact", "result-page", ResultData{
		Title: "Entry deleted", Message: fmt.Sprintf("Deleted %s", dn),
		Link: "/api/entry/" + url.PathEscape(parent), LinkText: "Back to parent",
	})
}

func (h *Handler) childCount(r *http.Request, dn string) (int, error) {
	req := ldap.NewSearchRequest(dn, ldap.ScopeSingleLevel, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"1.1"}, nil)
	res, err := h.client.Search(r.Context(), req)
	if err != nil {
		return 0, err
	}
	return len(res.Entries), nil
}

// recursiveDelete removes a subtree bottom-up with a ceiling guard.
func (h *Handler) recursiveDelete(r *http.Request, dn string) error {
	req := ldap.NewSearchRequest(dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"1.1"}, nil)
	res, err := h.client.Search(r.Context(), req)
	if err != nil {
		return err
	}
	if len(res.Entries) > MaxRecursiveDelete {
		return fmt.Errorf("subtree exceeds %d entries", MaxRecursiveDelete)
	}
	// Delete deepest first: sort by DN depth descending.
	entries := res.Entries
	sortEntriesByDepth(entries)
	for _, e := range entries {
		if err := h.client.Delete(r.Context(), e.DN); err != nil {
			return err
		}
	}
	return nil
}

func sortEntriesByDepth(entries []*ldap.Entry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && depth(entries[j-1].DN) < depth(entries[j].DN); j-- {
			entries[j-1], entries[j] = entries[j], entries[j-1]
		}
	}
}

func depth(dn string) int {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return 0
	}
	return len(parsed.RDNs)
}

func parentDN(dn string) string {
	if i := strings.Index(dn, ","); i >= 0 {
		return dn[i+1:]
	}
	return ""
}
