package entry

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/tree"
)

// DeleteConfirmData drives the F5 confirmation page.
type DeleteConfirmData struct {
	DN         string
	RDN        string
	ChildCount int
	Blocked    bool
	Crumbs     []tree.Crumb
	Error      string
}

// DeleteForm handles GET /entry/{dn...}/delete (F5 confirmation).
func (h *Handler) DeleteForm(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	count, err := h.childCount(r, dn)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	h.renderPage(w, "Delete entry — ldapact", "delete-confirm-content", DeleteConfirmData{
		DN: dn, RDN: rdnValue(dn), ChildCount: count, Blocked: count > 0,
		Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
	})
}

// DeleteSubmit handles POST /entry/{dn...}/delete (F5). Deletion is
// leaf-only (R13): an entry with children is blocked, never deleted.
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
	if count > 0 {
		h.renderPage(w, "Delete entry — ldapact", "delete-confirm-content", DeleteConfirmData{
			DN: dn, RDN: rdnValue(dn), ChildCount: count, Blocked: true,
			Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
		})
		return
	}
	if err := h.client.Delete(r.Context(), dn); err != nil {
		if handleInvalidCredentials(w, r, err) {
			return
		}
		h.dnError(w, r, err)
		return
	}
	h.audit(r, "ldap.delete", dn, "delete")
	parent := parentDN(dn)
	w.Header().Set("X-Mutated-Subtree", parent)
	h.renderPage(w, "Entry deleted — ldapact", "result-page", ResultData{
		Title: "Entry deleted", Message: fmt.Sprintf("Deleted %s", dn),
		Link: "/entry/" + url.PathEscape(parent), LinkText: "Back to parent",
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

func parentDN(dn string) string {
	if i := strings.Index(dn, ","); i >= 0 {
		return dn[i+1:]
	}
	return ""
}
