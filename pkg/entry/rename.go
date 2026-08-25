package entry

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/tree"
)

// RenameFormData drives the F6 form.
type RenameFormData struct {
	DN           string
	ParentDN     string
	NewRDN       string
	NewSuperior  string
	DeleteOldRDN bool
	Error        string
	Crumbs       []tree.Crumb
}

// RenameForm handles GET /api/entry/{dn...}/rename.
func (h *Handler) RenameForm(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	h.renderPage(w, "Rename entry — ldapact", "rename-form-content", RenameFormData{
		DN: dn, ParentDN: parentDN(dn), DeleteOldRDN: true,
		Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
	})
}

// RenameSubmit handles POST /api/entry/{dn...}/rename (F6).
func (h *Handler) RenameSubmit(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	newRDN := strings.TrimSpace(r.FormValue("new_rdn"))
	newSuperior := strings.TrimSpace(r.FormValue("new_superior"))
	deleteOld := r.FormValue("delete_old_rdn") == "1"
	if newRDN == "" {
		h.renderPage(w, "Rename entry — ldapact", "rename-form-content", RenameFormData{
			DN: dn, ParentDN: parentDN(dn), NewRDN: newRDN, NewSuperior: newSuperior, DeleteOldRDN: deleteOld,
			Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
			Error:  "New RDN is required",
		})
		return
	}
	// Validate the target parent exists (F6 error path).
	targetParent := newSuperior
	if targetParent == "" {
		targetParent = parentDN(dn)
	}
	if targetParent != "" {
		req := ldap.NewSearchRequest(targetParent, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"1.1"}, nil)
		if _, err := h.client.Search(r.Context(), req); err != nil {
			if isNotFound(err) {
				h.renderPage(w, "Rename entry — ldapact", "rename-form-content", RenameFormData{
					DN: dn, ParentDN: parentDN(dn), NewRDN: newRDN, NewSuperior: newSuperior, DeleteOldRDN: deleteOld,
					Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
					Error:  "Target parent does not exist",
				})
				return
			}
			h.dnError(w, r, err)
			return
		}
	}
	if err := h.client.ModifyDN(r.Context(), dn, newRDN, deleteOld, newSuperior); err != nil {
		h.renderPage(w, "Rename entry — ldapact", "rename-form-content", RenameFormData{
			DN: dn, ParentDN: parentDN(dn), NewRDN: newRDN, NewSuperior: newSuperior, DeleteOldRDN: deleteOld,
			Crumbs: tree.Breadcrumbs(dn, h.client.BaseDN(), 5),
			Error:  "Rename failed: " + err.Error(),
		})
		return
	}
	h.audit(r, "ldap.rename", dn, "modrdn")
	parent := targetParent
	if parent == "" {
		parent = h.client.BaseDN()
	}
	w.Header().Set("X-Mutated-Subtree", parent)
	h.renderPage(w, "Entry renamed — ldapact", "result-page", ResultData{
		Title:    "Entry renamed",
		Message:  fmt.Sprintf("Renamed to %s", dn),
		Link:     "/api/entry/" + url.PathEscape(dn),
		LinkText: "View entry",
	})
}
