package entry

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/tplengine"
)

// PasswordFormData drives the F3 form.
type PasswordFormData struct {
	DN            string
	CurrentScheme string
	Error         string
	Success       string
}

// PasswordForm handles GET /api/entry/{dn...}/password.
func (h *Handler) PasswordForm(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	scheme, err := h.currentScheme(r, dn)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	h.renderPage(w, "Change password — ldapact", "password-form-content", PasswordFormData{DN: dn, CurrentScheme: scheme})
}

// PasswordChange handles POST /api/entry/{dn...}/password (F3).
func (h *Handler) PasswordChange(w http.ResponseWriter, r *http.Request) {
	dn := r.PathValue("dn")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	newPW := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")
	if newPW == "" {
		h.renderPage(w, "Change password — ldapact", "password-form-content", PasswordFormData{DN: dn, Error: "Password is required"})
		return
	}
	if newPW != confirm {
		h.renderPage(w, "Change password — ldapact", "password-form-content", PasswordFormData{DN: dn, Error: "Passwords do not match"})
		return
	}
	scheme, err := h.currentScheme(r, dn)
	if err != nil {
		h.dnError(w, r, err)
		return
	}
	// KTD 6 default scheme (modification templates do not configure hashing).
	hashed, err := tplengine.HashPasswordWithOverride(tplengine.DefaultHashScheme, newPW,
		h.cfg != nil && h.cfg.LDAP.PasswordPlainOverride, h.logger)
	if err != nil {
		http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	changes := []ldap.Change{{
		Operation:    ldap.ReplaceAttribute,
		Modification: ldap.PartialAttribute{Type: "userPassword", Vals: []string{hashed}},
	}}
	if err := h.client.Modify(r.Context(), dn, changes); err != nil {
		// ppolicy overlays surface constraint violations as result codes
		// (e.g. 19 constraintViolation, 53 unwillingToPerform).
		h.logger.Warn("password change rejected", "event", "ldap.error", "dn", dn, "error", err)
		h.renderPage(w, "Change password — ldapact", "password-form-content", PasswordFormData{
			DN: dn, CurrentScheme: scheme, Error: passwordChangeError(err),
		})
		return
	}
	// AE4: verify the new password binds.
	if err := verifyUserBind(r.Context(), h.cfg, dn, newPW); err != nil {
		h.logger.Error("password set but bind verification failed", "event", "password.verify_failed", "dn", dn, "error", err)
		h.renderPage(w, "Change password — ldapact", "password-form-content", PasswordFormData{
			DN: dn, CurrentScheme: scheme,
			Error: "Password was updated but the bind verification failed — check the directory server.",
		})
		return
	}
	h.audit(r, "ldap.modify", dn, "modify")
	h.renderPage(w, "Password changed — ldapact", "password-form-content", PasswordFormData{
		DN: dn, CurrentScheme: scheme, Success: "Password changed. Old passwords no longer work.",
	})
}

func (h *Handler) currentScheme(r *http.Request, dn string) (string, error) {
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"userPassword"}, nil)
	res, err := h.client.Search(r.Context(), req)
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("entry not found: %s", dn)
	}
	vals := res.Entries[0].GetAttributeValues("userPassword")
	if len(vals) == 0 {
		return "none", nil
	}
	return tplengine.DetectScheme(vals[0]), nil
}

func verifyUserBind(ctx context.Context, cfg *config.Config, dn, password string) error {
	if cfg == nil {
		return nil // unit tests without a server skip the wire check
	}
	conn, err := ldapx.Dial(ctx, ldapx.DialOptions{URL: cfg.LDAP.URL, TLS: cfg.LDAP.TLS, Logger: nil})
	if err != nil {
		return err
	}
	defer conn.Close()
	return ldapx.Bind(conn, dn, password)
}

func passwordChangeError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "53"), strings.Contains(msg, "constraint"), strings.Contains(msg, "quality"):
		return "The directory rejected the password (policy violation)."
	case strings.Contains(msg, "19"):
		return "The directory rejected the password (constraint violation)."
	default:
		return "The directory rejected the password: " + msg
	}
}

func (h *Handler) dnError(w http.ResponseWriter, r *http.Request, err error) {
	if isNotFound(err) {
		http.NotFound(w, r)
		return
	}
	h.logger.Error("entry lookup failed", "event", "ldap.error", "error", err)
	http.Error(w, "Directory error", http.StatusBadGateway)
}
