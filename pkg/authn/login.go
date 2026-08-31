package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/session"
	"github.com/liut/ldapact/pkg/web"
)

// LoginData drives the login page.
type LoginData struct {
	BindDN string // prefilled from config, editable (R5)
	Next   string
	Error  string
}

// LoginHandler serves the shared-admin login gate (R5/R6): GET renders the
// form; POST verifies the bind DN + password against the directory, stores
// the encrypted credential in the session, and redirects to next.
type LoginHandler struct {
	store     session.Store
	cipher    *session.CredentialCipher
	client    *ldapx.Client // optional; warms the schema cache on login
	render    *web.Renderer
	logger    *slog.Logger
	serverRef string
	bindDN    string
	// verify is swappable in tests; production verifies through the
	// replica-aware client.
	verify func(context.Context, string, string) error
}

// NewLogin builds the login/logout handler.
func NewLogin(store session.Store, cipher *session.CredentialCipher, client *ldapx.Client,
	renderer *web.Renderer, logger *slog.Logger, serverRef, bindDN string) *LoginHandler {
	h := &LoginHandler{
		store: store, cipher: cipher, client: client, render: renderer,
		logger: logger, serverRef: serverRef, bindDN: bindDN,
	}
	h.verify = func(ctx context.Context, dn, password string) error {
		if client == nil {
			return errors.New("authn: LDAP client not configured")
		}
		return client.VerifyBind(ctx, dn, password)
	}
	return h
}

// ServeHTTP routes GET /login and POST /login. The route is public
// (middleware skips it), so a logged-in user re-posting replaces their old
// session (edge case: re-login rotates the identity).
func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.form(w, r)
	case http.MethodPost:
		h.submit(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *LoginHandler) form(w http.ResponseWriter, r *http.Request) {
	data := LoginData{
		BindDN: h.bindDN,
		Next:   sanitizeNext(r.URL.Query().Get("next")),
	}
	h.renderPage(w, "Login — ldapact", data)
}

func (h *LoginHandler) submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	dn := strings.TrimSpace(r.Form.Get("bind_dn"))
	password := r.Form.Get("password")
	next := sanitizeNext(r.Form.Get("next"))
	data := LoginData{BindDN: dn, Next: next}

	if dn == "" || password == "" {
		data.Error = "Bind DN and password are required."
		h.renderPage(w, "Login — ldapact", data)
		return
	}

	ctx := ldapx.WithCredential(r.Context(), ldapx.BindCredential{DN: dn, Password: password})
	if err := h.verify(ctx, dn, password); err != nil {
		if h.logger != nil {
			h.logger.Warn("login failed",
				"event", "session.login_failed",
				"actor", dn,
				"error", err)
		}
		data.Error = "Login failed: check the bind DN and password."
		h.renderPage(w, "Login — ldapact", data)
		return
	}

	// Replace any pre-existing session (re-login rotates the identity).
	if oldID, err := session.Read(r); err == nil {
		_ = h.store.Delete(oldID)
	}

	id, err := session.NewID()
	if err != nil {
		h.renderError(w, "session creation failed", err)
		return
	}
	encrypted, err := h.cipher.Encrypt([]byte(password))
	if err != nil {
		h.renderError(w, "credential encryption failed", err)
		return
	}
	if _, err := h.store.Create(id, dn, h.serverRef, encrypted); err != nil {
		h.renderError(w, "session store failed", err)
		return
	}
	session.Write(w, id)
	if h.logger != nil {
		h.logger.Info("login succeeded",
			"event", "session.login_ok",
			"actor", dn)
	}

	// Warm the schema cache with the verified credential (best effort): the
	// schema browser and edit forms assume it is populated post-login.
	if h.client != nil {
		if err := h.client.EnsureSchema(ctx); err != nil && h.logger != nil {
			h.logger.Warn("schema load after login failed",
				"event", "session.schema_load_failed",
				"error", err)
		}
	}

	http.Redirect(w, r, next, http.StatusFound)
}

// Logout deletes the session and clears the cookie (R7). POST /logout is
// protected by the middleware chain (CSRF/rate limit), so the session here is
// the rotated one.
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if s := SessionFrom(r.Context()); s != nil {
		_ = h.store.Delete(s.ID)
	}
	session.Clear(w)
	if h.logger != nil {
		h.logger.Info("logout", "event", "session.logout")
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *LoginHandler) renderPage(w http.ResponseWriter, title string, data LoginData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.Page(w, title, "login-content", data); err != nil {
		h.renderError(w, "render login page", err)
	}
}

func (h *LoginHandler) renderError(w http.ResponseWriter, event string, err error) {
	if h.logger != nil {
		h.logger.Error(event, "event", "session.login_error", "error", err)
	}
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
}

// sanitizeNext restricts the post-login redirect to a same-site path (no
// scheme, no protocol-relative URL).
func sanitizeNext(next string) string {
	if next == "" {
		return "/"
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// IsInvalidCredentials exposes the ldapx classification to handlers that do
// not import ldapx directly; it delegates to ldapx.IsInvalidCredentials.
func IsInvalidCredentials(err error) bool {
	return ldapx.IsInvalidCredentials(err)
}
