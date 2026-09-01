// Package app assembles the HTTP handler chain and routes. It is internal so
// the CLI stays thin and the integration harness can exercise the real
// handler stack without spawning a process.
package app

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/liut/ldapact"
	"github.com/liut/ldapact/pkg/authn"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/entry"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/ldif"
	"github.com/liut/ldapact/pkg/logging"
	"github.com/liut/ldapact/pkg/ratelimit"
	"github.com/liut/ldapact/pkg/search"
	"github.com/liut/ldapact/pkg/secheaders"
	"github.com/liut/ldapact/pkg/session"
	"github.com/liut/ldapact/pkg/tree"
	"github.com/liut/ldapact/pkg/web"
)

// Deps carries the runtime dependencies into the handler chain.
type Deps struct {
	Logger *slog.Logger
	LDAP   *ldapx.Client
	Store  session.Store
	Cipher *session.CredentialCipher
	Cfg    *config.Config
}

// NewHandler assembles the request chain (recover -> request id -> security
// headers -> session -> csrf -> rate limit -> routes).
func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	renderer := web.New(web.MustParse(nil))
	var treeBrowser *tree.Tree
	var schemaBrowser *tree.SchemaBrowser
	var entryHandler *entry.Handler
	var importHandler *ldif.ImportHandler
	var exportHandler *ldif.ExportHandler
	var searchHandler *search.Handler
	var loginHandler *authn.LoginHandler
	if d.LDAP != nil {
		treeBrowser = tree.NewTree(d.LDAP, renderer, d.Logger)
		schemaBrowser = tree.NewSchemaBrowser(d.LDAP, renderer)
		templatesDir := ""
		if d.Cfg != nil {
			templatesDir = d.Cfg.TemplatesDir
		}
		loader := entry.NewTemplateLoader(ldapact.Templates(), templatesDir)
		entryHandler = entry.New(d.LDAP, renderer, d.Logger, loader, d.Store, d.Cfg)
		importHandler = ldif.NewImportHandler(d.LDAP, renderer, d.Logger)
		exportHandler = ldif.NewExportHandler(d.LDAP, d.Logger)
		searchHandler = search.New(d.LDAP, renderer)
	}
	if d.Store != nil && d.Cipher != nil {
		serverRef := ""
		bindDN := ""
		if d.Cfg != nil {
			if len(d.Cfg.LDAP.Servers) > 0 {
				serverRef = d.Cfg.LDAP.Servers[0]
			} else {
				serverRef = d.Cfg.LDAP.URL
			}
			bindDN = d.Cfg.LDAP.BindDN
		}
		loginHandler = authn.NewLogin(d.Store, d.Cipher, d.LDAP, renderer, d.Logger, serverRef, bindDN)
	}
	rateKey := ratelimit.RemoteAddrKey
	if d.Cfg != nil && d.Cfg.TrustProxy {
		rateKey = ratelimit.ProxyKey
	}
	loginLimiter := ratelimit.NewWithKey(2, 5, rateKey)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if d.LDAP != nil {
			treeBrowser.HomePage(w, r)
			return
		}
		if err := renderer.Page(w, "ldapact", "home-content", nil); err != nil {
			d.Logger.Error("render home page", "event", "web.render_failed", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})
	if loginHandler != nil {
		mux.Handle("GET /login", loginHandler)
		// Tighter per-key login limiter on top of the app-wide limiter
		// (2/s refill, burst 5): throttles password guessing without
		// penalizing normal browsing traffic. Keyed like the global limiter
		// (RemoteAddr, or X-Forwarded-For when LDAPADM_TRUST_PROXY=true).
		mux.Handle("POST /login", loginLimiter.Handler(loginHandler))
		mux.HandleFunc("POST /logout", loginHandler.Logout)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(ldapact.Assets())))
	if treeBrowser != nil {
		// Go's ServeMux only allows multi-segment wildcards ({dn...}) as the
		// final segment, so suffix actions are dispatched manually. /api/ is
		// reserved for endpoints that return data or HTMX fragments; full
		// pages live under their plain route.
		mux.HandleFunc("GET /api/tree/{dn...}", func(w http.ResponseWriter, r *http.Request) {
			treeDispatch(treeBrowser, w, r)
		})
		mux.HandleFunc("GET /schema/objectclass", schemaBrowser.ObjectClasses)
		mux.HandleFunc("GET /schema/objectclass/{name}", schemaBrowser.ObjectClassDetail)
		mux.HandleFunc("GET /schema/attribute", schemaBrowser.Attributes)
		mux.HandleFunc("GET /schema/attribute/{name}", schemaBrowser.AttributeDetail)
		mux.HandleFunc("GET /template/{name}", entryHandler.CreateForm)
		mux.HandleFunc("POST /template/{name}/create", entryHandler.CreateSubmit)
		mux.HandleFunc("GET /entry/{dn...}", func(w http.ResponseWriter, r *http.Request) {
			entryDispatch(entryHandler, w, r)
		})
		mux.HandleFunc("POST /entry/{dn...}", func(w http.ResponseWriter, r *http.Request) {
			entryDispatch(entryHandler, w, r)
		})
		// Photo streams binary image data, so it stays under /api while every
		// other entry action renders a page under /entry/{dn...}.
		mux.HandleFunc("GET /api/entry/{dn...}", func(w http.ResponseWriter, r *http.Request) {
			apiEntryDispatch(entryHandler, w, r)
		})
		mux.HandleFunc("GET /import", importHandler.Form)
		mux.HandleFunc("POST /import", importHandler.Submit)
		mux.HandleFunc("GET /api/import/report/{id}", importHandler.Report)
		mux.HandleFunc("GET /api/export", exportHandler.Export)
		mux.HandleFunc("GET /search", searchHandler.Search)
	}

	var h http.Handler = mux
	h = ratelimit.NewWithKey(60, 120, rateKey).Handler(h)
	h = authn.Middleware(authn.MiddlewareOptions{Store: d.Store, Cipher: d.Cipher, Logger: d.Logger})(h)
	// CSRF runs before the session middleware so a rejected cross-origin
	// state change never mutates session state (rotation happens in the
	// middleware and would otherwise precede the Origin check).
	h = authn.CSRF(d.Logger)(h)
	h = secheaders.Middleware(h)
	h = logging.RequestID(h)
	h = logging.Recover(d.Logger)(h)
	return h
}

// treeDispatch strips the "/children" action suffix from
// /api/tree/{dn...}/children (multi-segment wildcards must end the pattern).
func treeDispatch(t *tree.Tree, w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/tree/")
	dn := strings.TrimSuffix(rest, "/children")
	if dn == rest || dn == "" {
		http.NotFound(w, r)
		return
	}
	r.SetPathValue("dn", dn)
	t.Children(w, r)
}

// entryDispatch routes /entry/{dn...} and its /edit /password /delete /rename
// action suffixes by method (wildcards must end the pattern, so the action is
// parsed from the last path segment). DNs containing "/" are not supported.
func entryDispatch(h *entry.Handler, w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/entry/")
	dn, action := parseEntryAction(rest)
	r.SetPathValue("dn", dn)
	switch action {
	case "password":
		if r.Method == http.MethodPost {
			h.PasswordChange(w, r)
		} else {
			h.PasswordForm(w, r)
		}
	case "delete":
		if r.Method == http.MethodPost {
			h.DeleteSubmit(w, r)
		} else {
			h.DeleteForm(w, r)
		}
	case "rename":
		if r.Method == http.MethodPost {
			h.RenameSubmit(w, r)
		} else {
			h.RenameForm(w, r)
		}
	case "edit":
		if r.Method == http.MethodPost {
			h.EditSubmit(w, r)
		} else {
			h.EditForm(w, r)
		}
	case "":
		h.Detail(w, r)
	default:
		http.NotFound(w, r)
	}
}

// apiEntryDispatch serves the only /api/entry route: GET
// /api/entry/{dn...}/photo streams a stored jpegPhoto as image data. The
// remaining entry actions render pages and live under /entry/{dn...}.
func apiEntryDispatch(h *entry.Handler, w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/entry/")
	dn, action := parseEntryAction(rest)
	if action != "photo" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	r.SetPathValue("dn", dn)
	h.Photo(w, r)
}

// parseEntryAction splits the trailing action suffix ("" | edit | password |
// delete | rename | photo) from the entry DN.
func parseEntryAction(rest string) (dn, action string) {
	dn = rest
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		dn, action = rest[:i], rest[i+1:]
	}
	return dn, action
}
