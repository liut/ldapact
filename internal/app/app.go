// Package app assembles the HTTP handler chain and routes. It is internal so
// the CLI stays thin and the integration harness can exercise the real
// handler stack without spawning a process.
package app

import (
	"fmt"
	"html"
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
	Store  *session.Store
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
	// Minimal landing for the redirect_to_login expired-session action (AE7).
	// v1 has no credential entry (AE1 auto-bind); the page offers to continue.
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		next := r.URL.Query().Get("next")
		if next == "" {
			next = "/"
		}
		fmt.Fprintf(w, `<!doctype html><html><head><title>Session expired — ldapact</title></head><body><main role="main"><h1>Session expired</h1><p>Your session expired. <a href="%s">Continue to ldapact</a>.</p></main></body></html>`, html.EscapeString(next))
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(ldapact.Assets())))
	if treeBrowser != nil {
		// Go's ServeMux only allows multi-segment wildcards ({dn...}) as the
		// final segment, so suffix actions are dispatched manually.
		mux.HandleFunc("GET /api/tree/{dn...}", func(w http.ResponseWriter, r *http.Request) {
			treeDispatch(treeBrowser, w, r)
		})
		mux.HandleFunc("GET /api/schema/objectclass", schemaBrowser.ObjectClasses)
		mux.HandleFunc("GET /api/schema/objectclass/{name}", schemaBrowser.ObjectClassDetail)
		mux.HandleFunc("GET /api/schema/attribute", schemaBrowser.Attributes)
		mux.HandleFunc("GET /api/schema/attribute/{name}", schemaBrowser.AttributeDetail)
		mux.HandleFunc("GET /api/template/{name}", entryHandler.CreateForm)
		mux.HandleFunc("POST /api/template/{name}/create", entryHandler.CreateSubmit)
		mux.HandleFunc("GET /api/entry/{dn...}", func(w http.ResponseWriter, r *http.Request) {
			entryDispatch(entryHandler, w, r)
		})
		mux.HandleFunc("POST /api/entry/{dn...}", func(w http.ResponseWriter, r *http.Request) {
			entryDispatch(entryHandler, w, r)
		})
		mux.HandleFunc("GET /api/import", importHandler.Form)
		mux.HandleFunc("POST /api/import", importHandler.Submit)
		mux.HandleFunc("GET /api/import/report/{id}", importHandler.Report)
		mux.HandleFunc("GET /api/export", exportHandler.Export)
		mux.HandleFunc("GET /api/search", searchHandler.Search)
	}

	var h http.Handler = mux
	h = ratelimit.New(60, 120).Handler(h)
	h = authn.CSRF(d.Logger)(h)
	sessOpts := authn.MiddlewareOptions{Store: d.Store, Logger: d.Logger}
	if d.Cfg != nil {
		sessOpts.ExpiredAction = d.Cfg.Session.ExpiredAction
		sessOpts.Profile = d.Cfg.LDAP.BindDN
	}
	h = authn.Middleware(sessOpts)(h)
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

// entryDispatch routes /api/entry/{dn...} and its /password /delete /rename
// action suffixes by method (wildcards must end the pattern, so the action is
// parsed from the last path segment). DNs containing "/" are not supported.
func entryDispatch(h *entry.Handler, w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/entry/")
	dn := rest
	action := ""
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		dn, action = rest[:i], rest[i+1:]
	}
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
	case "photo":
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		h.Photo(w, r)
	case "":
		h.Detail(w, r)
	default:
		http.NotFound(w, r)
	}
}
