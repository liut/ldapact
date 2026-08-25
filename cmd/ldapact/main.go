// Command ldapact is the single-binary phpLDAPadmin replacement (R17).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if err := os.Setenv("GOTRACEBACK", "none"); err != nil {
		fmt.Fprintf(os.Stderr, "ldapact: set GOTRACEBACK: %v\n", err)
		return 1
	}

	fs := flag.NewFlagSet("ldapact", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		configPath  string
		showVersion bool
	)
	fs.StringVar(&configPath, "config", "config/example.yaml", "path to the server profile YAML")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Printf("ldapact %s (commit %s)\n", version, commit)
		return 0
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ldapact: %v\n", err)
		return 1
	}
	if err := cfg.ResolveSecrets(); err != nil {
		fmt.Fprintf(os.Stderr, "ldapact: %v\n", err)
		return 1
	}

	lvl, err := logging.LevelFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ldapact: %v\n", err)
		return 1
	}
	if os.Getenv(logging.LevelEnv) == "" {
		lvl, err = logging.LevelFromString(cfg.LogLevel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ldapact: %v\n", err)
			return 1
		}
	}
	logger := logging.New(lvl, os.Stdout)
	disableCoreDumps(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ldapClient, err := ldapx.New(ctx, cfg, logger)
	if err != nil {
		logger.Error("LDAP startup bind failed (fail-fast, R14)",
			"event", "ldap.bind.failed",
			"error", err)
		return 1
	}
	defer ldapClient.Close()
	logger.Info("LDAP bound",
		"event", "ldap.bind.ok",
		"base_dn", cfg.LDAP.BaseDN)

	sessionStore, err := session.NewStore(
		cfg.Session.DBPath,
		time.Duration(cfg.Session.TimeoutMinutes)*time.Minute,
		time.Duration(cfg.Session.AbsoluteTimeoutMinutes)*time.Minute)
	if err != nil {
		logger.Error("session store failed to open", "event", "session.store_open_failed", "error", err)
		return 1
	}
	defer sessionStore.Close()
	stopSweep := make(chan struct{})
	defer close(stopSweep)
	go sessionStore.SweepLoop(5*time.Minute, stopSweep)

	logger.Info("starting ldapact",
		"event", "server.start",
		"version", version,
		"commit", commit,
		"listen", cfg.Server.Listen,
		"base_dn", cfg.LDAP.BaseDN,
		"bind_dn", cfg.LDAP.BindDN,
	)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           newHandler(appDeps{logger: logger, ldap: ldapClient, store: sessionStore, cfg: cfg}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited", "event", "server.stop", "error", err)
			return 1
		}
	case <-ctx.Done():
		logger.Info("shutting down", "event", "server.shutdown")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}
	return 0
}

// appDeps carries the runtime dependencies into the handler chain.
type appDeps struct {
	logger *slog.Logger
	ldap   *ldapx.Client
	store  *session.Store
	cfg    *config.Config
}

// newHandler assembles the request chain (recover -> request id -> security
// headers -> session -> csrf -> rate limit -> routes).
func newHandler(deps appDeps) http.Handler {
	mux := http.NewServeMux()
	renderer := web.New(web.MustParse(nil))
	var treeBrowser *tree.Tree
	var schemaBrowser *tree.SchemaBrowser
	var entryHandler *entry.Handler
	var importHandler *ldif.ImportHandler
	var exportHandler *ldif.ExportHandler
	var searchHandler *search.Handler
	if deps.ldap != nil {
		treeBrowser = tree.NewTree(deps.ldap, renderer, deps.logger)
		schemaBrowser = tree.NewSchemaBrowser(deps.ldap, renderer)
		templatesDir := ""
		if deps.cfg != nil {
			templatesDir = deps.cfg.TemplatesDir
		}
		loader := entry.NewTemplateLoader(ldapact.Templates(), templatesDir)
		entryHandler = entry.New(deps.ldap, renderer, deps.logger, loader, deps.store, deps.cfg)
		importHandler = ldif.NewImportHandler(deps.ldap, renderer, deps.logger)
		exportHandler = ldif.NewExportHandler(deps.ldap, deps.logger)
		searchHandler = search.New(deps.ldap, renderer)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if deps.ldap != nil {
			treeBrowser.HomePage(w, r)
			return
		}
		if err := renderer.Page(w, "ldapact", "home-content", nil); err != nil {
			deps.logger.Error("render home page", "event", "web.render_failed", "error", err)
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
		mux.HandleFunc("GET /api/tree/{dn...}/children", treeBrowser.Children)
		mux.HandleFunc("GET /api/schema/objectclass", schemaBrowser.ObjectClasses)
		mux.HandleFunc("GET /api/schema/objectclass/{name}", schemaBrowser.ObjectClassDetail)
		mux.HandleFunc("GET /api/schema/attribute", schemaBrowser.Attributes)
		mux.HandleFunc("GET /api/schema/attribute/{name}", schemaBrowser.AttributeDetail)
		mux.HandleFunc("GET /api/template/{name}", entryHandler.CreateForm)
		mux.HandleFunc("POST /api/template/{name}/create", entryHandler.CreateSubmit)
		mux.HandleFunc("GET /api/entry/{dn...}", entryHandler.Detail)
		mux.HandleFunc("GET /api/entry/{dn...}/password", entryHandler.PasswordForm)
		mux.HandleFunc("POST /api/entry/{dn...}/password", entryHandler.PasswordChange)
		mux.HandleFunc("GET /api/entry/{dn...}/delete", entryHandler.DeleteForm)
		mux.HandleFunc("POST /api/entry/{dn...}/delete", entryHandler.DeleteSubmit)
		mux.HandleFunc("GET /api/entry/{dn...}/rename", entryHandler.RenameForm)
		mux.HandleFunc("POST /api/entry/{dn...}/rename", entryHandler.RenameSubmit)
		mux.HandleFunc("GET /api/import", importHandler.Form)
		mux.HandleFunc("POST /api/import", importHandler.Submit)
		mux.HandleFunc("GET /api/import/report/{id}", importHandler.Report)
		mux.HandleFunc("GET /api/export", exportHandler.Export)
		mux.HandleFunc("GET /api/search", searchHandler.Search)
	}

	var h http.Handler = mux
	h = ratelimit.New(60, 120).Handler(h)
	h = authn.CSRF(deps.logger)(h)
	sessOpts := authn.MiddlewareOptions{Store: deps.store, Logger: deps.logger}
	if deps.cfg != nil {
		sessOpts.ExpiredAction = deps.cfg.Session.ExpiredAction
		sessOpts.Profile = deps.cfg.LDAP.BindDN
	}
	h = authn.Middleware(sessOpts)(h)
	h = secheaders.Middleware(h)
	h = logging.RequestID(h)
	h = logging.Recover(deps.logger)(h)
	return h
}

// disableCoreDumps sets RLIMIT_CORE to zero so secrets never leak through
// crash artifacts (KTD 17). Best-effort: some platforms refuse to lower the
// limit, which is logged but not fatal.
func disableCoreDumps(logger *slog.Logger) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		logger.Warn("cannot read RLIMIT_CORE", "event", "core_dump.limit_unavailable", "error", err)
		return
	}
	lim.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		logger.Warn("cannot disable core dumps", "event", "core_dump.disable_failed", "error", err)
	}
}
