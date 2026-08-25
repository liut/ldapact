// Command ldapact is the single-binary phpLDAPadmin replacement (R17).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/liut/ldapact/pkg/authn"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/logging"
	"github.com/liut/ldapact/pkg/ratelimit"
	"github.com/liut/ldapact/pkg/secheaders"
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
		Handler:           newHandler(logger),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exited", "event", "server.stop", "error", err)
		return 1
	}
	return 0
}

// newHandler assembles the request chain (recover -> request id -> security
// headers -> csrf -> rate limit -> routes). Session middleware joins in U3.
func newHandler(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, `<!doctype html><html><head><title>ldapact</title></head><body><h1>ldapact</h1><p>v1 skeleton is up; LDAP flows land in later units.</p></body></html>`)
	})

	var h http.Handler = mux
	h = ratelimit.New(60, 120).Handler(h)
	h = authn.CSRF(logger)(h)
	h = secheaders.Middleware(h)
	h = logging.RequestID(h)
	h = logging.Recover(logger)(h)
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
