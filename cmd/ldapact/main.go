// Command ldapact is the single-binary phpLDAPadmin replacement (R17).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/liut/ldapact/internal/app"
	"github.com/liut/ldapact/pkg/config"
	"github.com/liut/ldapact/pkg/ldapx"
	"github.com/liut/ldapact/pkg/logging"
	"github.com/liut/ldapact/pkg/session"
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
		showVersion bool
		healthcheck bool
		healthURL   string
	)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.BoolVar(&healthcheck, "healthcheck", false, "check /healthz and exit (container health probes)")
	fs.StringVar(&healthURL, "health-url", "http://127.0.0.1:8080/healthz", "URL for -healthcheck")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Printf("ldapact %s (commit %s)\n", version, commit)
		return 0
	}
	if healthcheck {
		resp, err := http.Get(healthURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ldapact: healthcheck failed: %v\n", err)
			return 1
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "ldapact: healthcheck: status %d\n", resp.StatusCode)
			return 1
		}
		return 0
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ldapact: %v\n", err)
		return 1
	}
	if err := cfg.ResolveSecrets(); err != nil {
		fmt.Fprintf(os.Stderr, "ldapact: %v\n", err)
		return 1
	}

	lvl, err := logging.LevelFromString(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ldapact: %v\n", err)
		return 1
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
		"db_path", cfg.Session.DBPath,
		"base_dn", cfg.LDAP.BaseDN,
		"bind_dn", cfg.LDAP.BindDN,
	)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           app.NewHandler(app.Deps{Logger: logger, LDAP: ldapClient, Store: sessionStore, Cfg: cfg}),
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
