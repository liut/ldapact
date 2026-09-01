// Command ldapact is the single-binary phpLDAPadmin replacement (R17).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
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
		showConfig  bool
		healthcheck bool
		healthURL   string
	)
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.BoolVar(&showConfig, "config-help", false, "print LDAPADM_* configuration reference and exit")
	fs.BoolVar(&healthcheck, "healthcheck", false, "check /healthz and exit (container health probes)")
	fs.StringVar(&healthURL, "health-url", "http://127.0.0.1:8389/healthz", "URL for -healthcheck")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Printf("ldapact %s (commit %s)\n", version, commit)
		return 0
	}
	if showConfig {
		if err := config.Usage(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "ldapact: config help: %v\n", err)
			return 1
		}
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
		logger.Error("LDAP startup dial failed (fail-fast, R15)",
			"event", "ldap.dial.failed",
			"error", err)
		return 1
	}
	defer ldapClient.Close()
	replicas := len(cfg.LDAP.Servers)
	if replicas == 0 {
		replicas = 1
	}
	logger.Info("LDAP replicas ready",
		"event", "ldap.dial_ok",
		"replicas", replicas,
		"active", ldapClient.ReplicaCount(),
		"base_dn", cfg.LDAP.BaseDN)

	cipher, err := session.NewCredentialCipher(cfg.SessionKey)
	if err != nil {
		logger.Error("session credential cipher failed", "event", "session.cipher_failed", "error", err)
		return 1
	}

	sessionStore, err := newSessionStore(ctx, cfg, logger)
	if err != nil {
		logger.Error("session store failed to open", "event", "session.store_open_failed", "error", err)
		return 1
	}
	defer sessionStore.Close()
	stopSweep := make(chan struct{})
	defer close(stopSweep)
	session.StartSweepLoop(sessionStore, 5*time.Minute, stopSweep)

	logger.Info("starting ldapact",
		"event", "server.start",
		"version", version,
		"commit", commit,
		"listen", cfg.Server.Listen,
		"session_store", cfg.Session.Store,
		"base_dn", cfg.LDAP.BaseDN,
		"bind_dn", cfg.LDAP.BindDN,
	)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           app.NewHandler(app.Deps{Logger: logger, LDAP: ldapClient, Store: sessionStore, Cipher: cipher, Cfg: cfg}),
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

// newSessionStore builds the configured session backend (R1/U8): Redis
// (default), bbolt (non-default compatibility), or memory. Redis and bbolt
// fail fast when their backing store is unreachable/invalid — except when
// the redis store was defaulted (not explicitly configured) and the Redis
// URL is empty or points at a loopback host (localhost/127.*/::1): those
// dev-shaped configurations fall back to the in-memory store with a warning
// instead of refusing to start.
func newSessionStore(ctx context.Context, cfg *config.Config, logger *slog.Logger) (session.Store, error) {
	idle := time.Duration(cfg.Session.TimeoutMinutes) * time.Minute
	absolute := time.Duration(cfg.Session.AbsoluteTimeoutMinutes) * time.Minute
	switch cfg.Session.Store {
	case config.SessionStoreRedis:
		store, err := session.NewRedisStore(ctx, session.RedisOptions{
			URL:      cfg.Session.RedisURL,
			Password: cfg.RedisPassword,
			DB:       cfg.Session.RedisDB,
		}, idle, absolute)
		if err != nil && !cfg.SessionStoreExplicit &&
			(cfg.Session.RedisURL == "" || isLoopbackRedisURL(cfg.Session.RedisURL)) {
			logger.Warn("Redis unavailable; using in-memory session store",
				"event", "session.redis_fallback_memory",
				"redis_url", redisURLForLog(cfg.Session.RedisURL),
				"error", err)
			return session.NewMemoryStore(idle, absolute), nil
		}
		return store, err
	case config.SessionStoreMemory:
		return session.NewMemoryStore(idle, absolute), nil
	default: // bbolt (R17): LDAPADM_DB_PATH applies here.
		return session.NewStore(cfg.Session.DBPath, idle, absolute)
	}
}

// isLoopbackRedisURL reports whether the Redis URL targets the local
// machine (localhost, 127.*, or ::1) — the only shapes eligible for the
// memory-store fallback.
func isLoopbackRedisURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.")
}

// redisURLForLog returns a log-safe view of a Redis URL: scheme + host only,
// never the userinfo component (a password may be embedded in the URL).
func redisURLForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid-redis-url>"
	}
	return u.Scheme + "://" + u.Host
}
