// Package config loads and validates the ldapact v1 server configuration (R12).
//
// Configuration is read from LDAPADM_* environment variables parsed by
// github.com/kelseyhightower/envconfig; there is no config file. Startup
// fails fast on policy violations; unknown LDAPADM_* variables are ignored.
// Secrets (bind password, auto-number password) are never parsed from the
// environment; they are resolved at startup through the secret resolver
// chain implemented in secret.go.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

// envPrefix is the envconfig prefix for every non-secret configuration
// variable. The full contract names are envPrefix + "_" + the short
// envconfig tag on envFields (e.g. LDAPADM_LISTEN).
const envPrefix = "LDAPADM"

// Secret env var names (R12). These are read directly by the resolver chain
// in secret.go. The non-secret LDAPADM_* contract names are test-only and
// live in config_test.go, pinned to the envconfig tags by
// TestEnvTagsMatchConstants.
const (
	BindPasswordEnv       = "LDAPADM_BIND_PASSWORD"
	AutoNumberPasswordEnv = "LDAPADM_AUTO_NUMBER_PASSWORD"
)

// Defaults (KTD 3, 5, 8; R2, R13).
const (
	DefaultListen               = "127.0.0.1:8389"
	DefaultIdleTimeoutMinutes   = 30
	DefaultAbsoluteTimeoutHours = 8
	DefaultPoolSize             = 8
	DefaultTreeFilter           = "(objectClass=*)"
	DefaultSchemaCompat         = "openldap"
	DefaultLogLevel             = "info"
	DefaultSessionDBPath        = "/var/lib/ldapact/sessions.db"
	DefaultTLSMinVersion        = "TLSv1.2"
)

// FallbackSessionDBPath returns the per-user XDG state path
// (~/.local/state/ldapact/sessions.db) used when the classic
// /var/lib/ldapact directory does not exist. If the home directory cannot
// be determined it returns DefaultSessionDBPath rather than inventing a
// path.
func FallbackSessionDBPath() string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".local", "state", "ldapact", "sessions.db")
	}
	return DefaultSessionDBPath
}

// resolveSessionDBPath applies the classic-default fallback to the effective
// DB path. When the path is the built-in /var/lib/ldapact/sessions.db and
// that directory does not exist, it switches to the per-user XDG state path.
// This covers both an unset variable and an explicitly configured value that
// happens to equal the default (e.g. sample env files), so the "default
// directory missing" rule is applied consistently. Any other explicitly
// configured path is left untouched.
func resolveSessionDBPath(dbPath string) string {
	return resolveSessionDBPathFor(dbPath, filepath.Dir(DefaultSessionDBPath), FallbackSessionDBPath())
}

// resolveSessionDBPathFor is the pure decision behind resolveSessionDBPath,
// split out so tests can exercise both branches without touching the host
// filesystem.
func resolveSessionDBPathFor(dbPath, systemDir, fallback string) string {
	if dbPath == DefaultSessionDBPath {
		return defaultSessionDBPathFor(systemDir, fallback)
	}
	return dbPath
}

// defaultSessionDBPathFor is the pure existence check behind the classic
// default resolution, split out so tests can exercise both branches without
// touching the host filesystem.
func defaultSessionDBPathFor(systemDir, fallback string) string {
	if fi, err := os.Stat(systemDir); err == nil && fi.IsDir() {
		return DefaultSessionDBPath
	}
	return fallback
}

// Session expiry actions (R13).
const (
	ExpiredActionRetryBind     = "retry_bind"
	ExpiredActionRedirectLogin = "redirect_to_login"
)

// TLSConfig controls the LDAP TLS posture (KTD 10). verify=off is rejected at
// parse time, StartTLS failures are fatal at runtime, and an expired server
// certificate refuses startup.
type TLSConfig struct {
	MinVersion           string
	Verify               *bool
	StartTLS             *bool
	CertExpiryFailClosed *bool
}

// LDAPConfig is the single-server profile (R12).
type LDAPConfig struct {
	URL          string
	BaseDN       string
	BindDN       string
	AutoNumberDN string
	TLS          TLSConfig
	SchemaCompat string
	TreeFilter   string
	PoolSize     int
	// PasswordPlainOverride permits {PLAIN} writes (KTD 6). Off by default;
	// enabling it emits a structured warn on every plaintext write.
	PasswordPlainOverride bool
	// PasswordScheme is the RFC 2307 write scheme (default SSHA512 per KTD 6).
	// Some directory builds only support legacy schemes ({SSHA} et al.); set
	// this to one of the write-allowlist names to match the server.
	PasswordScheme string
}

// SessionConfig carries the cookie/session security settings (R13, KTD 8).
type SessionConfig struct {
	TimeoutMinutes         int
	AbsoluteTimeoutMinutes int
	ExpiredAction          string
	DBPath                 string
}

// ServerConfig is the HTTP listener section.
type ServerConfig struct {
	Listen string
}

// Config is the v1 server profile (R16: a plain struct, not an interface).
// BindPassword and AutoNumberPassword are runtime-only values filled by
// ResolveSecrets; they are never parsed from the environment.
type Config struct {
	Server       ServerConfig
	LDAP         LDAPConfig
	Session      SessionConfig
	LogLevel     string
	TemplatesDir string

	BindPassword       string
	AutoNumberPassword string
}

// envFields is the flat envconfig view of the profile: every non-secret field
// tagged with its short leaf name, parsed with envPrefix. envconfig always
// prepends enclosing struct names to nested-struct keys, so parsing the
// nested Config directly would produce names like LDAPADM_LDAP_URL; the flat
// view keeps the LDAPADM_* contract while Config keeps its shape for
// consumers. The desc tags feed envconfig.Usage (see Usage).
type envFields struct {
	Listen        string `envconfig:"LISTEN" desc:"HTTP listen address (default 127.0.0.1:8389)"`
	URL           string `envconfig:"URL" desc:"LDAP server URL: ldap://host:port or ldaps://host:port (required)"`
	BaseDN        string `envconfig:"BASE_DN" desc:"LDAP base DN (required)"`
	BindDN        string `envconfig:"BIND_DN" desc:"LDAP bind DN (required)"`
	AutoNumberDN  string `envconfig:"AUTO_NUMBER_DN" desc:"auto-number service DN (optional)"`
	LogLevel      string `envconfig:"LOG_LEVEL" desc:"log level: debug|info|warn|error (default info)"`
	TemplatesDir  string `envconfig:"TEMPLATES_DIR" desc:"custom XML template directory (optional)"`
	TLSMinVersion string `envconfig:"MIN_VERSION" desc:"minimum TLS version: TLSv1.2|TLSv1.3 (default TLSv1.2)"`

	TLSVerify               *bool `envconfig:"VERIFY" desc:"verify the LDAP server certificate; false is rejected (default true)"`
	TLSStartTLS             *bool `envconfig:"START_TLS" desc:"use StartTLS for ldap:// (default true; must be off with ldaps://)"`
	TLSCertExpiryFailClosed *bool `envconfig:"CERT_EXPIRY_FAIL_CLOSED" desc:"refuse startup when the LDAP certificate is expired (default true)"`

	SchemaCompat          string         `envconfig:"SCHEMA_COMPAT" desc:"schema flavor: openldap|389ds (default openldap)"`
	TreeFilter            string         `envconfig:"TREE_FILTER" desc:"tree browse filter (default (objectClass=*))"`
	PoolSize              int            `envconfig:"POOL_SIZE" desc:"LDAP connection pool size, 1..100 (default 8)"`
	PasswordPlainOverride bool           `envconfig:"PASSWORD_PLAIN_OVERRIDE" desc:"allow {PLAIN} password writes (default false)"`
	PasswordScheme        passwordScheme `envconfig:"PASSWORD_SCHEME" desc:"RFC 2307 write scheme; empty = engine default SSHA512"`

	SessionTimeoutMinutes         int    `envconfig:"TIMEOUT_MINUTES" desc:"session idle timeout in minutes, 5..240 (default 30)"`
	SessionAbsoluteTimeoutMinutes int    `envconfig:"ABSOLUTE_TIMEOUT_MINUTES" desc:"session absolute timeout in minutes, 30..1440 (default 480)"`
	SessionExpiredAction          string `envconfig:"EXPIRED_ACTION" desc:"session expiry action: retry_bind|redirect_to_login (default retry_bind)"`
	SessionDBPath                 string `envconfig:"DB_PATH" desc:"sessions.db path (default /var/lib/ldapact/sessions.db; falls back to ~/.local/state/ldapact/sessions.db when /var/lib/ldapact is absent)"`
}

// Load reads, defaults, and validates the server profile from LDAPADM_*
// environment variables. Unknown LDAPADM_* variables are ignored; a
// set-but-empty value is parsed as-is — numeric/boolean fields fail at parse
// time naming the variable, string fields fall through to Validate.
func Load() (*Config, error) {
	var env envFields
	if err := envconfig.Process(envPrefix, &env); err != nil {
		return nil, fmt.Errorf("parse env config: %w", err)
	}
	cfg := env.toConfig()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// toConfig maps the flat envconfig view onto the nested Config shape.
func (e envFields) toConfig() Config {
	var c Config
	c.Server.Listen = e.Listen
	c.LDAP.URL = e.URL
	c.LDAP.BaseDN = e.BaseDN
	c.LDAP.BindDN = e.BindDN
	c.LDAP.AutoNumberDN = e.AutoNumberDN
	c.LDAP.TLS.MinVersion = e.TLSMinVersion
	c.LDAP.TLS.Verify = e.TLSVerify
	c.LDAP.TLS.StartTLS = e.TLSStartTLS
	c.LDAP.TLS.CertExpiryFailClosed = e.TLSCertExpiryFailClosed
	c.LDAP.SchemaCompat = e.SchemaCompat
	c.LDAP.TreeFilter = e.TreeFilter
	c.LDAP.PoolSize = e.PoolSize
	c.LDAP.PasswordPlainOverride = e.PasswordPlainOverride
	c.LDAP.PasswordScheme = string(e.PasswordScheme)
	c.Session.TimeoutMinutes = e.SessionTimeoutMinutes
	c.Session.AbsoluteTimeoutMinutes = e.SessionAbsoluteTimeoutMinutes
	c.Session.ExpiredAction = e.SessionExpiredAction
	c.Session.DBPath = e.SessionDBPath
	c.LogLevel = e.LogLevel
	c.TemplatesDir = e.TemplatesDir
	return c
}

// Validate applies defaults and enforces the R12/KTD constraints. It is safe
// to call more than once.
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListen
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		c.LogLevel = strings.ToLower(c.LogLevel)
	default:
		return fmt.Errorf("log_level must be debug|info|warn|error, got %q", c.LogLevel)
	}

	if err := c.validateLDAP(); err != nil {
		return err
	}
	if err := c.validateSession(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateLDAP() error {
	u, err := url.Parse(c.LDAP.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return errors.New("ldap.url must be ldap://host:port or ldaps://host:port")
	}
	if c.LDAP.BaseDN == "" {
		return errors.New("ldap.base_dn is required")
	}
	if c.LDAP.BindDN == "" {
		return errors.New("ldap.bind_dn is required")
	}
	if c.LDAP.SchemaCompat == "" {
		c.LDAP.SchemaCompat = DefaultSchemaCompat
	}
	if c.LDAP.TreeFilter == "" {
		c.LDAP.TreeFilter = DefaultTreeFilter
	}
	if c.LDAP.PoolSize == 0 {
		c.LDAP.PoolSize = DefaultPoolSize
	}
	if c.LDAP.PoolSize < 1 || c.LDAP.PoolSize > 100 {
		return fmt.Errorf("ldap.pool_size must be 1..100, got %d", c.LDAP.PoolSize)
	}
	if s := c.LDAP.PasswordScheme; s != "" {
		switch s {
		case "SSHA512", "SSHA256", "SSHA384", "SSHA", "SHA512", "SHA256", "SHA384", "SHA", "ARGON2ID", "MD4":
		default:
			return fmt.Errorf("ldap.password_scheme %q is not in the write allowlist", c.LDAP.PasswordScheme)
		}
	}

	t := &c.LDAP.TLS
	if t.MinVersion == "" {
		t.MinVersion = DefaultTLSMinVersion
	}
	switch t.MinVersion {
	case "TLSv1.2", "TLSv1.3":
	default:
		return fmt.Errorf("tls.min_version must be TLSv1.2 or TLSv1.3, got %q", t.MinVersion)
	}
	if t.Verify == nil {
		v := true
		t.Verify = &v
	}
	if !*t.Verify {
		return errors.New("tls.verify=off is rejected (KTD 10): certificate verification is mandatory")
	}
	if t.CertExpiryFailClosed == nil {
		v := true
		t.CertExpiryFailClosed = &v
	}
	if u.Scheme == "ldaps" {
		if t.StartTLS != nil && *t.StartTLS {
			return errors.New("tls.start_tls cannot be enabled with ldaps:// (use one or the other)")
		}
	} else if t.StartTLS == nil {
		v := true
		t.StartTLS = &v
	}
	return nil
}

func (c *Config) validateSession() error {
	s := &c.Session
	if s.TimeoutMinutes == 0 {
		s.TimeoutMinutes = DefaultIdleTimeoutMinutes
	}
	if s.TimeoutMinutes < 5 || s.TimeoutMinutes > 240 {
		return fmt.Errorf("session.timeout_minutes must be 5..240, got %d", s.TimeoutMinutes)
	}
	if s.AbsoluteTimeoutMinutes == 0 {
		s.AbsoluteTimeoutMinutes = DefaultAbsoluteTimeoutHours * 60
	}
	if s.AbsoluteTimeoutMinutes < 30 || s.AbsoluteTimeoutMinutes > 1440 {
		return fmt.Errorf("session.absolute_timeout_minutes must be 30..1440, got %d", s.AbsoluteTimeoutMinutes)
	}
	if s.ExpiredAction == "" {
		s.ExpiredAction = ExpiredActionRetryBind
	}
	switch s.ExpiredAction {
	case ExpiredActionRetryBind, ExpiredActionRedirectLogin:
	default:
		return fmt.Errorf("session.expired_action must be %q or %q, got %q",
			ExpiredActionRetryBind, ExpiredActionRedirectLogin, s.ExpiredAction)
	}
	if s.DBPath == "" {
		s.DBPath = DefaultSessionDBPath
	}
	s.DBPath = resolveSessionDBPath(s.DBPath)
	return nil
}

// Usage writes the envconfig reference (key, type, default, required,
// description) for the LDAPADM_* contract to w. The defaults shown come from
// the desc tags; the authoritative defaults and validation live in Validate.
func Usage(w io.Writer) error {
	return envconfig.Usagef(envPrefix, &envFields{}, w, envconfig.DefaultTableFormat)
}
