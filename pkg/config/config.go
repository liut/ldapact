// Package config loads and validates the ldapact v1 server profile (R12).
//
// The profile is read from a YAML file with strict known-field checking:
// unknown keys fail the parse. Secrets (bind password, auto-number password)
// are never accepted as YAML values; they are resolved at startup through the
// secret resolver chain implemented in secret.go.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Env var names. Secrets use the resolver chain in secret.go; the non-secret
// profile fields below override YAML when set to a non-empty value (R12).
const (
	BindPasswordEnv       = "LDAPADM_BIND_PASSWORD"
	AutoNumberPasswordEnv = "LDAPADM_AUTO_NUMBER_PASSWORD"

	ListenEnv = "LDAPADM_LISTEN"
	URLEnv    = "LDAPADM_URL"
	BaseDNEnv = "LDAPADM_BASE_DN"
	BindDNEnv = "LDAPADM_BIND_DN"
)

// Defaults (KTD 3, 5, 8; R2, R13).
const (
	DefaultListen               = "127.0.0.1:8080"
	DefaultIdleTimeoutMinutes   = 30
	DefaultAbsoluteTimeoutHours = 8
	DefaultPoolSize             = 8
	DefaultTreeFilter           = "(objectClass=*)"
	DefaultSchemaCompat         = "openldap"
	DefaultLogLevel             = "info"
	DefaultSessionDBPath        = "/var/lib/ldapact/sessions.db"
	DefaultTLSMinVersion        = "TLSv1.2"
)

// Session expiry actions (R13).
const (
	ExpiredActionRetryBind     = "retry_bind"
	ExpiredActionRedirectLogin = "redirect_to_login"
)

// TLSConfig controls the LDAP TLS posture (KTD 10). verify=off is rejected at
// parse time, StartTLS failures are fatal at runtime, and an expired server
// certificate refuses startup.
type TLSConfig struct {
	MinVersion           string `yaml:"min_version"`
	Verify               *bool  `yaml:"verify"`
	StartTLS             *bool  `yaml:"start_tls"`
	CertExpiryFailClosed *bool  `yaml:"cert_expiry_fail_closed"`
}

// LDAPConfig is the single-server profile (R12).
type LDAPConfig struct {
	URL          string    `yaml:"url"`
	BaseDN       string    `yaml:"base_dn"`
	BindDN       string    `yaml:"bind_dn"`
	AutoNumberDN string    `yaml:"auto_number_dn"`
	TLS          TLSConfig `yaml:"tls"`
	SchemaCompat string    `yaml:"schema_compat"`
	TreeFilter   string    `yaml:"tree_filter"`
	PoolSize     int       `yaml:"pool_size"`
	// PasswordPlainOverride permits {PLAIN} writes (KTD 6). Off by default;
	// enabling it emits a structured warn on every plaintext write.
	PasswordPlainOverride bool `yaml:"password_plain_override"`
	// PasswordScheme is the RFC 2307 write scheme (default SSHA512 per KTD 6).
	// Some directory builds only support legacy schemes ({SSHA} et al.); set
	// this to one of the write-allowlist names to match the server.
	PasswordScheme string `yaml:"password_scheme"`
}

// SessionConfig carries the cookie/session security settings (R13, KTD 8).
type SessionConfig struct {
	TimeoutMinutes         int    `yaml:"timeout_minutes"`
	AbsoluteTimeoutMinutes int    `yaml:"absolute_timeout_minutes"`
	ExpiredAction          string `yaml:"expired_action"`
	DBPath                 string `yaml:"db_path"`
}

// ServerConfig is the HTTP listener section.
type ServerConfig struct {
	Listen string `yaml:"listen"`
}

// Config is the v1 server profile (R16: a plain struct, not an interface).
// BindPassword and AutoNumberPassword are runtime-only values filled by
// ResolveSecrets; they are never parsed from YAML.
type Config struct {
	Server       ServerConfig  `yaml:"server"`
	LDAP         LDAPConfig    `yaml:"ldap"`
	Session      SessionConfig `yaml:"session"`
	LogLevel     string        `yaml:"log_level"`
	TemplatesDir string        `yaml:"templates_dir"`

	BindPassword       string `yaml:"-"`
	AutoNumberPassword string `yaml:"-"`
}

// Load reads, defaults, and validates a config file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.ApplyEnv()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

// ApplyEnv lets environment variables override the YAML profile for the four
// runtime fields: LDAPADM_LISTEN, LDAPADM_URL, LDAPADM_BASE_DN, and
// LDAPADM_BIND_DN. An unset or empty variable leaves the YAML value (or its
// default) untouched, so a blank env var never clears a configured value.
// Call before Validate; Load already does.
func (c *Config) ApplyEnv() {
	if v := os.Getenv(ListenEnv); v != "" {
		c.Server.Listen = v
	}
	if v := os.Getenv(URLEnv); v != "" {
		c.LDAP.URL = v
	}
	if v := os.Getenv(BaseDNEnv); v != "" {
		c.LDAP.BaseDN = v
	}
	if v := os.Getenv(BindDNEnv); v != "" {
		c.LDAP.BindDN = v
	}
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
	if s := strings.ToUpper(strings.TrimSpace(c.LDAP.PasswordScheme)); s != "" {
		switch s {
		case "SSHA512", "SSHA256", "SSHA384", "SSHA", "SHA512", "SHA256", "SHA384", "SHA", "ARGON2ID", "MD4":
			c.LDAP.PasswordScheme = s
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
	return nil
}
