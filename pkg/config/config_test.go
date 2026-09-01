package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/liut/ldapact/pkg/logging"
)

// TestMain keeps the suite hermetic: ambient LDAPADM_* vars from the
// developer's shell (for example LDAPADM_TEST_* used by the integration
// harness) would otherwise leak into Load(). Tests that need a variable set
// it explicitly with t.Setenv.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "LDAPADM_") {
			continue
		}
		name, _, _ := strings.Cut(kv, "=")
		_ = os.Unsetenv(name)
	}
	os.Exit(m.Run())
}

// Non-secret LDAPADM_* contract names (R12), test-side. Runtime code never
// reads them: envconfig resolves the short envFields tags against envPrefix
// and Validate applies defaults. They stay here as the canonical documented
// names used by the tests and pinned to the tags by TestEnvTagsMatchConstants.
const (
	ListenEnv       = "LDAPADM_LISTEN"
	URLEnv          = "LDAPADM_URL"
	BaseDNEnv       = "LDAPADM_BASE_DN"
	BindDNEnv       = "LDAPADM_BIND_DN"
	AutoNumberDNEnv = "LDAPADM_AUTO_NUMBER_DN"
	LogLevelEnv     = "LDAPADM_LOG_LEVEL"
	TemplatesDirEnv = "LDAPADM_TEMPLATES_DIR"

	TLSMinVersionEnv           = "LDAPADM_MIN_VERSION"
	TLSVerifyEnv               = "LDAPADM_VERIFY"
	TLSStartTLSEnv             = "LDAPADM_START_TLS"
	TLSCertExpiryFailClosedEnv = "LDAPADM_CERT_EXPIRY_FAIL_CLOSED"

	SchemaCompatEnv          = "LDAPADM_SCHEMA_COMPAT"
	TreeFilterEnv            = "LDAPADM_TREE_FILTER"
	PoolSizeEnv              = "LDAPADM_POOL_SIZE"
	PasswordPlainOverrideEnv = "LDAPADM_PASSWORD_PLAIN_OVERRIDE"
	PasswordSchemeEnv        = "LDAPADM_PASSWORD_SCHEME"

	SessionTimeoutMinutesEnv         = "LDAPADM_TIMEOUT_MINUTES"
	SessionAbsoluteTimeoutMinutesEnv = "LDAPADM_ABSOLUTE_TIMEOUT_MINUTES"
	SessionExpiredActionEnv          = "LDAPADM_EXPIRED_ACTION"
	SessionDBPathEnv                 = "LDAPADM_DB_PATH"
	SessionStoreEnv                  = "LDAPADM_SESSION_STORE"
	RedisURLEnv                      = "LDAPADM_REDIS_URL"
	RedisDBEnv                       = "LDAPADM_REDIS_DB"
	ServersEnv                       = "LDAPADM_SERVERS"
)

// setEnv sets several env vars for the duration of the test.
func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func minimalEnv() map[string]string {
	return map[string]string{
		URLEnv:      "ldap://127.0.0.1:389",
		BaseDNEnv:   "dc=example,dc=com",
		BindDNEnv:   "cn=admin,dc=example,dc=com",
		RedisURLEnv: "redis://127.0.0.1:6379",
	}
}

func TestLoadMinimalEnvDefaults(t *testing.T) {
	setEnv(t, minimalEnv())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != DefaultListen {
		t.Errorf("listen = %q, want %q", cfg.Server.Listen, DefaultListen)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("log_level = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}
	if cfg.LDAP.SchemaCompat != DefaultSchemaCompat {
		t.Errorf("schema_compat = %q, want %q", cfg.LDAP.SchemaCompat, DefaultSchemaCompat)
	}
	if cfg.LDAP.TreeFilter != DefaultTreeFilter {
		t.Errorf("tree_filter = %q, want %q", cfg.LDAP.TreeFilter, DefaultTreeFilter)
	}
	if cfg.LDAP.PoolSize != DefaultPoolSize {
		t.Errorf("pool_size = %d, want %d", cfg.LDAP.PoolSize, DefaultPoolSize)
	}
	if cfg.LDAP.TLS.MinVersion != DefaultTLSMinVersion {
		t.Errorf("tls.min_version = %q, want %q", cfg.LDAP.TLS.MinVersion, DefaultTLSMinVersion)
	}
	if cfg.LDAP.TLS.Verify == nil || !*cfg.LDAP.TLS.Verify {
		t.Error("tls.verify should default to true")
	}
	if cfg.LDAP.TLS.StartTLS == nil || !*cfg.LDAP.TLS.StartTLS {
		t.Error("tls.start_tls should default to true for ldap://")
	}
	if cfg.LDAP.TLS.CertExpiryFailClosed == nil || !*cfg.LDAP.TLS.CertExpiryFailClosed {
		t.Error("tls.cert_expiry_fail_closed should default to true")
	}
	if cfg.Session.TimeoutMinutes != DefaultIdleTimeoutMinutes {
		t.Errorf("session.timeout_minutes = %d, want %d", cfg.Session.TimeoutMinutes, DefaultIdleTimeoutMinutes)
	}
	if cfg.Session.AbsoluteTimeoutMinutes != DefaultAbsoluteTimeoutHours*60 {
		t.Errorf("session.absolute_timeout_minutes = %d, want %d", cfg.Session.AbsoluteTimeoutMinutes, DefaultAbsoluteTimeoutHours*60)
	}
	if cfg.Session.ExpiredAction != ExpiredActionRedirectLogin {
		t.Errorf("session.expired_action = %q, want %q", cfg.Session.ExpiredAction, ExpiredActionRedirectLogin)
	}
	if cfg.Session.Store != DefaultSessionStore {
		t.Errorf("session.store = %q, want %q", cfg.Session.Store, DefaultSessionStore)
	}
	if cfg.Session.RedisURL != "redis://127.0.0.1:6379" {
		t.Errorf("session.redis_url = %q", cfg.Session.RedisURL)
	}
	if cfg.Session.DBPath != resolveSessionDBPath(DefaultSessionDBPath) {
		t.Errorf("session.db_path = %q, want %q", cfg.Session.DBPath, resolveSessionDBPath(DefaultSessionDBPath))
	}
}

func TestLoadFullEnv(t *testing.T) {
	setEnv(t, map[string]string{
		ListenEnv:                        "0.0.0.0:8443",
		URLEnv:                           "ldap://ldap.example.com:389",
		BaseDNEnv:                        "dc=example,dc=com",
		BindDNEnv:                        "cn=admin,dc=example,dc=com",
		AutoNumberDNEnv:                  "cn=autonum,ou=svc,dc=example,dc=com",
		TLSMinVersionEnv:                 "TLSv1.3",
		TLSVerifyEnv:                     "true",
		TLSStartTLSEnv:                   "true",
		TLSCertExpiryFailClosedEnv:       "false",
		SchemaCompatEnv:                  "389ds",
		TreeFilterEnv:                    "(objectClass=inetOrgPerson)",
		PoolSizeEnv:                      "16",
		PasswordPlainOverrideEnv:         "true",
		PasswordSchemeEnv:                "SSHA512",
		SessionTimeoutMinutesEnv:         "45",
		SessionAbsoluteTimeoutMinutesEnv: "720",
		SessionExpiredActionEnv:          "redirect_to_login",
		SessionDBPathEnv:                 "/tmp/ldapact-sessions.db",
		SessionStoreEnv:                  "bbolt",
		RedisDBEnv:                       "3",
		LogLevelEnv:                      "debug",
		TemplatesDirEnv:                  "/etc/ldapact/templates",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "0.0.0.0:8443" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.LDAP.AutoNumberDN != "cn=autonum,ou=svc,dc=example,dc=com" {
		t.Errorf("auto_number_dn = %q", cfg.LDAP.AutoNumberDN)
	}
	if cfg.LDAP.TLS.MinVersion != "TLSv1.3" {
		t.Errorf("min_version = %q", cfg.LDAP.TLS.MinVersion)
	}
	if cfg.LDAP.TLS.Verify == nil || !*cfg.LDAP.TLS.Verify {
		t.Error("tls.verify should be true")
	}
	if cfg.LDAP.TLS.StartTLS == nil || !*cfg.LDAP.TLS.StartTLS {
		t.Error("tls.start_tls should be true")
	}
	if cfg.LDAP.TLS.CertExpiryFailClosed == nil || *cfg.LDAP.TLS.CertExpiryFailClosed {
		t.Error("tls.cert_expiry_fail_closed should be false")
	}
	if cfg.LDAP.SchemaCompat != "389ds" {
		t.Errorf("schema_compat = %q", cfg.LDAP.SchemaCompat)
	}
	if cfg.LDAP.TreeFilter != "(objectClass=inetOrgPerson)" {
		t.Errorf("tree_filter = %q", cfg.LDAP.TreeFilter)
	}
	if cfg.LDAP.PoolSize != 16 {
		t.Errorf("pool_size = %d", cfg.LDAP.PoolSize)
	}
	if !cfg.LDAP.PasswordPlainOverride {
		t.Error("password_plain_override should be true")
	}
	if cfg.LDAP.PasswordScheme != "SSHA512" {
		t.Errorf("password_scheme = %q", cfg.LDAP.PasswordScheme)
	}
	if cfg.Session.TimeoutMinutes != 45 || cfg.Session.AbsoluteTimeoutMinutes != 720 {
		t.Errorf("session timeouts = %d/%d", cfg.Session.TimeoutMinutes, cfg.Session.AbsoluteTimeoutMinutes)
	}
	if cfg.Session.ExpiredAction != ExpiredActionRedirectLogin {
		t.Errorf("expired_action = %q", cfg.Session.ExpiredAction)
	}
	if cfg.Session.Store != SessionStoreBbolt {
		t.Errorf("session.store = %q, want bbolt", cfg.Session.Store)
	}
	if cfg.Session.RedisDB != 3 {
		t.Errorf("redis_db = %d, want 3", cfg.Session.RedisDB)
	}
	if cfg.Session.DBPath != "/tmp/ldapact-sessions.db" {
		t.Errorf("db_path = %q", cfg.Session.DBPath)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log_level = %q", cfg.LogLevel)
	}
	if cfg.TemplatesDir != "/etc/ldapact/templates" {
		t.Errorf("templates_dir = %q", cfg.TemplatesDir)
	}
}

func TestLoadShippedEnvNames(t *testing.T) {
	// R6 regression: the four env names shipped before this migration are
	// unchanged.
	setEnv(t, map[string]string{
		ListenEnv:   "127.0.0.1:9999",
		URLEnv:      "ldap://127.0.0.1:389",
		BaseDNEnv:   "dc=shipped,dc=com",
		BindDNEnv:   "cn=admin,dc=shipped,dc=com",
		RedisURLEnv: "redis://127.0.0.1:6379",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9999" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.LDAP.URL != "ldap://127.0.0.1:389" {
		t.Errorf("url = %q", cfg.LDAP.URL)
	}
	if cfg.LDAP.BaseDN != "dc=shipped,dc=com" {
		t.Errorf("base_dn = %q", cfg.LDAP.BaseDN)
	}
	if cfg.LDAP.BindDN != "cn=admin,dc=shipped,dc=com" {
		t.Errorf("bind_dn = %q", cfg.LDAP.BindDN)
	}
}

func TestLoadEmptyStringEnvUsesDefaults(t *testing.T) {
	// String fields flow through envconfig as empty and Validate applies
	// the defaults (or leaves the field empty). Numeric/boolean fields fail
	// at parse time instead (TestLoadEmptyIntBoolEnvParseErrors).
	setEnv(t, map[string]string{
		URLEnv:                  "ldap://127.0.0.1:389",
		BaseDNEnv:               "dc=example,dc=com",
		BindDNEnv:               "cn=admin,dc=example,dc=com",
		ListenEnv:               "",
		AutoNumberDNEnv:         "",
		TLSMinVersionEnv:        "",
		SchemaCompatEnv:         "",
		TreeFilterEnv:           "",
		PasswordSchemeEnv:       "",
		SessionExpiredActionEnv: "",
		SessionDBPathEnv:        "",
		SessionStoreEnv:         "",
		RedisURLEnv:             "redis://127.0.0.1:6379",
		LogLevelEnv:             "",
		TemplatesDirEnv:         "",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != DefaultListen {
		t.Errorf("listen = %q, want default", cfg.Server.Listen)
	}
	if cfg.LDAP.AutoNumberDN != "" {
		t.Errorf("auto_number_dn = %q, want empty", cfg.LDAP.AutoNumberDN)
	}
	if cfg.LDAP.TLS.MinVersion != DefaultTLSMinVersion {
		t.Errorf("tls.min_version = %q, want default", cfg.LDAP.TLS.MinVersion)
	}
	if cfg.LDAP.SchemaCompat != DefaultSchemaCompat {
		t.Errorf("schema_compat = %q, want default", cfg.LDAP.SchemaCompat)
	}
	if cfg.LDAP.TreeFilter != DefaultTreeFilter {
		t.Errorf("tree_filter = %q, want default", cfg.LDAP.TreeFilter)
	}
	if cfg.LDAP.PasswordScheme != "" {
		t.Errorf("password_scheme = %q, want empty", cfg.LDAP.PasswordScheme)
	}
	if cfg.Session.ExpiredAction != ExpiredActionRedirectLogin {
		t.Errorf("session.expired_action = %q, want default", cfg.Session.ExpiredAction)
	}
	if cfg.Session.Store != DefaultSessionStore {
		t.Errorf("session.store = %q, want default redis", cfg.Session.Store)
	}
	if cfg.Session.DBPath != resolveSessionDBPath(DefaultSessionDBPath) {
		t.Errorf("session.db_path = %q, want default %q", cfg.Session.DBPath, resolveSessionDBPath(DefaultSessionDBPath))
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("log_level = %q, want default", cfg.LogLevel)
	}
	if cfg.TemplatesDir != "" {
		t.Errorf("templates_dir = %q, want empty", cfg.TemplatesDir)
	}
}

func TestLoadEmptyIntBoolEnvParseErrors(t *testing.T) {
	// An explicitly empty numeric/boolean value is a configuration error:
	// envconfig cannot convert "" and the parse error names the variable.
	cases := []struct {
		name string
		env  string
	}{
		{"pool size", PoolSizeEnv},
		{"verify", TLSVerifyEnv},
		{"start tls", TLSStartTLSEnv},
		{"cert expiry fail closed", TLSCertExpiryFailClosedEnv},
		{"password plain override", PasswordPlainOverrideEnv},
		{"idle timeout", SessionTimeoutMinutesEnv},
		{"absolute timeout", SessionAbsoluteTimeoutMinutesEnv},
		{"redis db", RedisDBEnv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, minimalEnv())
			t.Setenv(tc.env, "")
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("want parse error naming %s, got %v", tc.env, err)
			}
		})
	}
}

func TestResolveSessionDBPath(t *testing.T) {
	// Custom paths are always kept as configured.
	if got := resolveSessionDBPathFor("/srv/ldapact/sessions.db", "/var/lib/ldapact", "/tmp/fallback.db"); got != "/srv/ldapact/sessions.db" {
		t.Errorf("custom path: got %q, want unchanged", got)
	}
	// The classic default wins when the directory exists.
	existing := t.TempDir()
	if got := resolveSessionDBPathFor(DefaultSessionDBPath, existing, "/tmp/fallback.db"); got != DefaultSessionDBPath {
		t.Errorf("existing dir: got %q, want %q", got, DefaultSessionDBPath)
	}
	// The classic default switches to the fallback when the directory is
	// missing — whether the variable was unset or explicitly set to the
	// default value.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if got := resolveSessionDBPathFor(DefaultSessionDBPath, missing, "/tmp/fallback.db"); got != "/tmp/fallback.db" {
		t.Errorf("missing dir: got %q, want fallback", got)
	}
}

func TestLoadExplicitDefaultDBPath(t *testing.T) {
	// An explicitly configured value equal to the built-in default must get
	// the same fallback treatment as an unset variable.
	setEnv(t, minimalEnv())
	t.Setenv(SessionDBPathEnv, DefaultSessionDBPath)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Session.DBPath != resolveSessionDBPath(DefaultSessionDBPath) {
		t.Errorf("session.db_path = %q, want %q", cfg.Session.DBPath, resolveSessionDBPath(DefaultSessionDBPath))
	}
}

func TestDefaultSessionDBPathFallback(t *testing.T) {
	// The classic /var/lib/ldapact path wins when the directory exists.
	existing := t.TempDir()
	if got := defaultSessionDBPathFor(existing, "/tmp/fallback.db"); got != DefaultSessionDBPath {
		t.Errorf("existing dir: got %q, want %q", got, DefaultSessionDBPath)
	}
	// A missing directory (or a non-directory path) selects the fallback.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if got := defaultSessionDBPathFor(missing, "/tmp/fallback.db"); got != "/tmp/fallback.db" {
		t.Errorf("missing dir: got %q, want fallback", got)
	}
	notADir := filepath.Join(t.TempDir(), "file.db")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := defaultSessionDBPathFor(notADir, "/tmp/fallback.db"); got != "/tmp/fallback.db" {
		t.Errorf("non-directory path: got %q, want fallback", got)
	}
}

func TestFallbackSessionDBPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("no home directory: %v", err)
	}
	want := filepath.Join(home, ".local", "state", "ldapact", "sessions.db")
	if got := FallbackSessionDBPath(); got != want {
		t.Errorf("FallbackSessionDBPath = %q, want %q", got, want)
	}
}

func TestEnvPtrsStayNilWhenUnset(t *testing.T) {
	// envconfig leaves absent bool pointers untouched; Validate fills the
	// true defaults afterward.
	setEnv(t, minimalEnv())
	var env envFields
	if err := envconfig.Process(envPrefix, &env); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if env.TLSVerify != nil || env.TLSStartTLS != nil || env.TLSCertExpiryFailClosed != nil {
		t.Error("unset bool pointers should stay nil before Validate")
	}
	cfg := env.toConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.LDAP.TLS.Verify == nil || !*cfg.LDAP.TLS.Verify {
		t.Error("tls.verify should default to true")
	}
	if cfg.LDAP.TLS.StartTLS == nil || !*cfg.LDAP.TLS.StartTLS {
		t.Error("tls.start_tls should default to true")
	}
	if cfg.LDAP.TLS.CertExpiryFailClosed == nil || !*cfg.LDAP.TLS.CertExpiryFailClosed {
		t.Error("tls.cert_expiry_fail_closed should default to true")
	}
}

func TestValidateStartTLSExplicitFalse(t *testing.T) {
	setEnv(t, map[string]string{
		URLEnv:         "ldap://127.0.0.1:389",
		BaseDNEnv:      "dc=example,dc=com",
		BindDNEnv:      "cn=admin,dc=example,dc=com",
		TLSStartTLSEnv: "false",
		RedisURLEnv:    "redis://127.0.0.1:6379",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.TLS.StartTLS == nil || *cfg.LDAP.TLS.StartTLS {
		t.Error("start_tls should remain explicitly false (plaintext dev mode)")
	}
}

func TestLoadParseErrors(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		value string
		want  string
	}{
		{"pool size", PoolSizeEnv, "abc", "LDAPADM_POOL_SIZE"},
		{"start tls", TLSStartTLSEnv, "maybe", "LDAPADM_START_TLS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, minimalEnv())
			t.Setenv(tc.env, tc.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want parse error naming %s, got %v", tc.want, err)
			}
		})
	}
}

func TestLoadValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"bad url scheme", map[string]string{URLEnv: "http://127.0.0.1:389"}, "ldap.url"},
		{"bad url host", map[string]string{URLEnv: "ldap://"}, "ldap.url"},
		{"missing base dn", map[string]string{BaseDNEnv: ""}, "base_dn"},
		{"missing bind dn", map[string]string{BindDNEnv: ""}, "bind_dn"},
		{"min version too low", map[string]string{TLSMinVersionEnv: "TLSv1.1"}, "min_version"},
		{"verify off rejected", map[string]string{TLSVerifyEnv: "false"}, "verify"},
		{"ldaps plus starttls", map[string]string{URLEnv: "ldaps://127.0.0.1:636", TLSStartTLSEnv: "true"}, "start_tls"},
		{"pool size invalid", map[string]string{PoolSizeEnv: "500"}, "pool_size"},
		{"log level invalid", map[string]string{LogLevelEnv: "loud"}, "log_level"},
		{"idle timeout too small", map[string]string{SessionTimeoutMinutesEnv: "1"}, "timeout_minutes"},
		{"absolute timeout too large", map[string]string{SessionAbsoluteTimeoutMinutesEnv: "9999"}, "absolute_timeout_minutes"},
		{"expired action invalid", map[string]string{SessionExpiredActionEnv: "explode"}, "expired_action"},
		{"password scheme invalid", map[string]string{PasswordSchemeEnv: "ROT13"}, "password_scheme"},
		{"expired action retry_bind removed", map[string]string{SessionExpiredActionEnv: "retry_bind"}, "retry_bind"},
		{"session store invalid", map[string]string{SessionStoreEnv: "sqlite"}, "session.store"},
		{"redis store without url", map[string]string{SessionStoreEnv: "redis", RedisURLEnv: ""}, "redis_url"},
		{"redis url bad scheme", map[string]string{SessionStoreEnv: "redis", RedisURLEnv: "http://127.0.0.1:6379"}, "redis_url"},
		{"servers and url conflict", map[string]string{ServersEnv: "ldap://a.example:389"}, "mutually exclusive"},
		{"invalid replica url", map[string]string{URLEnv: "", ServersEnv: "http://a.example:389"}, "servers"},
		{"empty replica element", map[string]string{URLEnv: "", ServersEnv: "ldap://a.example:389,,"}, "servers"},
		{"no url and no servers", map[string]string{URLEnv: ""}, "required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, minimalEnv())
			setEnv(t, tc.set)
			_, err := Load()
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadUnprefixedVarsIgnored(t *testing.T) {
	// When the prefixed key is present it wins; the bare name is inert
	// because envconfig's unprefixed fallback never triggers.
	setEnv(t, map[string]string{
		URLEnv:      "ldap://127.0.0.1:389",
		BaseDNEnv:   "dc=example,dc=com",
		BindDNEnv:   "cn=admin,dc=example,dc=com",
		"URL":       "ldaps://wrong.example.com:636",
		RedisURLEnv: "redis://127.0.0.1:6379",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.URL != "ldap://127.0.0.1:389" {
		t.Errorf("url = %q, want the LDAPADM_ value", cfg.LDAP.URL)
	}
}

func TestLoadBareNameFallback(t *testing.T) {
	// Short-tag parsing makes envconfig fall back to the bare tag name when
	// the prefixed key is missing (documented library behavior); the value
	// is read as-is.
	setEnv(t, map[string]string{
		BaseDNEnv:   "dc=example,dc=com",
		BindDNEnv:   "cn=admin,dc=example,dc=com",
		"URL":       "ldap://bare.example.com:389",
		RedisURLEnv: "redis://127.0.0.1:6379",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.URL != "ldap://bare.example.com:389" {
		t.Errorf("url = %q, want the bare URL fallback value", cfg.LDAP.URL)
	}
}

func TestLoadEmptyPrefixedVarBlocksBareFallback(t *testing.T) {
	// A set-but-empty prefixed key parses as empty (ok=true), so envconfig
	// never consults the bare name; the empty value then fails validation.
	setEnv(t, minimalEnv())
	t.Setenv(URLEnv, "")
	t.Setenv("URL", "ldap://bare.example.com:389")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "ldap.url") {
		t.Fatalf("want ldap.url validation error, got %v", err)
	}
}

func TestLoadBareNameFallbackReadsBool(t *testing.T) {
	// The fallback applies to non-string fields too: a bare VERIFY=false is
	// parsed and then rejected by Validate, proving it was consumed.
	setEnv(t, minimalEnv())
	t.Setenv("VERIFY", "false")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("want verify validation error from bare fallback, got %v", err)
	}
}

func TestLoadIgnoresSecretVars(t *testing.T) {
	// R3: secrets are never parsed by envconfig; the resolver chain fills
	// them later. Load must succeed with the secret vars present and leave
	// the runtime fields empty.
	setEnv(t, map[string]string{
		URLEnv:           "ldap://127.0.0.1:389",
		BaseDNEnv:        "dc=example,dc=com",
		BindDNEnv:        "cn=admin,dc=example,dc=com",
		RedisURLEnv:      "redis://127.0.0.1:6379",
		BindPasswordEnv:  "s3cr3t",
		SessionKeyEnv:    "a2V5LWtleS1rZXkta2V5LWtleQ==",
		RedisPasswordEnv: "redis-s3cr3t",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BindPassword != "" {
		t.Errorf("bind password parsed by envconfig: %q", cfg.BindPassword)
	}
	if cfg.AutoNumberPassword != "" {
		t.Errorf("auto-number password parsed by envconfig: %q", cfg.AutoNumberPassword)
	}
	if cfg.SessionKey != "" {
		t.Errorf("session key parsed by envconfig: %q", cfg.SessionKey)
	}
	if cfg.RedisPassword != "" {
		t.Errorf("redis password parsed by envconfig: %q", cfg.RedisPassword)
	}
}

func TestPasswordSchemeNormalized(t *testing.T) {
	setEnv(t, minimalEnv())
	t.Setenv(PasswordSchemeEnv, "  ssha  ")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP.PasswordScheme != "SSHA" {
		t.Errorf("password_scheme = %q, want SSHA", cfg.LDAP.PasswordScheme)
	}
}

func TestEnvTagsMatchConstants(t *testing.T) {
	want := map[string]string{
		"Listen":                        ListenEnv,
		"URL":                           URLEnv,
		"BaseDN":                        BaseDNEnv,
		"BindDN":                        BindDNEnv,
		"AutoNumberDN":                  AutoNumberDNEnv,
		"LogLevel":                      LogLevelEnv,
		"TemplatesDir":                  TemplatesDirEnv,
		"TLSMinVersion":                 TLSMinVersionEnv,
		"TLSVerify":                     TLSVerifyEnv,
		"TLSStartTLS":                   TLSStartTLSEnv,
		"TLSCertExpiryFailClosed":       TLSCertExpiryFailClosedEnv,
		"SchemaCompat":                  SchemaCompatEnv,
		"TreeFilter":                    TreeFilterEnv,
		"PoolSize":                      PoolSizeEnv,
		"PasswordPlainOverride":         PasswordPlainOverrideEnv,
		"PasswordScheme":                PasswordSchemeEnv,
		"SessionTimeoutMinutes":         SessionTimeoutMinutesEnv,
		"SessionAbsoluteTimeoutMinutes": SessionAbsoluteTimeoutMinutesEnv,
		"SessionExpiredAction":          SessionExpiredActionEnv,
		"SessionDBPath":                 SessionDBPathEnv,
		"SessionStore":                  SessionStoreEnv,
		"RedisURL":                      RedisURLEnv,
		"RedisDB":                       RedisDBEnv,
		"Servers":                       ServersEnv,
	}
	typ := reflect.TypeOf(envFields{})
	for field, env := range want {
		sf, ok := typ.FieldByName(field)
		if !ok {
			t.Errorf("envFields has no field %s", field)
			continue
		}
		got := sf.Tag.Get("envconfig")
		if envPrefix+"_"+got != env {
			t.Errorf("%s tag = %q, want %q (with %s prefix)", field, got, env, envPrefix)
		}
	}
}

func TestUsageIncludesContract(t *testing.T) {
	var buf bytes.Buffer
	if err := Usage(&buf); err != nil {
		t.Fatalf("Usage: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"LDAPADM_LISTEN", "LDAPADM_URL", "LDAPADM_PASSWORD_SCHEME",
		"LDAPADM_TIMEOUT_MINUTES", "LDAPADM_DB_PATH",
		"LDAPADM_SESSION_STORE", "LDAPADM_REDIS_URL", "LDAPADM_REDIS_DB",
		"LDAPADM_SERVERS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output missing %s", want)
		}
	}
}

func TestLogLevelEnvMatchesLogging(t *testing.T) {
	if LogLevelEnv != logging.LevelEnv {
		t.Fatalf("config.LogLevelEnv = %q, logging.LevelEnv = %q", LogLevelEnv, logging.LevelEnv)
	}
}

func TestResolveSecretFromEnv(t *testing.T) {
	t.Setenv(BindPasswordEnv, "s3cr3t")
	got, err := ResolveSecret(BindPasswordEnv)
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("got %q", got)
	}
}

func TestResolveSecretFromFile(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(secretFile, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", secretFile)
	got, err := ResolveSecret(BindPasswordEnv)
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if got != "file-secret" {
		t.Errorf("got %q, want %q", got, "file-secret")
	}
}

func TestResolveSecretFileModeRejected(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(secretFile, []byte("leaky\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", secretFile)
	_, err := ResolveSecret(BindPasswordEnv)
	if err == nil || !strings.Contains(err.Error(), secretFile) || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("want mode error naming %s, got %v", secretFile, err)
	}
}

func TestResolveSecretFileMissing(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", filepath.Join(t.TempDir(), "absent"))
	if _, err := ResolveSecret(BindPasswordEnv); err == nil {
		t.Fatal("want error for missing secret file")
	}
}

func TestResolveSecretFileNotRegular(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", t.TempDir())
	if _, err := ResolveSecret(BindPasswordEnv); err == nil {
		t.Fatal("want error for directory secret path")
	}
}

func TestResolveSecretFileEmpty(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(secretFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", secretFile)
	if _, err := ResolveSecret(BindPasswordEnv); err == nil {
		t.Fatal("want error for empty secret file")
	}
}

func TestResolveSecretMissingFailsFast(t *testing.T) {
	// ldapact is a server process: missing secrets fail fast instead of
	// falling back to an interactive TTY prompt.
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", "")
	_, err := ResolveSecret(BindPasswordEnv)
	if err == nil {
		t.Fatal("want error when env and file are both absent (no TTY fallback)")
	}
	for _, want := range []string{BindPasswordEnv, BindPasswordEnv + "_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "TTY") || strings.Contains(err.Error(), "hunter2") {
		t.Error("error must not mention TTY or leak a secret value")
	}
}

func TestSecretFingerprint(t *testing.T) {
	if got := SecretFingerprint("supersecret123"); got != "supe..23" {
		t.Errorf("got %q", got)
	}
	if got := SecretFingerprint("ab"); got != "[redacted]" {
		t.Errorf("short secret leaked: %q", got)
	}
	if got := SecretFingerprint(""); got != "[empty]" {
		t.Errorf("empty secret: %q", got)
	}
}

func TestResolveSecrets(t *testing.T) {
	t.Setenv(SessionKeyEnv, "a2V5LWtleS1rZXkta2V5LWtleQ==")
	t.Setenv(BindPasswordEnv, "bind-secret") // deprecated: must be ignored
	t.Setenv(RedisPasswordEnv, "redis-secret")
	t.Setenv(AutoNumberPasswordEnv, "auto-secret")

	cfg := &Config{}
	cfg.Session.Store = SessionStoreRedis
	cfg.LDAP.AutoNumberDN = ""
	if err := cfg.ResolveSecrets(); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if cfg.SessionKey != "a2V5LWtleS1rZXkta2V5LWtleQ==" {
		t.Errorf("session key = %q", cfg.SessionKey)
	}
	if cfg.BindPassword != "" {
		t.Errorf("deprecated bind password still resolved: %q", cfg.BindPassword)
	}
	if cfg.RedisPassword != "redis-secret" {
		t.Errorf("redis password = %q", cfg.RedisPassword)
	}
	if cfg.AutoNumberPassword != "" {
		t.Errorf("auto-number password resolved without auto_number_dn: %q", cfg.AutoNumberPassword)
	}

	cfg.LDAP.AutoNumberDN = "cn=autonum,ou=svc,dc=example,dc=com"
	if err := cfg.ResolveSecrets(); err != nil {
		t.Fatalf("ResolveSecrets (auto): %v", err)
	}
	if cfg.AutoNumberPassword != "auto-secret" {
		t.Errorf("auto-number password = %q", cfg.AutoNumberPassword)
	}
}

func TestResolveSecretsSessionKeyMissing(t *testing.T) {
	t.Setenv(SessionKeyEnv, "")
	t.Setenv(SessionKeyEnv+"_FILE", "")
	cfg := &Config{Session: SessionConfig{Store: SessionStoreBbolt}}
	if err := cfg.ResolveSecrets(); err == nil {
		t.Fatal("want session-key resolution failure")
	} else if !strings.Contains(err.Error(), SessionKeyEnv) {
		t.Errorf("error %q must name the missing secret", err)
	}
}

func TestResolveSecretsRedisPasswordOptional(t *testing.T) {
	// Redis without auth: no env var, no file reference — the optional
	// resolver must return empty without failing.
	t.Setenv(SessionKeyEnv, "a2V5LWtleS1rZXkta2V5LWtleQ==")
	t.Setenv(RedisPasswordEnv, "")
	t.Setenv(RedisPasswordEnv+"_FILE", "")
	cfg := &Config{}
	cfg.Session.Store = SessionStoreRedis
	if err := cfg.ResolveSecrets(); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if cfg.RedisPassword != "" {
		t.Errorf("redis password = %q, want empty", cfg.RedisPassword)
	}
}

func TestLoadServersOnly(t *testing.T) {
	setEnv(t, map[string]string{
		ServersEnv:      "ldap://a.example:389,ldap://b.example:389",
		BaseDNEnv:       "dc=example,dc=com",
		BindDNEnv:       "cn=admin,dc=example,dc=com",
		RedisURLEnv:     "redis://127.0.0.1:6379",
		SessionStoreEnv: "bbolt",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.LDAP.Servers) != 2 {
		t.Fatalf("servers = %v, want 2 entries", cfg.LDAP.Servers)
	}
	if cfg.LDAP.Servers[0] != "ldap://a.example:389" || cfg.LDAP.Servers[1] != "ldap://b.example:389" {
		t.Errorf("servers = %v", cfg.LDAP.Servers)
	}
	if cfg.LDAP.URL != "" {
		t.Errorf("url should stay empty with servers set, got %q", cfg.LDAP.URL)
	}
	if cfg.LDAP.TLS.StartTLS == nil || !*cfg.LDAP.TLS.StartTLS {
		t.Error("start_tls should default to true for ldap:// replicas")
	}
}

func TestLoadMemoryStoreIgnoresRedis(t *testing.T) {
	setEnv(t, map[string]string{
		URLEnv:          "ldap://127.0.0.1:389",
		BaseDNEnv:       "dc=example,dc=com",
		BindDNEnv:       "cn=admin,dc=example,dc=com",
		SessionStoreEnv: "memory",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Session.Store != SessionStoreMemory {
		t.Errorf("session.store = %q", cfg.Session.Store)
	}
	if cfg.Session.RedisURL != "" {
		t.Errorf("redis_url = %q, want empty for memory store", cfg.Session.RedisURL)
	}
}
