package config

import (
	"io"
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
// harness) would otherwise trip the strict allowlist in Load(). Tests that
// need a variable set it explicitly with t.Setenv.
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

// setEnv sets several env vars for the duration of the test.
func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func minimalEnv() map[string]string {
	return map[string]string{
		URLEnv:    "ldap://127.0.0.1:389",
		BaseDNEnv: "dc=example,dc=com",
		BindDNEnv: "cn=admin,dc=example,dc=com",
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
	if cfg.Session.ExpiredAction != ExpiredActionRetryBind {
		t.Errorf("session.expired_action = %q, want %q", cfg.Session.ExpiredAction, ExpiredActionRetryBind)
	}
	if cfg.Session.DBPath != DefaultSessionDBPath {
		t.Errorf("session.db_path = %q, want %q", cfg.Session.DBPath, DefaultSessionDBPath)
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
		ListenEnv: "127.0.0.1:9999",
		URLEnv:    "ldap://127.0.0.1:389",
		BaseDNEnv: "dc=shipped,dc=com",
		BindDNEnv: "cn=admin,dc=shipped,dc=com",
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

func TestLoadEmptyEnvIgnored(t *testing.T) {
	setEnv(t, map[string]string{
		URLEnv:                           "ldap://127.0.0.1:389",
		BaseDNEnv:                        "dc=example,dc=com",
		BindDNEnv:                        "cn=admin,dc=example,dc=com",
		ListenEnv:                        "",
		AutoNumberDNEnv:                  "",
		TLSMinVersionEnv:                 "",
		TLSVerifyEnv:                     "",
		TLSStartTLSEnv:                   "",
		TLSCertExpiryFailClosedEnv:       "",
		SchemaCompatEnv:                  "",
		TreeFilterEnv:                    "",
		PoolSizeEnv:                      "",
		PasswordPlainOverrideEnv:         "",
		PasswordSchemeEnv:                "",
		SessionTimeoutMinutesEnv:         "",
		SessionAbsoluteTimeoutMinutesEnv: "",
		SessionExpiredActionEnv:          "",
		SessionDBPathEnv:                 "",
		LogLevelEnv:                      "",
		TemplatesDirEnv:                  "",
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
	if cfg.LDAP.TLS.Verify == nil || !*cfg.LDAP.TLS.Verify {
		t.Error("tls.verify should default to true")
	}
	if cfg.LDAP.TLS.StartTLS == nil || !*cfg.LDAP.TLS.StartTLS {
		t.Error("tls.start_tls should default to true")
	}
	if cfg.LDAP.TLS.CertExpiryFailClosed == nil || !*cfg.LDAP.TLS.CertExpiryFailClosed {
		t.Error("tls.cert_expiry_fail_closed should default to true")
	}
	if cfg.LDAP.SchemaCompat != DefaultSchemaCompat {
		t.Errorf("schema_compat = %q, want default", cfg.LDAP.SchemaCompat)
	}
	if cfg.LDAP.TreeFilter != DefaultTreeFilter {
		t.Errorf("tree_filter = %q, want default", cfg.LDAP.TreeFilter)
	}
	if cfg.LDAP.PoolSize != DefaultPoolSize {
		t.Errorf("pool_size = %d, want default", cfg.LDAP.PoolSize)
	}
	if cfg.LDAP.PasswordPlainOverride {
		t.Error("password_plain_override should default to false")
	}
	if cfg.LDAP.PasswordScheme != "" {
		t.Errorf("password_scheme = %q, want empty", cfg.LDAP.PasswordScheme)
	}
	if cfg.Session.TimeoutMinutes != DefaultIdleTimeoutMinutes {
		t.Errorf("session.timeout_minutes = %d, want default", cfg.Session.TimeoutMinutes)
	}
	if cfg.Session.AbsoluteTimeoutMinutes != DefaultAbsoluteTimeoutHours*60 {
		t.Errorf("session.absolute_timeout_minutes = %d, want default", cfg.Session.AbsoluteTimeoutMinutes)
	}
	if cfg.Session.ExpiredAction != ExpiredActionRetryBind {
		t.Errorf("session.expired_action = %q, want default", cfg.Session.ExpiredAction)
	}
	if cfg.Session.DBPath != DefaultSessionDBPath {
		t.Errorf("session.db_path = %q, want default", cfg.Session.DBPath)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("log_level = %q, want default", cfg.LogLevel)
	}
	if cfg.TemplatesDir != "" {
		t.Errorf("templates_dir = %q, want empty", cfg.TemplatesDir)
	}
}

func TestEnvPtrsStayNilWhenUnset(t *testing.T) {
	// envconfig leaves absent bool pointers untouched; Validate fills the
	// true defaults afterward.
	setEnv(t, minimalEnv())
	var env envFields
	if err := envconfig.Process("", &env); err != nil {
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

func TestLoadUnknownEnvVar(t *testing.T) {
	setEnv(t, minimalEnv())
	t.Setenv("LDAPADM_LITSEN", "1")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "LDAPADM_LITSEN") {
		t.Fatalf("want unknown-var error naming LDAPADM_LITSEN, got %v", err)
	}
}

func TestLoadUnknownEmptyEnvVarRejected(t *testing.T) {
	// Strictness applies even to set-but-empty unknown vars.
	setEnv(t, minimalEnv())
	t.Setenv("LDAPADM_LITSEN", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "LDAPADM_LITSEN") {
		t.Fatalf("want unknown-var error for empty value, got %v", err)
	}
}

func TestLoadUnprefixedVarsIgnored(t *testing.T) {
	// A stray unprefixed URL/VERIFY must never be read (full-name-tag guard).
	setEnv(t, map[string]string{
		URLEnv:    "ldap://127.0.0.1:389",
		BaseDNEnv: "dc=example,dc=com",
		BindDNEnv: "cn=admin,dc=example,dc=com",
		"URL":     "ldaps://wrong.example.com:636",
		"VERIFY":  "false",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.URL != "ldap://127.0.0.1:389" {
		t.Errorf("url = %q, want the LDAPADM_ value", cfg.LDAP.URL)
	}
	if cfg.LDAP.TLS.Verify == nil || !*cfg.LDAP.TLS.Verify {
		t.Error("verify should default to true; unprefixed VERIFY ignored")
	}
}

func TestLoadIgnoresSecretVars(t *testing.T) {
	// R3: secrets are never parsed by envconfig; the resolver chain fills
	// them later. Load must succeed with the secret vars present and leave
	// the runtime fields empty.
	setEnv(t, map[string]string{
		URLEnv:                "ldap://127.0.0.1:389",
		BaseDNEnv:             "dc=example,dc=com",
		BindDNEnv:             "cn=admin,dc=example,dc=com",
		BindPasswordEnv:       "s3cr3t",
		AutoNumberPasswordEnv: "auto-s3cr3t",
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
}

func TestKnownEnvNamesComplete(t *testing.T) {
	// The strict allowlist must cover exactly the parsed config fields plus
	// the secret variables and their _FILE references -- no more, no less.
	want := map[string]struct{}{
		ListenEnv: {}, URLEnv: {}, BaseDNEnv: {}, BindDNEnv: {}, AutoNumberDNEnv: {},
		TLSMinVersionEnv: {}, TLSVerifyEnv: {}, TLSStartTLSEnv: {}, TLSCertExpiryFailClosedEnv: {},
		SchemaCompatEnv: {}, TreeFilterEnv: {}, PoolSizeEnv: {},
		PasswordPlainOverrideEnv: {}, PasswordSchemeEnv: {},
		SessionTimeoutMinutesEnv: {}, SessionAbsoluteTimeoutMinutesEnv: {},
		SessionExpiredActionEnv: {}, SessionDBPathEnv: {},
		LogLevelEnv: {}, TemplatesDirEnv: {},
		BindPasswordEnv: {}, BindPasswordEnv + "_FILE": {},
		AutoNumberPasswordEnv: {}, AutoNumberPasswordEnv + "_FILE": {},
	}
	for name := range want {
		if _, ok := knownEnvNames[name]; !ok {
			t.Errorf("allowlist missing %s", name)
		}
	}
	for name := range knownEnvNames {
		if _, ok := want[name]; !ok {
			t.Errorf("allowlist contains unexpected %s", name)
		}
	}
}

func TestPasswordSchemeNormalized(t *testing.T) {
	setEnv(t, minimalEnv())
	t.Setenv(PasswordSchemeEnv, "ssha")
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
	}
	typ := reflect.TypeOf(envFields{})
	for field, env := range want {
		sf, ok := typ.FieldByName(field)
		if !ok {
			t.Errorf("envFields has no field %s", field)
			continue
		}
		got := sf.Tag.Get("envconfig")
		if got != env {
			t.Errorf("%s tag = %q, want %q", field, got, env)
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

func TestScanSecretLineEOF(t *testing.T) {
	got, err := scanSecretLine(strings.NewReader("no-newline"))
	if err != nil {
		t.Fatalf("scanSecretLine: %v", err)
	}
	if got != "no-newline" {
		t.Errorf("got %q", got)
	}
}

func TestResolveSecretTTYFallback(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", "")
	origOpen := openTTY
	defer func() { openTTY = origOpen }()
	openTTY = func() (io.ReadWriteCloser, error) {
		return &fakeTTY{rd: strings.NewReader("tty-secret\n")}, nil
	}
	got, err := ResolveSecret(BindPasswordEnv)
	if err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if got != "tty-secret" {
		t.Errorf("got %q, want %q", got, "tty-secret")
	}
}

func TestResolveSecretTTYUnavailable(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", "")
	origOpen := openTTY
	defer func() { openTTY = origOpen }()
	openTTY = func() (io.ReadWriteCloser, error) { return nil, os.ErrNotExist }
	_, err := ResolveSecret(BindPasswordEnv)
	if err == nil {
		t.Fatal("want error when no env/file/TTY")
	}
	for _, want := range []string{BindPasswordEnv, BindPasswordEnv + "_FILE", "TTY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Error("error must never contain a secret value")
	}
}

func TestResolveSecretTTYEmpty(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", "")
	origOpen := openTTY
	defer func() { openTTY = origOpen }()
	openTTY = func() (io.ReadWriteCloser, error) {
		return &fakeTTY{rd: strings.NewReader("\n")}, nil
	}
	if _, err := ResolveSecret(BindPasswordEnv); err == nil {
		t.Fatal("want error for empty TTY input")
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
	t.Setenv(BindPasswordEnv, "bind-secret")
	t.Setenv(AutoNumberPasswordEnv, "auto-secret")

	cfg := &Config{}
	cfg.LDAP.AutoNumberDN = ""
	if err := cfg.ResolveSecrets(); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if cfg.BindPassword != "bind-secret" {
		t.Errorf("bind password = %q", cfg.BindPassword)
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

func TestResolveSecretsBindMissing(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	t.Setenv(BindPasswordEnv+"_FILE", "")
	origOpen := openTTY
	defer func() { openTTY = origOpen }()
	openTTY = func() (io.ReadWriteCloser, error) { return nil, os.ErrNotExist }
	cfg := &Config{}
	if err := cfg.ResolveSecrets(); err == nil {
		t.Fatal("want bind-secret resolution failure")
	}
}

type fakeTTY struct {
	rd *strings.Reader
	wb strings.Builder
}

func (f *fakeTTY) Read(p []byte) (int, error)  { return f.rd.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) { return f.wb.Write(p) }
func (f *fakeTTY) Close() error                { return nil }
