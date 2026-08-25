package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validMinimal = `
ldap:
  url: "ldap://127.0.0.1:389"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
`

func TestLoadValidMinimalDefaults(t *testing.T) {
	path := writeTemp(t, "config.yaml", validMinimal)
	cfg, err := Load(path)
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

func TestLoadFull(t *testing.T) {
	path := writeTemp(t, "config.yaml", `
server:
  listen: "0.0.0.0:8443"
ldap:
  url: "ldaps://ldap.example.com:636"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  auto_number_dn: "cn=autonum,ou=svc,dc=example,dc=com"
  tls:
    min_version: "TLSv1.3"
    verify: true
    cert_expiry_fail_closed: false
  schema_compat: "389ds"
  tree_filter: "(objectClass=inetOrgPerson)"
  pool_size: 16
session:
  timeout_minutes: 45
  absolute_timeout_minutes: 720
  expired_action: "redirect_to_login"
  db_path: "/tmp/ldapact-sessions.db"
log_level: "debug"
templates_dir: "/etc/ldapact/templates"
`)
	cfg, err := Load(path)
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
	if cfg.LDAP.TLS.CertExpiryFailClosed == nil || *cfg.LDAP.TLS.CertExpiryFailClosed {
		t.Error("cert_expiry_fail_closed should be false")
	}
	if cfg.LDAP.TLS.StartTLS != nil && *cfg.LDAP.TLS.StartTLS {
		t.Error("start_tls should stay nil/off for ldaps://")
	}
	if cfg.LDAP.SchemaCompat != "389ds" {
		t.Errorf("schema_compat = %q", cfg.LDAP.SchemaCompat)
	}
	if cfg.Session.TimeoutMinutes != 45 || cfg.Session.AbsoluteTimeoutMinutes != 720 {
		t.Errorf("session timeouts = %d/%d", cfg.Session.TimeoutMinutes, cfg.Session.AbsoluteTimeoutMinutes)
	}
	if cfg.Session.ExpiredAction != ExpiredActionRedirectLogin {
		t.Errorf("expired_action = %q", cfg.Session.ExpiredAction)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log_level = %q", cfg.LogLevel)
	}
	if cfg.TemplatesDir != "/etc/ldapact/templates" {
		t.Errorf("templates_dir = %q", cfg.TemplatesDir)
	}
}

func TestLoadUnknownField(t *testing.T) {
	path := writeTemp(t, "config.yaml", validMinimal+`
unknown_key: true
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("want unknown-field error, got %v", err)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeTemp(t, "config.yaml", "ldap: [unclosed")
	if _, err := Load(path); err == nil {
		t.Fatal("want parse error")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"bad url scheme", `
ldap:
  url: "http://127.0.0.1:389"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
`, "ldap.url"},
		{"bad url host", `
ldap:
  url: "ldap://"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
`, "ldap.url"},
		{"missing base dn", `
ldap:
  url: "ldap://127.0.0.1:389"
  bind_dn: "cn=admin,dc=example,dc=com"
`, "base_dn"},
		{"missing bind dn", `
ldap:
  url: "ldap://127.0.0.1:389"
  base_dn: "dc=example,dc=com"
`, "bind_dn"},
		{"min version too low", `
ldap:
  url: "ldap://127.0.0.1:389"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  tls:
    min_version: "TLSv1.1"
`, "min_version"},
		{"verify off rejected", `
ldap:
  url: "ldap://127.0.0.1:389"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  tls:
    verify: false
`, "verify"},
		{"ldaps plus starttls", `
ldap:
  url: "ldaps://127.0.0.1:636"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  tls:
    start_tls: true
`, "start_tls"},
		{"pool size invalid", `
ldap:
  url: "ldap://127.0.0.1:389"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  pool_size: 500
`, "pool_size"},
		{"log level invalid", validMinimal + `
log_level: "loud"
`, "log_level"},
		{"idle timeout too small", validMinimal + `
session:
  timeout_minutes: 1
`, "timeout_minutes"},
		{"absolute timeout too large", validMinimal + `
session:
  absolute_timeout_minutes: 9999
`, "absolute_timeout_minutes"},
		{"expired action invalid", validMinimal + `
session:
  expired_action: "explode"
`, "expired_action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, "config.yaml", tc.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateStartTLSExplicitFalse(t *testing.T) {
	path := writeTemp(t, "config.yaml", `
ldap:
  url: "ldap://127.0.0.1:389"
  base_dn: "dc=example,dc=com"
  bind_dn: "cn=admin,dc=example,dc=com"
  tls:
    start_tls: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.TLS.StartTLS == nil || *cfg.LDAP.TLS.StartTLS {
		t.Error("start_tls should remain explicitly false (plaintext dev mode)")
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

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type fakeTTY struct {
	rd *strings.Reader
	wb strings.Builder
}

func (f *fakeTTY) Read(p []byte) (int, error)  { return f.rd.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) { return f.wb.Write(p) }
func (f *fakeTTY) Close() error                { return nil }
