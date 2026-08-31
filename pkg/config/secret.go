package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// openTTY is swappable in tests. It returns an error when no TTY is available
// (CI, daemonized deployments), which makes the resolver fail fast instead of
// hanging on a missing terminal.
var openTTY = func() (io.ReadWriteCloser, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// promptSecretTTY is swappable in tests; the production implementation reads a
// line from the controlling terminal with echo disabled. Non-terminal streams
// (used by tests) fall back to a plain buffered read.
var promptSecretTTY = func(prompt string) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", err
	}
	defer tty.Close()
	if _, err := io.WriteString(tty, prompt); err != nil {
		return "", err
	}
	if f, ok := tty.(interface{ Fd() uintptr }); ok {
		b, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(tty, "\n")
		return string(b), nil
	}
	return scanSecretLine(tty)
}

// ResolveSecret resolves a named secret through the R12 chain:
//  1. env var <name>
//  2. file referenced by env var <name>_FILE (mode must be 0600)
//  3. TTY prompt (echo disabled)
//
// The returned error names the chain that was attempted but never contains a
// secret value.
func ResolveSecret(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	fileEnv := name + "_FILE"
	if p := os.Getenv(fileEnv); p != "" {
		return readSecretFile(p)
	}
	v, err := promptSecretTTY("Enter secret " + name + ": ")
	if err != nil {
		return "", fmt.Errorf("resolve secret %s: no env var %s, no file ref %s, and TTY prompt failed: %w",
			name, name, fileEnv, err)
	}
	if v == "" {
		return "", fmt.Errorf("resolve secret %s: empty value from TTY prompt", name)
	}
	return v, nil
}

// readSecretFile reads a secret from path, requiring regular-file mode 0600
// (R12). Trailing newlines are stripped.
func readSecretFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("resolve secret file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("resolve secret file %s: not a regular file", path)
	}
	if fi.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("resolve secret file %s: mode is %o, want 0600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file %s: %w", path, err)
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", fmt.Errorf("resolve secret file %s: file is empty", path)
	}
	return s, nil
}

// SecretFingerprint returns a truncated fingerprint safe for log lines: the
// first four and last two characters. Short or empty secrets never leak.
func SecretFingerprint(s string) string {
	switch {
	case s == "":
		return "[empty]"
	case len(s) <= 6:
		return "[redacted]"
	default:
		return s[:4] + ".." + s[len(s)-2:]
	}
}

// ResolveSecrets fills the runtime secret fields:
//   - LDAPADM_SESSION_KEY is required (U4 cipher key; changing it invalidates
//     every stored encrypted credential, R14).
//   - LDAPADM_REDIS_PASSWORD is resolved only when the redis store is
//     selected and the env var / file reference is present (optional; Redis
//     without auth is allowed).
//   - LDAPADM_AUTO_NUMBER_PASSWORD is resolved only when AutoNumberDN is
//     configured.
//   - LDAPADM_BIND_PASSWORD is no longer resolved (R15): the bind credential
//     moves to the login flow. BindPassword remains on Config only for
//     transitional code until the ldapx pool refactor lands.
func (c *Config) ResolveSecrets() error {
	sk, err := ResolveSecret(SessionKeyEnv)
	if err != nil {
		return fmt.Errorf("session key: %w", err)
	}
	c.SessionKey = sk
	if c.Session.Store == SessionStoreRedis {
		rp, err := resolveOptionalSecret(RedisPasswordEnv)
		if err != nil {
			return fmt.Errorf("redis password: %w", err)
		}
		c.RedisPassword = rp
	}
	if c.LDAP.AutoNumberDN != "" {
		ap, err := ResolveSecret(AutoNumberPasswordEnv)
		if err != nil {
			return fmt.Errorf("auto-number secret: %w", err)
		}
		c.AutoNumberPassword = ap
	}
	return nil
}

// resolveOptionalSecret resolves a secret only when its env var or _FILE
// reference is present; an absent secret resolves to "". It never falls back
// to a TTY prompt, so optional secrets (like a no-auth Redis) do not hang
// startup.
func resolveOptionalSecret(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	if p := os.Getenv(name + "_FILE"); p != "" {
		return readSecretFile(p)
	}
	return "", nil
}

// scanSecrets is a small helper kept for tests that need a bufio reader on a
// secret stream without importing bufio at call sites.
func scanSecretLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
