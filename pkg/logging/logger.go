// Package logging builds the structured slog logger and enforces the
// userPassword redaction rule (R15, KTD 12) at the handler boundary.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LevelEnv is the environment variable controlling the log level (R15).
const LevelEnv = "LDAPADM_LOG_LEVEL"

// Audit event names for LDAP write operations (R15, AE6).
const (
	EventCreate = "ldap.create"
	EventModify = "ldap.modify"
	EventDelete = "ldap.delete"
	EventRename = "ldap.rename"
)

// New returns a JSON slog logger writing to out. ReplaceAttr drops every
// attribute whose key is userPassword or ends in _password/Password, so no
// code path can accidentally emit a secret.
func New(level slog.Level, out io.Writer) *slog.Logger {
	h := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redactAttr,
	})
	return slog.New(h)
}

// NewFromEnv builds the default logger with the level from LDAPADM_LOG_LEVEL
// (defaults to info when unset).
func NewFromEnv() (*slog.Logger, error) {
	lvl, err := LevelFromEnv()
	if err != nil {
		return nil, err
	}
	return New(lvl, os.Stdout), nil
}

// LevelFromEnv parses LDAPADM_LOG_LEVEL (empty means info).
func LevelFromEnv() (slog.Level, error) {
	return LevelFromString(os.Getenv(LevelEnv))
}

// LevelFromString parses a level name, defaulting empty to info.
func LevelFromString(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid %s value %q (want debug|info|warn|error)", LevelEnv, s)
	}
}

// redactAttr is the ReplaceAttr hook. Dropping an attr is done by returning a
// zero slog.Attr.
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	if isSecretKey(a.Key) {
		return slog.Attr{}
	}
	return a
}

// isSecretKey reports whether an attribute key may carry a secret value.
func isSecretKey(key string) bool {
	k := strings.ToLower(key)
	return k == "userpassword" ||
		strings.HasSuffix(k, "_password") ||
		strings.HasSuffix(k, "password")
}

// SafeAttr constructs a slog.Attr with the same redaction rule applied at the
// call site (belt-and-suspenders, KTD 12).
func SafeAttr(key string, val any) slog.Attr {
	if isSecretKey(key) {
		return slog.Attr{}
	}
	return slog.Any(key, val)
}
