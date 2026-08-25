// Package ldapx wraps go-ldap/ldap/v3 with the admin-tool-specific concerns
// from R1-R5: a validated connection pool, paged search, subschema caching,
// and CRUD helpers. Nothing in this package is exported as a general-purpose
// LDAP client library (outside this product's identity).
package ldapx

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Sentinel errors for the pool and TLS layer.
var (
	ErrPoolClosed     = errors.New("ldapx: pool closed")
	ErrStartTLSFailed = errors.New("ldapx: StartTLS failed")
	ErrTLSCertExpired = errors.New("ldapx: LDAP TLS certificate expired")
)

// LDAPError wraps an LDAP operation failure with the result code and target
// DN so handlers can map result codes to HTTP statuses. It implements
// slog.LogValuer so structured logs surface the code without dumping the full
// error chain; it never carries password values.
type LDAPError struct {
	Op   string // operation label: bind/add/search/...
	Code uint16 // LDAP result code
	DN   string // target DN
	Err  error  // underlying error
}

func (e *LDAPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("ldapx: %s on %q failed (code %d): %v", e.Op, e.DN, e.Code, e.Err)
	}
	return fmt.Sprintf("ldapx: %s on %q failed (code %d)", e.Op, e.DN, e.Code)
}

func (e *LDAPError) Unwrap() error { return e.Err }

// LogValue implements slog.LogValuer (KTD 12 / System-Wide Impact).
func (e *LDAPError) LogValue() slog.Value {
	msg := ""
	if e.Err != nil {
		msg = e.Err.Error()
	}
	return slog.GroupValue(
		slog.String("op", e.Op),
		slog.Uint64("ldap_code", uint64(e.Code)),
		slog.String("dn", e.DN),
		slog.String("error", msg),
	)
}

// wrapError converts an ldap error into *LDAPError, extracting the result
// code. Non-ldap errors are returned unchanged.
func wrapError(op, dn string, err error) error {
	if err == nil {
		return nil
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		return &LDAPError{Op: op, Code: le.ResultCode, DN: dn, Err: err}
	}
	return err
}

// isRetryable reports whether an operation failure is a network-level error
// that warrants a single retry on a fresh connection (KTD 5).
func isRetryable(err error) bool {
	var le *ldap.Error
	if errors.As(err, &le) {
		return le.ResultCode == ldap.ErrorNetwork || le.ResultCode == ldap.LDAPResultServerDown
	}
	return false
}

// backoffFor returns the exponential backoff for the given 1-based attempt:
// 50ms, 100ms, 200ms, ... capped at 2s (KTD 5).
func backoffFor(attempt int) time.Duration {
	d := 50 * time.Millisecond
	for i := 1; i < attempt && d < 2*time.Second; i++ {
		d *= 2
	}
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}
