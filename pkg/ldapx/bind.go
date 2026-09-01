package ldapx

import "context"

// Bind performs a simple bind (or anonymous bind when dn is empty), wrapping
// failures as LDAPError.
func Bind(conn Conn, dn, password string) error {
	if dn == "" {
		if err := conn.UnauthenticatedBind(""); err != nil {
			return wrapError("bind", dn, err)
		}
		return nil
	}
	if err := conn.Bind(dn, password); err != nil {
		return wrapError("bind", dn, err)
	}
	return nil
}

// ExternalBind performs a SASL EXTERNAL bind (R1 SASL support). The v1 config
// model uses simple bind for the admin identity; this helper keeps SASL
// reachable for future profiles.
func ExternalBind(conn Conn) error {
	if err := conn.ExternalBind(); err != nil {
		return wrapError("sasl.bind", "", err)
	}
	return nil
}

// BindCredential is the request-scoped bind identity injected by the authn
// middleware (U6) and consumed by the unbound pool on every operation.
type BindCredential struct {
	DN       string
	Password string
}

type bindCredentialKey struct{}

// WithCredential attaches the request bind credential to ctx.
func WithCredential(ctx context.Context, cred BindCredential) context.Context {
	return context.WithValue(ctx, bindCredentialKey{}, cred)
}

// CredentialFrom returns the request bind credential, if any.
func CredentialFrom(ctx context.Context) (BindCredential, bool) {
	cred, ok := ctx.Value(bindCredentialKey{}).(BindCredential)
	return cred, ok
}

// VerifyBind dials (with TLS verification), performs a simple bind, and
// closes the connection: the login gate's credential check (R6). Invalid
// credentials surface as an *LDAPError with result code 49.
func VerifyBind(ctx context.Context, opts DialOptions, dn, password string) error {
	conn, err := dialConn(ctx, opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	return Bind(conn, dn, password)
}
