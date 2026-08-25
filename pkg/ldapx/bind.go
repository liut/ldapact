package ldapx

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
