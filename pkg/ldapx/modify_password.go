package ldapx

import (
	"context"

	"github.com/go-ldap/ldap/v3"
)

// PasswordModify performs an RFC 3062 password modify operation. The new
// password is never logged.
func (c *Client) PasswordModify(ctx context.Context, userDN, newPassword string) error {
	req := ldap.NewPasswordModifyRequest(userDN, "", newPassword)
	return c.pool.Do(ctx, func(conn Conn) error {
		if _, err := conn.PasswordModify(req); err != nil {
			return wrapError("password.modify", userDN, err)
		}
		return nil
	})
}
