package ldapx

import (
	"context"

	"github.com/go-ldap/ldap/v3"
)

// Add creates an entry (R3). Attribute names are canonicalized against the
// cached schema before the request is sent (R14).
func (c *Client) Add(ctx context.Context, dn string, attrs map[string][]string) error {
	if c.schema != nil {
		c.schema.CanonicalAttributes(attrs)
	}
	req := ldap.NewAddRequest(dn, nil)
	for k, vals := range attrs {
		req.Attribute(k, vals)
	}
	return c.pool.Do(ctx, func(conn Conn) error {
		if err := conn.Add(req); err != nil {
			return wrapError("add", dn, err)
		}
		return nil
	})
}

// Modify applies changes to an entry (R3). Each ldap.Change carries an
// operation (Add/Delete/Replace) and a PartialAttribute.
func (c *Client) Modify(ctx context.Context, dn string, changes []ldap.Change) error {
	req := ldap.NewModifyRequest(dn, nil)
	req.Changes = changes
	return c.pool.Do(ctx, func(conn Conn) error {
		if err := conn.Modify(req); err != nil {
			return wrapError("modify", dn, err)
		}
		return nil
	})
}

// Delete removes an entry (R3).
func (c *Client) Delete(ctx context.Context, dn string) error {
	return c.pool.Do(ctx, func(conn Conn) error {
		req := ldap.NewDelRequest(dn, nil)
		if err := conn.Del(req); err != nil {
			return wrapError("delete", dn, err)
		}
		return nil
	})
}

// ModifyDN renames an entry, optionally moving it to a new superior
// (cross-naming-context move per RFC 4511 §4.9) (R3, F6).
func (c *Client) ModifyDN(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error {
	req := ldap.NewModifyDNRequest(dn, newRDN, deleteOldRDN, newSuperior)
	return c.pool.Do(ctx, func(conn Conn) error {
		if err := conn.ModifyDN(req); err != nil {
			return wrapError("modrdn", dn, err)
		}
		return nil
	})
}
