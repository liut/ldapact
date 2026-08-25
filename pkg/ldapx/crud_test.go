package ldapx

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestAddCanonicalizesAndSends(t *testing.T) {
	s, err := ParseSchema(sampleSchemaEntry())
	if err != nil {
		t.Fatal(err)
	}
	var got *ldap.AddRequest
	f := &fakeConn{addFn: func(req *ldap.AddRequest) error {
		got = req
		return nil
	}}
	c := &Client{pool: newTestPool(f), schema: s}
	err = c.Add(context.Background(), "cn=alice,dc=example,dc=com", map[string][]string{
		"CN": {"alice"},
		"SN": {"Smith"},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got == nil || got.DN != "cn=alice,dc=example,dc=com" {
		t.Fatalf("AddRequest = %+v", got)
	}
	if len(got.Attributes) != 2 {
		t.Fatalf("attributes = %+v", got.Attributes)
	}
	seen := map[string]bool{}
	for _, a := range got.Attributes {
		seen[a.Type] = true
	}
	if !seen["cn"] || !seen["sn"] {
		t.Errorf("attribute names not canonicalized: %v", seen)
	}
}

func TestModifySendsChanges(t *testing.T) {
	var got *ldap.ModifyRequest
	f := &fakeConn{modifyFn: func(req *ldap.ModifyRequest) error {
		got = req
		return nil
	}}
	c := &Client{pool: newTestPool(f)}
	changes := []ldap.Change{
		{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "description", Vals: []string{"new"}}},
	}
	err := c.Modify(context.Background(), "cn=alice,dc=example,dc=com", changes)
	if err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if got == nil || len(got.Changes) != 1 || got.Changes[0].Modification.Type != "description" {
		t.Fatalf("ModifyRequest = %+v", got)
	}
}

func TestDeleteSendsRequest(t *testing.T) {
	var gotDN string
	f := &fakeConn{delFn: func(req *ldap.DelRequest) error {
		gotDN = req.DN
		return ldap.NewError(32, errors.New("no such object"))
	}}
	c := &Client{pool: newTestPool(f)}
	err := c.Delete(context.Background(), "cn=bob,dc=example,dc=com")
	if gotDN != "cn=bob,dc=example,dc=com" {
		t.Errorf("deleted DN = %q", gotDN)
	}
	var lerr *LDAPError
	if !errors.As(err, &lerr) || lerr.Code != 32 || lerr.Op != "delete" {
		t.Fatalf("want delete LDAPError code 32, got %v", err)
	}
}

func TestModifyDNSendsRequest(t *testing.T) {
	var got *ldap.ModifyDNRequest
	f := &fakeConn{modifyDNFn: func(req *ldap.ModifyDNRequest) error {
		got = req
		return nil
	}}
	c := &Client{pool: newTestPool(f)}
	err := c.ModifyDN(context.Background(), "cn=bob,ou=People,dc=example,dc=com",
		"cn=robert", true, "ou=Archive,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ModifyDN: %v", err)
	}
	if got == nil || got.DN != "cn=bob,ou=People,dc=example,dc=com" ||
		got.NewRDN != "cn=robert" || !got.DeleteOldRDN || got.NewSuperior != "ou=Archive,dc=example,dc=com" {
		t.Fatalf("ModifyDNRequest = %+v", got)
	}
}

func TestPasswordModifySendsRequest(t *testing.T) {
	var got *ldap.PasswordModifyRequest
	f := &fakeConn{passwdFn: func(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
		got = req
		return &ldap.PasswordModifyResult{}, nil
	}}
	c := &Client{pool: newTestPool(f)}
	err := c.PasswordModify(context.Background(), "cn=alice,dc=example,dc=com", "NewPass#2026")
	if err != nil {
		t.Fatalf("PasswordModify: %v", err)
	}
	if got == nil || got.UserIdentity != "cn=alice,dc=example,dc=com" || got.NewPassword != "NewPass#2026" {
		t.Fatalf("PasswordModifyRequest = %+v", got)
	}
}

func TestLDAPErrorLogValue(t *testing.T) {
	lerr := &LDAPError{Op: "bind", Code: 49, DN: "cn=admin,dc=example,dc=com", Err: errors.New("invalid credentials")}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Error("ldap operation failed", "ldap", lerr)
	out := buf.String()
	for _, want := range []string{"bind", "49", "cn=admin,dc=example,dc=com", "invalid credentials"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q: %s", want, out)
		}
	}
}
