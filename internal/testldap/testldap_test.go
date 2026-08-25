package testldap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// TestStartSmoke starts whichever backend is available (Docker or local
// ephemeral slapd) and verifies an admin bind + base search.
func TestStartSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	inst, err := Start(ctx)
	if errors.Is(err, ErrUnavailable) {
		t.Skip("no LDAP backend available: " + err.Error())
	}
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer inst.Stop()

	conn, err := ldap.DialURL(inst.URL, ldap.DialWithDialer(nil))
	if err != nil {
		t.Fatalf("dial %s: %v", inst.URL, err)
	}
	defer conn.Close()
	if err := conn.Bind(inst.AdminDN, inst.AdminPassword); err != nil {
		t.Fatalf("bind: %v", err)
	}
	res, err := conn.Search(ldap.NewSearchRequest(inst.BaseDN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectClass"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 || !strings.Contains(res.Entries[0].DN, inst.BaseDN) {
		t.Errorf("base search = %+v", res.Entries)
	}
}

// TestConfigPointers verifies the generated profile targets the instance.
func TestConfigPointers(t *testing.T) {
	inst := &Instance{URL: "ldap://127.0.0.1:1389", AdminDN: AdminDN, AdminPassword: AdminPassword, BaseDN: BaseDN}
	cfg := inst.Config()
	if cfg.LDAP.URL != inst.URL || cfg.LDAP.BindDN != AdminDN || cfg.BindPassword != AdminPassword {
		t.Errorf("config = %+v", cfg.LDAP)
	}
}
