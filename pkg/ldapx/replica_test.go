package ldapx

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func newTestReplicas(pools ...*Pool) *Replicas {
	urls := make([]string, 0, len(pools))
	for i := range pools {
		urls = append(urls, "ldap://replica-"+string(rune('a'+i))+".test:389")
	}
	return &Replicas{pools: pools, urls: urls}
}

func TestReplicasDoFailsOverOnNetworkError(t *testing.T) {
	bad := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, wrapError("search", "dc=example,dc=com", ldap.NewError(ldap.ErrorNetwork, errors.New("down")))
	}}
	good := &fakeConn{}
	r := newTestReplicas(newTestPool(bad), newTestPool(good))
	if err := r.Do(context.Background(), func(c Conn) error {
		_, err := c.Search(nil)
		return err
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !bad.closed.Load() {
		t.Error("sick replica connection should be dropped")
	}
	if good.searchCalls.Load() == 0 {
		t.Error("second replica should serve the operation")
	}
}

func TestReplicasDoNoFailoverOnInvalidCredentials(t *testing.T) {
	bad := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, wrapError("search", "dc=example,dc=com", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad creds")))
	}}
	good := &fakeConn{}
	r := newTestReplicas(newTestPool(bad), newTestPool(good))
	err := r.Do(context.Background(), func(c Conn) error {
		_, err := c.Search(nil)
		return err
	})
	if !IsInvalidCredentials(err) {
		t.Fatalf("want invalidCredentials, got %v", err)
	}
	if good.searchCalls.Load() != 0 {
		t.Error("invalidCredentials must never fail over (shared identity)")
	}
}

func TestReplicasDoNoFailoverOnAppError(t *testing.T) {
	first := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, wrapError("search", "dc=example,dc=com", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("missing")))
	}}
	second := &fakeConn{}
	r := newTestReplicas(newTestPool(first), newTestPool(second))
	err := r.Do(context.Background(), func(c Conn) error {
		_, err := c.Search(nil)
		return err
	})
	if err == nil {
		t.Fatal("want noSuchObject error")
	}
	if second.searchCalls.Load() != 0 {
		t.Error("application-level errors must not fail over")
	}
}

func TestReplicasDoAllDownAggregates(t *testing.T) {
	down := func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, wrapError("search", "dc=example,dc=com", ldap.NewError(ldap.ErrorNetwork, errors.New("unreachable")))
	}
	r := newTestReplicas(
		newTestPool(&fakeConn{searchFn: down}),
		newTestPool(&fakeConn{searchFn: down}),
	)
	err := r.Do(context.Background(), func(c Conn) error {
		_, err := c.Search(nil)
		return err
	})
	if err == nil {
		t.Fatal("want aggregate error")
	}
	for _, want := range []string{"replica-a", "replica-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("aggregate error missing %q: %v", want, err)
		}
	}
}

func TestReplicasRotationAdvances(t *testing.T) {
	r := newTestReplicas(newTestPool(), newTestPool())
	a := r.start()
	b := r.start()
	if a == b {
		t.Error("rotating start point must change between calls")
	}
}

func TestReplicasSingleURLStableStart(t *testing.T) {
	r := newTestReplicas(newTestPool())
	if got := r.start(); got != 0 {
		t.Errorf("single replica start = %d, want 0", got)
	}
}

func TestReplicasPageFailsOver(t *testing.T) {
	bad := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, wrapError("search", "dc=example,dc=com", ldap.NewError(ldap.ErrorNetwork, errors.New("down")))
	}}
	good := &fakeConn{}
	r := newTestReplicas(newTestPool(bad), newTestPool(good))
	ctx := WithCredential(context.Background(), BindCredential{DN: "cn=admin,dc=example,dc=com", Password: "pw"})
	res, err := r.Page(ctx, SearchOptions{BaseDN: "dc=example,dc=com", Scope: ldap.ScopeSingleLevel, PageSize: 10}, 1)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if res == nil {
		t.Fatal("nil page result")
	}
	if good.searchCalls.Load() == 0 {
		t.Error("second replica should serve the paged search")
	}
}
