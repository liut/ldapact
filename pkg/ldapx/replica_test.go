package ldapx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func newTestReplicas(pools ...*Pool) *Replicas {
	urls := make([]string, 0, len(pools))
	for i := range pools {
		urls = append(urls, "ldap://replica-"+string(rune('a'+i))+".test:389")
	}
	return &Replicas{pools: pools, poolURLs: append([]string(nil), urls...), urls: urls}
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

// TestReplicasPartialStartupRetriesFailedReplica verifies R11 startup
// tolerance: a replica that fails its initial dial does not abort startup
// while another replica is reachable, and is retried in the background.
func TestReplicasPartialStartupRetriesFailedReplica(t *testing.T) {
	origDial := dialConn
	var mu sync.Mutex
	dialCount := 0
	dialConn = func(_ context.Context, opts DialOptions) (Conn, error) {
		mu.Lock()
		dialCount++
		n := dialCount
		mu.Unlock()
		if strings.Contains(opts.URL, "bad") && n <= 2 {
			return nil, fmt.Errorf("dial refused")
		}
		return &fakeConn{}, nil
	}
	defer func() { dialConn = origDial }()

	r, err := NewReplicas(context.Background(), []string{
		"ldap://good.test:389",
		"ldap://bad.test:389",
	}, PoolOptions{
		Size:           1,
		HealthInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("startup with one reachable replica must succeed, got %v", err)
	}
	defer r.Close()
	if got := r.Len(); got != 1 {
		t.Fatalf("active replicas = %d, want 1", got)
	}
	if err := r.Do(context.Background(), func(c Conn) error {
		_, err := c.Search(nil)
		return err
	}); err != nil {
		t.Fatalf("Do through healthy replica: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && r.Len() != 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := r.Len(); got != 2 {
		t.Fatalf("failed replica never recovered: active = %d", got)
	}
}

func TestReplicasAllDownFailsStartup(t *testing.T) {
	origDial := dialConn
	dialConn = func(_ context.Context, opts DialOptions) (Conn, error) {
		return nil, fmt.Errorf("refused %s", opts.URL)
	}
	defer func() { dialConn = origDial }()

	_, err := NewReplicas(context.Background(), []string{
		"ldap://a.test:389",
		"ldap://b.test:389",
	}, PoolOptions{Size: 1, HealthInterval: time.Hour})
	if err == nil || !strings.Contains(err.Error(), "all replicas failed") {
		t.Fatalf("want aggregated all-down error, got %v", err)
	}
}

func TestReplicasVerifyBindFailsOverOnDialError(t *testing.T) {
	origDial := dialConn
	attempts := 0
	dialConn = func(_ context.Context, _ DialOptions) (Conn, error) {
		attempts++
		if attempts == 1 {
			return nil, &net.OpError{Op: "dial", Err: errors.New("refused")}
		}
		return &fakeConn{}, nil
	}
	defer func() { dialConn = origDial }()

	p1, p2 := newTestPool(), newTestPool()
	p1.opts.Dial.URL = "ldap://replica-a.test:389"
	p2.opts.Dial.URL = "ldap://replica-b.test:389"
	r := newTestReplicas(p1, p2)
	if err := r.VerifyBind(context.Background(), "cn=admin,dc=example,dc=com", "pw"); err != nil {
		t.Fatalf("VerifyBind after dial failover: %v", err)
	}
	if attempts != 2 {
		t.Errorf("dial attempts = %d, want 2 (fail over to the healthy replica)", attempts)
	}
}

func TestReplicasVerifyBindNoFailoverOnAppError(t *testing.T) {
	origDial := dialConn
	bad := &fakeConn{bindFn: func(user, pass string) error {
		return ldap.NewError(ldap.LDAPResultBusy, errors.New("server busy"))
	}}
	calls := 0
	dialConn = func(_ context.Context, _ DialOptions) (Conn, error) {
		calls++
		return bad, nil
	}
	defer func() { dialConn = origDial }()

	p1, p2 := newTestPool(), newTestPool()
	p1.opts.Dial.URL = "ldap://replica-a.test:389"
	p2.opts.Dial.URL = "ldap://replica-b.test:389"
	r := newTestReplicas(p1, p2)
	err := r.VerifyBind(context.Background(), "cn=admin,dc=example,dc=com", "pw")
	if err == nil {
		t.Fatal("want the busy bind error")
	}
	if calls != 1 {
		t.Errorf("dial calls = %d, want 1 (app-level error must not fail over)", calls)
	}
}

func TestReplicasVerifyBindNoFailoverOnInvalidCredentials(t *testing.T) {
	origDial := dialConn
	bad := &fakeConn{bindFn: func(user, pass string) error {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad creds"))
	}}
	calls := 0
	dialConn = func(_ context.Context, _ DialOptions) (Conn, error) {
		calls++
		return bad, nil
	}
	defer func() { dialConn = origDial }()

	p1, p2 := newTestPool(), newTestPool()
	p1.opts.Dial.URL = "ldap://replica-a.test:389"
	p2.opts.Dial.URL = "ldap://replica-b.test:389"
	r := newTestReplicas(p1, p2)
	err := r.VerifyBind(context.Background(), "cn=admin,dc=example,dc=com", "pw")
	if !IsInvalidCredentials(err) {
		t.Fatalf("want invalidCredentials, got %v", err)
	}
	if calls != 1 {
		t.Errorf("dial calls = %d, want 1 (invalidCredentials must never fail over)", calls)
	}
}
