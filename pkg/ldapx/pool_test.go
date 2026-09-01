package ldapx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func newTestPool(conns ...Conn) *Pool {
	capacity := len(conns)
	if capacity < 1 {
		capacity = 1
	}
	p := &Pool{
		conns:  make(chan Conn, capacity),
		opts:   PoolOptions{},
		ctx:    context.Background(),
		cancel: func() {},
	}
	for _, c := range conns {
		p.conns <- c
	}
	return p
}

// newBoundTestPool builds a pool with a configured bind identity, so
// validate-on-Put and the bound-path semantics apply.
func newBoundTestPool(conns ...Conn) *Pool {
	p := newTestPool(conns...)
	p.opts.BindDN = "cn=admin,dc=example,dc=com"
	p.opts.BindPassword = "admin-password"
	return p
}

func TestPoolPutDropsInvalidConn(t *testing.T) {
	f := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("dead"))
	}}
	p := newBoundTestPool(f)
	if err := p.Put(f); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !f.closed.Load() {
		t.Error("invalid conn should be closed and dropped")
	}
}

func TestPoolPutReturnsHealthyConn(t *testing.T) {
	f := &fakeConn{}
	p := newBoundTestPool()
	if err := p.Put(f); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if f.closed.Load() {
		t.Error("healthy conn must not be closed")
	}
	if p.Len() != 1 {
		t.Errorf("Len = %d, want 1", p.Len())
	}
}

func TestPoolPutUnboundSkipsValidationSearch(t *testing.T) {
	f := &fakeConn{}
	p := newTestPool(f)
	got, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Put(got); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if f.closed.Load() {
		t.Error("unbound Put must not close a healthy conn")
	}
	if f.searchCalls.Load() != 0 {
		t.Errorf("unbound Put must not run the validation search, got %d calls", f.searchCalls.Load())
	}
	if p.Len() != 1 {
		t.Errorf("Len = %d, want 1", p.Len())
	}
}

func TestPoolPutUnboundDropsClosingConn(t *testing.T) {
	f := &fakeConn{}
	p := newTestPool(f)
	got, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got.Close() // IsClosing becomes true
	if err := p.Put(got); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if p.Len() != 0 {
		t.Errorf("Len = %d, want 0 (closing conn dropped)", p.Len())
	}
}

func TestPoolGetBlocksAndHonorsContext(t *testing.T) {
	p := newTestPool()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := p.Get(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestPoolGetReturnsConn(t *testing.T) {
	f := &fakeConn{}
	p := newTestPool(f)
	got, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != f {
		t.Error("returned wrong conn")
	}
}

func TestPoolDoRetriesOnNetworkError(t *testing.T) {
	bad := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("server unreachable"))
	}}
	good := &fakeConn{}
	p := newTestPool(bad, good)

	err := p.Do(context.Background(), func(c Conn) error {
		_, err := c.Search(nil)
		return err
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !bad.closed.Load() {
		t.Error("bad conn should have been dropped after network error")
	}
	if good.closed.Load() {
		t.Error("good conn should stay open")
	}
	if good.searchCalls.Load() != 1 {
		t.Errorf("good conn search calls = %d, want 1 (unbound Put skips validation)", good.searchCalls.Load())
	}
}

func TestPoolDoBindsRequestCredential(t *testing.T) {
	f := &fakeConn{}
	p := newTestPool(f)
	ctx := WithCredential(context.Background(), BindCredential{
		DN:       "cn=admin,dc=example,dc=com",
		Password: "admin-password",
	})
	if err := p.Do(ctx, func(c Conn) error { return nil }); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if f.lastBindUser != "cn=admin,dc=example,dc=com" || f.lastBindPass != "admin-password" {
		t.Errorf("bind = %q/%q, want request credential", f.lastBindUser, f.lastBindPass)
	}
}

func TestPoolDoBindsAnonymousWithoutCredential(t *testing.T) {
	f := &fakeConn{}
	p := newTestPool(f)
	if err := p.Do(context.Background(), func(c Conn) error { return nil }); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if f.lastBindUser != "" {
		t.Errorf("bind user = %q, want anonymous", f.lastBindUser)
	}
}

func TestPoolDoRetriesBindNetworkError(t *testing.T) {
	bad := &fakeConn{bindFn: func(user, pass string) error {
		return ldap.NewError(ldap.ErrorNetwork, errors.New("connection lost during bind"))
	}}
	good := &fakeConn{}
	p := newTestPool(bad, good)
	ctx := WithCredential(context.Background(), BindCredential{
		DN: "cn=admin,dc=example,dc=com", Password: "pw",
	})
	if err := p.Do(ctx, func(c Conn) error { return nil }); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !bad.closed.Load() {
		t.Error("sick connection must be dropped after a bind network error")
	}
	if good.closed.Load() {
		t.Error("replacement connection should stay open")
	}
	if good.lastBindUser != "cn=admin,dc=example,dc=com" {
		t.Errorf("replacement connection bound as %q", good.lastBindUser)
	}
}

func TestPoolDoBindFailureDropsConn(t *testing.T) {
	f := &fakeConn{bindFn: func(user, pass string) error {
		return ldap.NewError(49, errors.New("invalid credentials"))
	}}
	p := newTestPool(f)
	fnCalls := 0
	err := p.Do(WithCredential(context.Background(), BindCredential{
		DN: "cn=admin,dc=example,dc=com", Password: "wrong",
	}), func(c Conn) error {
		fnCalls++
		return nil
	})
	if err == nil {
		t.Fatal("want bind error")
	}
	if !IsInvalidCredentials(err) {
		t.Fatalf("want invalidCredentials error, got %v", err)
	}
	if fnCalls != 0 {
		t.Errorf("fn must not run after bind failure, ran %d times", fnCalls)
	}
	if !f.closed.Load() {
		t.Error("conn must be closed after bind failure (no stale identity)")
	}
}

func TestPoolBoundSkipsRequestBind(t *testing.T) {
	f := &fakeConn{bindFn: func(user, pass string) error {
		t.Fatal("bound pool must not bind with request credential")
		return nil
	}}
	p := newBoundTestPool(f)
	ctx := WithCredential(context.Background(), BindCredential{DN: "someone", Password: "else"})
	if err := p.Do(ctx, func(c Conn) error { return nil }); err != nil {
		t.Fatalf("Do: %v", err)
	}
}

func TestPoolDoNoRetryOnLDAPError(t *testing.T) {
	f := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, ldap.NewError(32, errors.New("no such object"))
	}}
	p := newTestPool(f)
	fnCalls := 0
	err := p.Do(context.Background(), func(c Conn) error {
		fnCalls++
		_, err := c.Search(nil)
		return err
	})
	if err == nil {
		t.Fatal("want error")
	}
	var le *ldap.Error
	if !errors.As(err, &le) || le.ResultCode != 32 {
		t.Fatalf("want ldap code 32, got %v", err)
	}
	if fnCalls != 1 {
		t.Errorf("fn calls = %d, want 1 (no retry on non-network error)", fnCalls)
	}
}

func TestPoolDoRetriesOnlyOnce(t *testing.T) {
	bad1 := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("down"))
	}}
	bad2 := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("still down"))
	}}
	p := newTestPool(bad1, bad2)
	err := p.Do(context.Background(), func(c Conn) error {
		_, err := c.Search(nil)
		return err
	})
	if err == nil {
		t.Fatal("want error after single retry")
	}
	if !bad1.closed.Load() || !bad2.closed.Load() {
		t.Error("both failed conns should be dropped")
	}
}

func TestPoolClosed(t *testing.T) {
	f := &fakeConn{}
	p := newTestPool(f)
	p.closed.Store(true)
	if _, err := p.Get(context.Background()); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("Get after close: %v", err)
	}
	if err := p.Put(f); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("Put after close: %v", err)
	}
	if !f.closed.Load() {
		t.Error("Put after close must close the conn")
	}
}

func TestPoolCloseDrains(t *testing.T) {
	f1, f2 := &fakeConn{}, &fakeConn{}
	p := newTestPool(f1, f2)
	p.Close()
	if !f1.closed.Load() || !f2.closed.Load() {
		t.Error("Close must close idle conns")
	}
	if p.Len() != 0 {
		t.Errorf("Len after Close = %d", p.Len())
	}
}

func TestBackoffFor(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 50 * time.Millisecond},
		{2, 100 * time.Millisecond},
		{3, 200 * time.Millisecond},
		{10, 2 * time.Second},
	}
	for _, tc := range cases {
		if got := backoffFor(tc.attempt); got != tc.want {
			t.Errorf("backoffFor(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}
