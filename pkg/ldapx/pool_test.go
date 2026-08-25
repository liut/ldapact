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

func TestPoolPutDropsInvalidConn(t *testing.T) {
	f := &fakeConn{searchFn: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("dead"))
	}}
	p := newTestPool(f)
	if err := p.Put(f); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !f.closed.Load() {
		t.Error("invalid conn should be closed and dropped")
	}
}

func TestPoolPutReturnsHealthyConn(t *testing.T) {
	f := &fakeConn{}
	p := newTestPool()
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
	if good.searchCalls.Load() != 2 {
		t.Errorf("good conn search calls = %d, want 2 (the op, then a successful Put validation)", good.searchCalls.Load())
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
