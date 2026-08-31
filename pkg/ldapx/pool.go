package ldapx

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Pool is a hand-rolled channel-based LDAP connection pool (KTD 5; go-ldap
// ships no native pool). In bound mode connections are validated on Put with
// a base-scope search and dropped on error; in unbound mode (no configured
// BindDN) each operation binds with the request-scoped credential from the
// context, and health checking is dial-level (U5/R15).
type Pool struct {
	conns  chan Conn
	opts   PoolOptions
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
	logger *slog.Logger
}

// PoolOptions configures the pool.
type PoolOptions struct {
	Size int
	// BindDN/BindPassword are optional (U5/R15): empty leaves the pool
	// unbound and every Do/Page binds with the request credential from the
	// context. The auto-number pool keeps its configured identity.
	BindDN         string
	BindPassword   string
	Dial           DialOptions
	HealthInterval time.Duration
}

// NewPool dials and binds Size connections up front (fail-fast on any error),
// then starts the health goroutine.
func NewPool(ctx context.Context, opts PoolOptions) (*Pool, error) {
	if opts.Size < 1 {
		opts.Size = 1
	}
	if opts.HealthInterval <= 0 {
		opts.HealthInterval = 30 * time.Second
	}
	childCtx, cancel := context.WithCancel(ctx)
	p := &Pool{
		conns:  make(chan Conn, opts.Size),
		opts:   opts,
		ctx:    childCtx,
		cancel: cancel,
		logger: opts.Dial.Logger,
	}
	for i := 0; i < opts.Size; i++ {
		c, err := p.newConn(childCtx)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.conns <- c
	}
	go p.healthLoop()
	return p, nil
}

func (p *Pool) newConn(ctx context.Context) (Conn, error) {
	conn, err := Dial(ctx, p.opts.Dial)
	if err != nil {
		return nil, err
	}
	if p.opts.BindDN == "" {
		return conn, nil
	}
	if err := Bind(conn, p.opts.BindDN, p.opts.BindPassword); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Get returns an idle connection, blocking until one is available or ctx is
// done.
func (p *Pool) Get(ctx context.Context) (Conn, error) {
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}
	select {
	case c := <-p.conns:
		if c == nil {
			return nil, ErrPoolClosed
		}
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Put validates bound-pool connections with a base-scope search; invalid
// connections are closed and dropped (the health loop refills). Unbound
// pools skip the search (dial-level health, R15) — operations detect dead
// connections and retry on a fresh one. After Close, Put closes the
// connection.
func (p *Pool) Put(c Conn) error {
	if p.closed.Load() {
		c.Close()
		return ErrPoolClosed
	}
	if err := p.validate(c); err != nil {
		if p.logger != nil {
			p.logger.Debug("dropping invalid pool connection",
				"event", "ldap.pool.drop",
				"error", err)
		}
		c.Close()
		return nil
	}
	select {
	case p.conns <- c:
		return nil
	default:
		c.Close()
		return nil
	}
}

// validate performs the KTD 5 validate-on-Put search for bound pools.
// Unbound pools have no resting identity (each request binds), so a search
// here would probe the wrong identity or fail on anonymous-search ACLs; the
// dial-level health posture applies instead (R15).
func (p *Pool) validate(c Conn) error {
	if p.opts.BindDN == "" {
		if c.IsClosing() {
			return fmt.Errorf("ldapx: connection is closing")
		}
		return nil
	}
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 5, false, "(objectClass=*)", []string{"1.1"}, nil)
	_, err := c.Search(req)
	return err
}

// Do acquires a connection, binds it to the request credential (unbound
// pools), runs fn, and returns it. Network-level failures retry once on a
// fresh connection after backoff (KTD 5). invalidCredentials (49) is not a
// network error and is never retried.
func (p *Pool) Do(ctx context.Context, fn func(Conn) error) error {
	c, err := p.Get(ctx)
	if err != nil {
		return err
	}
	if err := p.bindFor(ctx, c); err != nil {
		c.Close()
		return err
	}
	attempt := 0
	for {
		attempt++
		err = fn(c)
		if err == nil {
			p.Put(c)
			return nil
		}
		if attempt == 1 && isRetryable(err) {
			if p.opts.BindDN == "" {
				// Unbound pools cannot validate; drop the sick connection
				// outright so the retry uses a fresh one.
				c.Close()
			} else {
				// Drop the sick connection (Put validates and closes it).
				_ = p.Put(c)
			}
			select {
			case <-time.After(backoffFor(attempt)):
			case <-ctx.Done():
				return ctx.Err()
			}
			c, err = p.Get(ctx)
			if err != nil {
				return err
			}
			if err := p.bindFor(ctx, c); err != nil {
				c.Close()
				return err
			}
			continue
		}
		if p.opts.BindDN == "" && isRetryable(err) {
			// Final network-level failure on an unbound pool: the connection
			// is suspect, so drop it rather than recycle it unvalidated.
			c.Close()
			return err
		}
		p.Put(c)
		return err
	}
}

// bindFor applies the request-scoped credential to an unbound pool
// connection. Bound pools keep their configured identity. Missing context
// credentials bind anonymously — a pooled connection must never run an
// operation under another request's bind.
func (p *Pool) bindFor(ctx context.Context, c Conn) error {
	if p.opts.BindDN != "" {
		return nil
	}
	dn, password := "", ""
	if cred, ok := CredentialFrom(ctx); ok {
		dn, password = cred.DN, cred.Password
	}
	if err := Bind(c, dn, password); err != nil {
		return fmt.Errorf("ldapx: request bind: %w", err)
	}
	return nil
}

func (p *Pool) healthLoop() {
	t := time.NewTicker(p.opts.HealthInterval)
	defer t.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
			p.pingAll()
		}
	}
}

// pingAll pings every idle connection and refills any that were dropped.
func (p *Pool) pingAll() {
	dropped := false
	for {
		select {
		case c := <-p.conns:
			if err := p.validate(c); err != nil {
				if p.logger != nil {
					p.logger.Debug("health check dropped pool connection",
						"event", "ldap.pool.health_drop",
						"error", err)
				}
				c.Close()
				dropped = true
			} else {
				select {
				case p.conns <- c:
				default:
					c.Close()
				}
			}
		default:
			if dropped {
				p.topUp()
			}
			return
		}
	}
}

func (p *Pool) topUp() {
	for len(p.conns) < p.opts.Size {
		c, err := p.newConn(p.ctx)
		if err != nil {
			return // retry on the next tick
		}
		select {
		case p.conns <- c:
		default:
			c.Close()
			return
		}
	}
}

// Close stops the health loop and closes all idle connections. In-flight
// connections are closed by their callers via Put.
func (p *Pool) Close() {
	if p.closed.Swap(true) {
		return
	}
	p.cancel()
	for {
		select {
		case c := <-p.conns:
			c.Close()
		default:
			return
		}
	}
}

// Len reports the number of idle connections currently in the pool.
func (p *Pool) Len() int {
	return len(p.conns)
}
