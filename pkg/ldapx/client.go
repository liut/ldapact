package ldapx

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/liut/ldapact/pkg/config"
)

// Client is the admin-tool-specific LDAP facade: pool + auto-number pool +
// cached subschema. The main pool is unbound (U5/R15): every operation binds
// with the request credential from the context. The subschema cache loads
// lazily on the first authenticated operation.
type Client struct {
	pool     *Pool
	autoPool *Pool
	schema   *Schema
	mu       sync.RWMutex
	logger   *slog.Logger
	baseDN   string
	filter   string
}

// New dials the admin pool (fail-fast reachability/TLS probe, R15) and the
// optional auto-number pool (bound, R8). The subschema cache is loaded
// lazily on the first authenticated operation (U5); credential validation
// happens at login instead of startup.
func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Client, error) {
	dialOpts := DialOptions{URL: cfg.LDAP.URL, TLS: cfg.LDAP.TLS, Logger: logger}
	pool, err := NewPool(ctx, PoolOptions{
		Size:           cfg.LDAP.PoolSize,
		Dial:           dialOpts,
		HealthInterval: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	c := &Client{
		pool:   pool,
		logger: logger,
		baseDN: cfg.LDAP.BaseDN,
		filter: cfg.LDAP.TreeFilter,
	}
	if cfg.LDAP.AutoNumberDN != "" {
		ap, err := NewPool(ctx, PoolOptions{
			Size:           2,
			BindDN:         cfg.LDAP.AutoNumberDN,
			BindPassword:   cfg.AutoNumberPassword,
			Dial:           dialOpts,
			HealthInterval: 30 * time.Second,
		})
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("ldapx: auto-number pool: %w", err)
		}
		c.autoPool = ap
	}
	return c, nil
}

// Close releases both pools.
func (c *Client) Close() {
	if c.pool != nil {
		c.pool.Close()
	}
	if c.autoPool != nil {
		c.autoPool.Close()
	}
}

// BaseDN returns the configured base DN.
func (c *Client) BaseDN() string { return c.baseDN }

// TreeFilter returns the configured tree browse filter (R2).
func (c *Client) TreeFilter() string { return c.filter }
