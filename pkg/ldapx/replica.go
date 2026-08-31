package ldapx

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// Replicas is the replica-aware connection layer (R10/R11): one unbound
// sub-pool per LDAP replica URL, with rotating start points and bounded
// failover on network-level errors only. invalidCredentials (49) never
// failovers — the identity is shared across replicas, so a rejected bind
// means the credential itself is stale (R8/AE5), not the replica.
type Replicas struct {
	pools []*Pool
	urls  []string
	next  atomic.Uint64
}

// NewReplicas dials one pool per URL (fail-fast: any replica that cannot be
// dialed aborts startup, R15) and starts each pool's health loop.
func NewReplicas(ctx context.Context, urls []string, opts PoolOptions) (*Replicas, error) {
	if len(urls) == 0 {
		return nil, errors.New("ldapx: no replica URLs")
	}
	pools := make([]*Pool, 0, len(urls))
	for _, u := range urls {
		po := opts
		po.Dial.URL = u
		p, err := NewPool(ctx, po)
		if err != nil {
			for _, prev := range pools {
				prev.Close()
			}
			return nil, fmt.Errorf("ldapx: replica %s: %w", u, err)
		}
		pools = append(pools, p)
	}
	return &Replicas{pools: pools, urls: append([]string(nil), urls...)}, nil
}

// Do runs fn against one replica at a time, failing over to the next on
// network-level errors. Each sub-pool already retries once internally, so a
// full sweep is bounded at 2×replicas connection attempts.
func (r *Replicas) Do(ctx context.Context, fn func(Conn) error) error {
	start := r.start()
	var errs []error
	for i := 0; i < len(r.pools); i++ {
		idx := (start + i) % len(r.pools)
		err := r.pools[idx].Do(ctx, fn)
		if err == nil {
			return nil
		}
		if IsInvalidCredentials(err) {
			return err // stale credential: never failover (R8)
		}
		if !isRetryable(err) {
			return err // application-level failure: not a replica problem
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.urls[idx], err))
	}
	return fmt.Errorf("ldapx: all replicas failed: %w", errors.Join(errs...))
}

// Page runs a connection-scoped paged search with the same failover policy
// as Do (R11/AE4). Paged sessions are connection-scoped, so each attempt
// re-runs the whole loop on one replica's connection.
func (r *Replicas) Page(ctx context.Context, opts SearchOptions, page int) (*PageResult, error) {
	start := r.start()
	var errs []error
	for i := 0; i < len(r.pools); i++ {
		idx := (start + i) % len(r.pools)
		res, err := r.pools[idx].Page(ctx, opts, page)
		if err == nil {
			return res, nil
		}
		if IsInvalidCredentials(err) {
			return nil, err
		}
		if !isRetryable(err) {
			return nil, err
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.urls[idx], err))
	}
	return nil, fmt.Errorf("ldapx: all replicas failed: %w", errors.Join(errs...))
}

// VerifyBind checks a credential against any available replica (login gate,
// R6): dial + bind + close per replica, failing over on network errors only.
func (r *Replicas) VerifyBind(ctx context.Context, dn, password string) error {
	start := r.start()
	var errs []error
	for i := 0; i < len(r.pools); i++ {
		idx := (start + i) % len(r.pools)
		err := VerifyBind(ctx, r.pools[idx].opts.Dial, dn, password)
		if err == nil {
			return nil
		}
		if IsInvalidCredentials(err) {
			return err
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.urls[idx], err))
	}
	return fmt.Errorf("ldapx: all replicas failed: %w", errors.Join(errs...))
}

// Close closes every sub-pool.
func (r *Replicas) Close() {
	for _, p := range r.pools {
		p.Close()
	}
}

// start returns the rotating first-replica index for the next operation.
func (r *Replicas) start() int {
	if len(r.pools) == 1 {
		return 0
	}
	return int(r.next.Add(1)-1) % len(r.pools)
}

// Len reports the number of replicas.
func (r *Replicas) Len() int { return len(r.pools) }

// URL returns the configured replica URLs (for diagnostics).
func (r *Replicas) URL() []string { return r.urls }
