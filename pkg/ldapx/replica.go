package ldapx

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Replicas is the replica-aware connection layer (R10/R11): one unbound
// sub-pool per LDAP replica URL, with rotating start points and bounded
// failover on network-level errors only. invalidCredentials (49) never
// failovers — the identity is shared across replicas, so a rejected bind
// means the credential itself is stale (R8/AE5), not the replica.
//
// Startup tolerance: a replica that cannot be dialed at startup does not
// abort the process as long as at least one other replica is reachable
// (R11: replica failure is transparent to users). Unreachable replicas are
// retried in the background on the health interval and join the rotation
// when they recover. If every replica fails the initial dial, startup
// aborts with an aggregated error (fail-fast, R15).
type Replicas struct {
	mu       sync.RWMutex
	pools    []*Pool
	poolURLs []string // aligned with pools for accurate diagnostics
	urls     []string
	failed   []string // URLs whose initial dial failed; retried in the background
	opts     PoolOptions
	next     atomic.Uint64
	ctx      context.Context
	cancel   context.CancelFunc
	closed   atomic.Bool
}

// NewReplicas dials one pool per URL and starts each pool's health loop.
// Replicas that fail the initial dial are recorded and retried in the
// background; startup only fails when every replica is unreachable.
func NewReplicas(ctx context.Context, urls []string, opts PoolOptions) (*Replicas, error) {
	if len(urls) == 0 {
		return nil, errors.New("ldapx: no replica URLs")
	}
	childCtx, cancel := context.WithCancel(ctx)
	r := &Replicas{urls: append([]string(nil), urls...), opts: opts, ctx: childCtx, cancel: cancel}
	var errs []error
	for _, u := range urls {
		po := opts
		po.Dial.URL = u
		p, err := NewPool(childCtx, po)
		if err != nil {
			r.failed = append(r.failed, u)
			errs = append(errs, fmt.Errorf("ldapx: replica %s: %w", u, err))
			if opts.Dial.Logger != nil {
				opts.Dial.Logger.Warn("replica unavailable at startup; will retry in the background",
					"event", "ldap.replica.down",
					"url", u,
					"error", err)
			}
			continue
		}
		r.pools = append(r.pools, p)
		r.poolURLs = append(r.poolURLs, u)
	}
	if len(r.pools) == 0 {
		r.cancel()
		return nil, fmt.Errorf("ldapx: all replicas failed at startup: %w", errors.Join(errs...))
	}
	if len(r.failed) > 0 {
		go r.retryLoop()
	}
	return r, nil
}

// Do runs fn against one replica at a time, failing over to the next on
// network-level errors. Each sub-pool already retries once internally, so a
// full sweep is bounded at 2×replicas connection attempts.
func (r *Replicas) Do(ctx context.Context, fn func(Conn) error) error {
	pools, urls := r.snapshotWithURLs()
	if len(pools) == 0 {
		return errors.New("ldapx: no replicas available")
	}
	start := r.rotate(len(pools))
	var errs []error
	for i := 0; i < len(pools); i++ {
		idx := (start + i) % len(pools)
		err := pools[idx].Do(ctx, fn)
		if err == nil {
			return nil
		}
		if IsInvalidCredentials(err) {
			return err // stale credential: never failover (R8)
		}
		if !isRetryable(err) {
			return err // application-level failure: not a replica problem
		}
		errs = append(errs, fmt.Errorf("%s: %w", urls[idx], err))
	}
	return fmt.Errorf("ldapx: all replicas failed: %w", errors.Join(errs...))
}

// Page runs a connection-scoped paged search with the same failover policy
// as Do (R11/AE4). Paged sessions are connection-scoped, so each attempt
// re-runs the whole loop on one replica's connection.
func (r *Replicas) Page(ctx context.Context, opts SearchOptions, page int) (*PageResult, error) {
	pools, urls := r.snapshotWithURLs()
	if len(pools) == 0 {
		return nil, errors.New("ldapx: no replicas available")
	}
	start := r.rotate(len(pools))
	var errs []error
	for i := 0; i < len(pools); i++ {
		idx := (start + i) % len(pools)
		res, err := pools[idx].Page(ctx, opts, page)
		if err == nil {
			return res, nil
		}
		if IsInvalidCredentials(err) {
			return nil, err
		}
		if !isRetryable(err) {
			return nil, err
		}
		errs = append(errs, fmt.Errorf("%s: %w", urls[idx], err))
	}
	return nil, fmt.Errorf("ldapx: all replicas failed: %w", errors.Join(errs...))
}

// VerifyBind checks a credential against any available replica (login gate,
// R6): dial + bind + close per replica, failing over on network errors only.
func (r *Replicas) VerifyBind(ctx context.Context, dn, password string) error {
	pools, urls := r.snapshotWithURLs()
	if len(pools) == 0 {
		return errors.New("ldapx: no replicas available")
	}
	start := r.rotate(len(pools))
	var errs []error
	for i := 0; i < len(pools); i++ {
		idx := (start + i) % len(pools)
		err := VerifyBind(ctx, pools[idx].opts.Dial, dn, password)
		if err == nil {
			return nil
		}
		if IsInvalidCredentials(err) {
			return err
		}
		if !isRetryable(err) && !isDialRetryable(err) {
			// App-level failure (certificate, protocol, busy): it will
			// repeat on every replica, so report it instead of failing over.
			return err
		}
		errs = append(errs, fmt.Errorf("%s: %w", urls[idx], err))
	}
	return fmt.Errorf("ldapx: all replicas failed: %w", errors.Join(errs...))
}

// Close closes every sub-pool.
func (r *Replicas) Close() {
	if r.closed.Swap(true) {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	for _, p := range r.snapshot() {
		p.Close()
	}
}

// start returns the rotating first-replica index for the next operation.
func (r *Replicas) start() int {
	return r.rotate(len(r.snapshot()))
}

// rotate maps the atomic rotation counter onto the current pool count.
func (r *Replicas) rotate(n int) int {
	if n <= 1 {
		return 0
	}
	return int(r.next.Add(1)-1) % n
}

// snapshot returns a copy of the active pools under the read lock.
func (r *Replicas) snapshot() []*Pool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*Pool(nil), r.pools...)
}

// snapshotWithURLs returns the active pools and their URLs under the read
// lock so diagnostics never mislabel a recovered replica.
func (r *Replicas) snapshotWithURLs() ([]*Pool, []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*Pool(nil), r.pools...), append([]string(nil), r.poolURLs...)
}

// Len reports the number of replicas.
func (r *Replicas) Len() int { return len(r.snapshot()) }

// URL returns the configured replica URLs (for diagnostics).
func (r *Replicas) URL() []string { return r.urls }

// retryLoop periodically retries replicas that were unreachable at startup,
// promoting them into the rotation once they dial successfully.
func (r *Replicas) retryLoop() {
	interval := r.opts.HealthInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			r.retryFailed()
		}
	}
}

// retryFailed dials each failed replica and appends recovered pools to the
// rotation. Dials happen outside the lock so a slow replica never blocks
// operations; the pool health loop continues to maintain recovered pools.
func (r *Replicas) retryFailed() {
	r.mu.RLock()
	if r.closed.Load() {
		r.mu.RUnlock()
		return
	}
	pending := append([]string(nil), r.failed...)
	r.mu.RUnlock()
	for _, u := range pending {
		po := r.opts
		po.Dial.URL = u
		p, err := NewPool(r.ctx, po)
		if err != nil {
			if r.opts.Dial.Logger != nil {
				r.opts.Dial.Logger.Warn("replica still unavailable; retrying",
					"event", "ldap.replica.retry_failed",
					"url", u,
					"error", err)
			}
			continue
		}
		r.mu.Lock()
		if r.closed.Load() {
			r.mu.Unlock()
			p.Close()
			return
		}
		r.pools = append(r.pools, p)
		r.poolURLs = append(r.poolURLs, u)
		r.failed = removeString(r.failed, u)
		r.mu.Unlock()
		if r.opts.Dial.Logger != nil {
			r.opts.Dial.Logger.Info("replica recovered and joined the rotation",
				"event", "ldap.replica.up",
				"url", u)
		}
	}
}

func removeString(vs []string, want string) []string {
	out := vs[:0]
	for _, v := range vs {
		if v != want {
			out = append(out, v)
		}
	}
	return out
}
