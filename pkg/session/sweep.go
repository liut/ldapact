package session

import (
	"encoding/json"
	"time"

	"go.etcd.io/bbolt"
)

// Sweep deletes all expired sessions. Called by the periodic sweeper and
// directly in tests (KTD 7: expired entries removed within 5 minutes).
func (s *BboltStore) Sweep() (int, error) {
	now := s.now()
	var removed int
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(BucketName))
		c := b.Cursor()
		for k, raw := c.First(); k != nil; k, raw = c.Next() {
			var v Value
			if err := json.Unmarshal(raw, &v); err != nil {
				continue // corrupt row: skip; startup corruption check handles the file
			}
			if expired(&v, now) {
				if err := b.Delete(k); err != nil {
					return err
				}
				removed++
			}
		}
		return nil
	})
	return removed, err
}

// sweeper is the minimal surface the shared SweepLoop needs.
type sweeper interface {
	Sweep() (int, error)
}

// sweepLoop runs Sweep on an interval until stop is closed (5 minutes per
// KTD 7). The store is not closed on stop.
func sweepLoop(s sweeper, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_, _ = s.Sweep()
		}
	}
}

// SweepLoop runs Sweep on an interval until stop is closed (5 minutes per
// KTD 7). The store is not closed on stop.
func (s *BboltStore) SweepLoop(interval time.Duration, stop <-chan struct{}) {
	sweepLoop(s, interval, stop)
}

// SweepLoop runs Sweep on an interval until stop is closed (5 minutes per
// KTD 7). The store is not closed on stop.
func (s *MemoryStore) SweepLoop(interval time.Duration, stop <-chan struct{}) {
	sweepLoop(s, interval, stop)
}

// SweepLoopStarter is implemented by backends with a periodic sweeper
// (bbolt, memory). Redis relies on key TTL expiry instead (Sweep is a
// no-op), so it does not implement this.
type SweepLoopStarter interface {
	SweepLoop(interval time.Duration, stop <-chan struct{})
}

// StartSweepLoop runs the periodic sweeper when the backend supports one.
// Callers close stop to stop the loop (the store is not closed).
func StartSweepLoop(s Store, interval time.Duration, stop <-chan struct{}) {
	if sl, ok := s.(SweepLoopStarter); ok {
		go sl.SweepLoop(interval, stop)
	}
}
