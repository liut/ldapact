package session

import (
	"encoding/json"
	"time"

	"go.etcd.io/bbolt"
)

// Sweep deletes all expired sessions. Called by the periodic sweeper and
// directly in tests (KTD 7: expired entries removed within 5 minutes).
func (s *Store) Sweep() (int, error) {
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
			if now.After(v.AbsoluteExpiresAt) || now.After(v.ExpiresAt) {
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

// SweepLoop runs Sweep on an interval until stop is closed (5 minutes per
// KTD 7). The store is not closed on stop.
func (s *Store) SweepLoop(interval time.Duration, stop <-chan struct{}) {
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
