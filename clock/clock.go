// Package clock detects system clock rollback.
//
// Offline license checks are only as trustworthy as the clock they compare
// against. A user who winds the system clock back can keep using an expired
// license indefinitely. A Guard records the latest time it has ever observed
// in a pluggable Store and reports ErrClockRollback when the current time
// falls behind that high-water mark by more than a configured tolerance.
//
// The default FileStore persists the high-water mark to disk and can
// optionally protect it with an HMAC so casual edits of the state file are
// detected as well.
package clock

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrClockRollback is reported (via errors.Is) when the observed time is
// earlier than the last recorded time by more than the guard's tolerance.
var ErrClockRollback = errors.New("clock: system time moved backwards")

// ErrStateTampered is returned by a Store whose persisted state fails its
// integrity check.
var ErrStateTampered = errors.New("clock: state failed integrity check")

// RollbackError describes a detected rollback. It matches ErrClockRollback
// with errors.Is.
type RollbackError struct {
	// LastSeen is the high-water mark recorded in the store.
	LastSeen time.Time
	// Now is the time that was observed.
	Now time.Time
	// Tolerance is the allowed backwards drift that was exceeded.
	Tolerance time.Duration
}

// Error implements error.
func (e *RollbackError) Error() string {
	return fmt.Sprintf("clock: system time moved backwards by %s (last seen %s, now %s, tolerance %s)",
		e.LastSeen.Sub(e.Now).Round(time.Second), e.LastSeen.Format(time.RFC3339), e.Now.Format(time.RFC3339), e.Tolerance)
}

// Is reports whether target is ErrClockRollback.
func (e *RollbackError) Is(target error) bool { return target == ErrClockRollback }

// Store persists the latest observed time. Implementations must be safe for
// use by a single Guard; the Guard serialises its own calls.
type Store interface {
	// Load returns the last saved time, or the zero time if nothing has
	// been saved yet.
	Load() (time.Time, error)
	// Save records t as the latest observed time.
	Save(t time.Time) error
}

// Option configures a Guard.
type Option func(*Guard)

// WithNow overrides the time source used by Guard.Check. It is mainly useful
// in tests.
func WithNow(now func() time.Time) Option {
	return func(g *Guard) {
		if now != nil {
			g.now = now
		}
	}
}

// Guard detects clock rollback against a Store. It is safe for concurrent
// use.
type Guard struct {
	mu        sync.Mutex
	store     Store
	tolerance time.Duration
	now       func() time.Time
}

// NewGuard returns a Guard that persists its high-water mark in store and
// tolerates backwards movement of up to tolerance (to absorb NTP corrections
// and small skews). A negative tolerance is treated as zero.
func NewGuard(store Store, tolerance time.Duration, opts ...Option) *Guard {
	if tolerance < 0 {
		tolerance = 0
	}
	g := &Guard{store: store, tolerance: tolerance, now: time.Now}
	for _, o := range opts {
		o(g)
	}
	return g
}

// Check observes the current time and returns it together with any rollback
// error.
func (g *Guard) Check() (time.Time, error) {
	now := g.now()
	return now, g.Observe(now)
}

// Observe records now as a time that has been seen. It returns a
// *RollbackError if now is earlier than the stored high-water mark by more
// than the tolerance; in that case the store is left untouched. Times within
// the tolerance are accepted without lowering the high-water mark.
func (g *Guard) Observe(now time.Time) error {
	if g == nil || g.store == nil {
		return errors.New("clock: guard has no store")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	last, err := g.store.Load()
	if err != nil {
		return err
	}
	if !last.IsZero() && last.Sub(now) > g.tolerance {
		return &RollbackError{LastSeen: last, Now: now, Tolerance: g.tolerance}
	}
	if now.After(last) {
		if err := g.store.Save(now); err != nil {
			return err
		}
	}
	return nil
}

// LastSeen returns the stored high-water mark (zero if none).
func (g *Guard) LastSeen() (time.Time, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.store.Load()
}

// MemoryStore is an in-memory Store, useful for tests and for processes that
// only need rollback detection within their own lifetime.
type MemoryStore struct {
	mu sync.Mutex
	t  time.Time
}

// Load implements Store.
func (m *MemoryStore) Load() (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.t, nil
}

// Save implements Store.
func (m *MemoryStore) Save(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t = t
	return nil
}
