package clock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var base = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestGuardObserve(t *testing.T) {
	tests := []struct {
		name      string
		tolerance time.Duration
		times     []time.Time
		wantErrAt int // index of the observation expected to fail, -1 for none
		wantLast  time.Time
	}{
		{
			name:      "monotonic forward",
			tolerance: time.Minute,
			times:     []time.Time{base, base.Add(time.Hour), base.Add(2 * time.Hour)},
			wantErrAt: -1,
			wantLast:  base.Add(2 * time.Hour),
		},
		{
			name:      "small skew within tolerance",
			tolerance: 5 * time.Minute,
			times:     []time.Time{base, base.Add(-4 * time.Minute)},
			wantErrAt: -1,
			wantLast:  base, // high-water mark is not lowered
		},
		{
			name:      "rollback beyond tolerance",
			tolerance: 5 * time.Minute,
			times:     []time.Time{base, base.Add(-24 * time.Hour)},
			wantErrAt: 1,
			wantLast:  base,
		},
		{
			name:      "zero tolerance rejects any rewind",
			tolerance: 0,
			times:     []time.Time{base, base.Add(-time.Second)},
			wantErrAt: 1,
			wantLast:  base,
		},
		{
			name:      "negative tolerance treated as zero",
			tolerance: -time.Hour,
			times:     []time.Time{base, base},
			wantErrAt: -1,
			wantLast:  base,
		},
		{
			name:      "recovers after clock fixed",
			tolerance: time.Minute,
			times:     []time.Time{base, base.Add(-time.Hour), base.Add(time.Hour)},
			wantErrAt: 1,
			wantLast:  base.Add(time.Hour),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGuard(&MemoryStore{}, tt.tolerance)
			for i, ts := range tt.times {
				err := g.Observe(ts)
				if i == tt.wantErrAt {
					if !errors.Is(err, ErrClockRollback) {
						t.Fatalf("observation %d: want ErrClockRollback, got %v", i, err)
					}
					var re *RollbackError
					if !errors.As(err, &re) || !re.Now.Equal(ts) {
						t.Fatalf("observation %d: want *RollbackError with Now=%v, got %#v", i, ts, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("observation %d: unexpected error %v", i, err)
				}
			}
			last, err := g.LastSeen()
			if err != nil {
				t.Fatal(err)
			}
			if !last.Equal(tt.wantLast) {
				t.Fatalf("last seen = %v, want %v", last, tt.wantLast)
			}
		})
	}
}

func TestGuardCheckUsesInjectedClock(t *testing.T) {
	now := base
	g := NewGuard(&MemoryStore{}, time.Minute, WithNow(func() time.Time { return now }))
	if _, err := g.Check(); err != nil {
		t.Fatal(err)
	}
	now = base.Add(-time.Hour)
	got, err := g.Check()
	if !errors.Is(err, ErrClockRollback) {
		t.Fatalf("want rollback, got %v", err)
	}
	if !got.Equal(now) {
		t.Fatalf("Check returned %v, want %v", got, now)
	}
}

func TestGuardNilStore(t *testing.T) {
	if err := NewGuard(nil, 0).Observe(base); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestGuardConcurrent(t *testing.T) {
	g := NewGuard(&MemoryStore{}, time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := g.Observe(base.Add(time.Duration(i) * time.Second)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	last, _ := g.LastSeen()
	if !last.Equal(base.Add(49 * time.Second)) {
		t.Fatalf("last = %v", last)
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	for _, key := range [][]byte{nil, []byte("secret")} {
		path := filepath.Join(t.TempDir(), "sub", "state")
		s := NewFileStore(path, key)
		got, err := s.Load()
		if err != nil || !got.IsZero() {
			t.Fatalf("empty load = %v, %v", got, err)
		}
		ts := base.Add(123456789 * time.Nanosecond)
		if err := s.Save(ts); err != nil {
			t.Fatal(err)
		}
		got, err = NewFileStore(path, key).Load()
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(ts) {
			t.Fatalf("got %v, want %v", got, ts)
		}
	}
}

func TestFileStorePersistsAcrossGuards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	key := []byte("k")
	if err := NewGuard(NewFileStore(path, key), time.Minute).Observe(base); err != nil {
		t.Fatal(err)
	}
	// A new process (new guard, same file) with the clock wound back.
	err := NewGuard(NewFileStore(path, key), time.Minute).Observe(base.Add(-48 * time.Hour))
	if !errors.Is(err, ErrClockRollback) {
		t.Fatalf("want rollback across restarts, got %v", err)
	}
}

func TestFileStoreTamper(t *testing.T) {
	key := []byte("secret")
	tests := []struct {
		name    string
		mutate  func(string) string
		key     []byte
		wantErr error
	}{
		{"edit timestamp with key", func(s string) string {
			f := strings.Fields(s)
			return f[0] + " 1 " + f[2]
		}, key, ErrStateTampered},
		{"strip tag with key", func(s string) string {
			f := strings.Fields(s)
			return f[0] + " " + f[1]
		}, key, ErrStateTampered},
		{"garbage", func(string) string { return "hello" }, key, ErrStateTampered},
		{"bad version", func(string) string { return "v9 1" }, nil, ErrStateTampered},
		{"non numeric", func(string) string { return "v1 abc" }, nil, ErrStateTampered},
		{"empty", func(string) string { return "" }, nil, ErrStateTampered},
		{"untouched", func(s string) string { return s }, key, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			s := NewFileStore(path, tt.key)
			if err := s.Save(base); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tt.mutate(string(b))), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = s.Load()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("want %v, got %v", tt.wantErr, err)
			}
		})
	}
}
