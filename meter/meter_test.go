package meter

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = []byte("meter-test-key")

// writeLog creates a log with n records and returns its path and the lines.
func writeLog(t *testing.T, key []byte, n int) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "usage.log")
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l, err := Open(path, key, WithClock(func() time.Time { ts = ts.Add(time.Second); return ts }), WithoutSync())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := l.Append("api_call", int64(i+1), map[string]string{"i": fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func join(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestAppendAndVerify(t *testing.T) {
	for _, key := range [][]byte{testKey, nil} {
		path, _ := writeLog(t, key, 5)
		sum, err := VerifyFile(path, key)
		if err != nil {
			t.Fatalf("key=%q: %v", key, err)
		}
		if sum.Records != 5 || sum.Head.Seq != 5 || sum.Totals["api_call"] != 15 {
			t.Fatalf("unexpected summary %+v", sum)
		}
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path, _ := writeLog(t, testKey, 3)
	l, err := Open(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := l.Append("export", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 4 {
		t.Fatalf("seq = %d, want 4", rec.Seq)
	}
	cp := l.Checkpoint()
	_ = l.Close()
	sum, err := VerifyFile(path, testKey, WithCheckpoint(cp))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Totals["export"] != 2 || sum.Records != 4 {
		t.Fatalf("summary %+v", sum)
	}
}

func TestEmptyLog(t *testing.T) {
	sum, err := Verify(strings.NewReader(""), testKey)
	if err != nil || sum.Records != 0 {
		t.Fatalf("empty: %+v %v", sum, err)
	}
}

func TestTamperDetection(t *testing.T) {
	_, lines := writeLog(t, testKey, 5)

	tests := []struct {
		name   string
		mutate func([]string) []string
		key    []byte
	}{
		{"edit quantity", func(l []string) []string {
			l[2] = strings.Replace(l[2], `"qty":3`, `"qty":1`, 1)
			return l
		}, testKey},
		{"edit event", func(l []string) []string {
			l[0] = strings.Replace(l[0], `"api_call"`, `"api_cal1"`, 1)
			return l
		}, testKey},
		{"edit metadata", func(l []string) []string {
			l[4] = strings.Replace(l[4], `"i":"4"`, `"i":"9"`, 1)
			return l
		}, testKey},
		{"delete middle record", func(l []string) []string {
			return append(l[:2:2], l[3:]...)
		}, testKey},
		{"delete first record", func(l []string) []string { return l[1:] }, testKey},
		{"swap two records", func(l []string) []string {
			l[1], l[2] = l[2], l[1]
			return l
		}, testKey},
		{"duplicate record", func(l []string) []string {
			return append(l[:3:3], l[2:]...)
		}, testKey},
		{"wrong key", func(l []string) []string { return l }, []byte("other")},
		{"keyed log verified without key", func(l []string) []string { return l }, nil},
		{"garbage line", func(l []string) []string {
			l[3] = "not json"
			return l
		}, testKey},
		{"blank line", func(l []string) []string {
			return append(l[:2:2], append([]string{""}, l[2:]...)...)
		}, testKey},
		{"unknown field", func(l []string) []string {
			l[1] = strings.Replace(l[1], `{"seq"`, `{"x":1,"seq"`, 1)
			return l
		}, testKey},
		{"trailing data", func(l []string) []string {
			l[1] += ` {}`
			return l
		}, testKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := append([]string(nil), lines...)
			_, err := Verify(strings.NewReader(join(tt.mutate(cp))), tt.key)
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("want ErrTampered, got %v", err)
			}
			var ce *ChainError
			if !errors.As(err, &ce) {
				t.Fatalf("want *ChainError, got %T", err)
			}
		})
	}
}

func TestTailTruncationNeedsCheckpoint(t *testing.T) {
	path, lines := writeLog(t, testKey, 5)
	full, err := VerifyFile(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	truncated := join(lines[:3])

	// Without a checkpoint a truncated chain is still internally consistent.
	if _, err := Verify(strings.NewReader(truncated), testKey); err != nil {
		t.Fatalf("truncated log without checkpoint: %v", err)
	}
	// With a checkpoint the truncation is caught.
	_, err = Verify(strings.NewReader(truncated), testKey, WithCheckpoint(full.Head))
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
	// A checkpoint with the right seq but wrong hash is caught too.
	_, err = Verify(strings.NewReader(join(lines)), testKey, WithCheckpoint(Checkpoint{Seq: 2, Hash: full.Head.Hash}))
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered for bad checkpoint hash, got %v", err)
	}
}

func TestOpenRefusesBrokenLog(t *testing.T) {
	path, lines := writeLog(t, testKey, 3)
	lines[1] = strings.Replace(lines[1], `"qty":2`, `"qty":200`, 1)
	if err := os.WriteFile(path, []byte(join(lines)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testKey); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestAppendValidation(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "log"), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append("", 1, nil); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("want ErrInvalidEvent, got %v", err)
	}
	_ = l.Close()
	if _, err := l.Append("x", 1, nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}
}

func TestConcurrentAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	l, err := Open(path, testKey, WithoutSync())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if _, err := l.Append("tick", 1, nil); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	_ = l.Close()
	sum, err := VerifyFile(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Records != 200 || sum.Totals["tick"] != 200 {
		t.Fatalf("summary %+v", sum)
	}
}

func TestOverlongLine(t *testing.T) {
	big := bytes.Repeat([]byte("a"), MaxLineSize+10)
	if _, err := Verify(bytes.NewReader(big), nil); !errors.Is(err, ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}
