// Package meter implements a tamper-evident, append-only usage log.
//
// Each record is one JSON line carrying a sequence number, a timestamp, an
// event name, a quantity, optional metadata, the hash of the previous record
// and its own hash. The hash covers every other field, including the previous
// hash, so the records form a chain: editing a record, deleting one from the
// middle, or reordering records breaks the chain and is reported by Verify.
//
// With a secret key the hash is HMAC-SHA256, so only holders of the key can
// produce a valid chain. Without a key it is plain SHA-256, which detects
// accidental corruption and naive edits but not an attacker who recomputes
// the whole chain.
//
// A hash chain cannot by itself reveal that records were cut off the end of
// the log. Persist a Checkpoint (for example alongside the license or report
// it to a server) and pass it to Verify with WithCheckpoint to detect tail
// truncation.
package meter

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// MaxLineSize is the largest record, in bytes, that Verify accepts.
const MaxLineSize = 1 << 20

// genesisHash is the Prev value of the first record.
var genesisHash = strings.Repeat("0", sha256.Size*2)

// ErrTampered is matched (via errors.Is) by every integrity failure reported
// by Verify.
var ErrTampered = errors.New("meter: log integrity check failed")

// ErrInvalidEvent is returned by Append for an empty event name.
var ErrInvalidEvent = errors.New("meter: event name must not be empty")

// ChainError pinpoints where verification failed. It matches ErrTampered.
type ChainError struct {
	// Line is the 1-based line number of the offending record (0 when the
	// failure concerns the log as a whole, e.g. a checkpoint mismatch).
	Line int
	// Seq is the sequence number that was expected at that point.
	Seq uint64
	// Reason is a human-readable description.
	Reason string
}

// Error implements error.
func (e *ChainError) Error() string {
	if e.Line == 0 {
		return "meter: log integrity check failed: " + e.Reason
	}
	return fmt.Sprintf("meter: log integrity check failed at line %d (seq %d): %s", e.Line, e.Seq, e.Reason)
}

// Is reports whether target is ErrTampered.
func (e *ChainError) Is(target error) bool { return target == ErrTampered }

// Record is one metered event.
type Record struct {
	Seq      uint64            `json:"seq"`
	Time     time.Time         `json:"ts"`
	Event    string            `json:"event"`
	Quantity int64             `json:"qty"`
	Meta     map[string]string `json:"meta,omitempty"`
	Prev     string            `json:"prev"`
	Hash     string            `json:"hash"`
}

// body is the hashed portion of a Record (everything except Hash).
type body struct {
	Seq      uint64            `json:"seq"`
	Time     time.Time         `json:"ts"`
	Event    string            `json:"event"`
	Quantity int64             `json:"qty"`
	Meta     map[string]string `json:"meta,omitempty"`
	Prev     string            `json:"prev"`
}

func computeHash(key []byte, r *Record) (string, error) {
	b, err := json.Marshal(body{Seq: r.Seq, Time: r.Time, Event: r.Event, Quantity: r.Quantity, Meta: r.Meta, Prev: r.Prev})
	if err != nil {
		return "", err
	}
	var h hash.Hash
	if len(key) > 0 {
		h = hmac.New(sha256.New, key)
	} else {
		h = sha256.New()
	}
	h.Write([]byte("go-license/meter/v1\x00"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Checkpoint identifies the head of a log at some point in time.
type Checkpoint struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// Summary is the result of a successful Verify.
type Summary struct {
	// Records is the number of records in the log.
	Records int
	// Head is the checkpoint of the last record (zero for an empty log).
	Head Checkpoint
	// Totals sums Quantity per event name.
	Totals map[string]int64
}

// VerifyOption configures Verify.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	checkpoint *Checkpoint
}

// WithCheckpoint requires the log to contain the record identified by cp,
// which detects records deleted from the end of the log since cp was taken.
func WithCheckpoint(cp Checkpoint) VerifyOption {
	return func(c *verifyConfig) { c.checkpoint = &cp }
}

// Verify reads a log from r and checks the integrity of the whole chain. It
// returns a *ChainError (matching ErrTampered) on the first inconsistency.
func Verify(r io.Reader, key []byte, opts ...VerifyOption) (Summary, error) {
	var cfg verifyConfig
	for _, o := range opts {
		o(&cfg)
	}
	sum := Summary{Totals: map[string]int64{}}
	prev := genesisHash
	checkpointSeen := false

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineSize)
	line := 0
	for sc.Scan() {
		line++
		want := uint64(line)
		raw := sc.Bytes()
		if len(raw) == 0 {
			return Summary{}, &ChainError{Line: line, Seq: want, Reason: "empty line"}
		}
		var rec Record
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return Summary{}, &ChainError{Line: line, Seq: want, Reason: "malformed record: " + err.Error()}
		}
		if dec.More() {
			return Summary{}, &ChainError{Line: line, Seq: want, Reason: "trailing data after record"}
		}
		if rec.Seq != want {
			return Summary{}, &ChainError{Line: line, Seq: want, Reason: fmt.Sprintf("sequence %d out of order (record deleted or reordered)", rec.Seq)}
		}
		if rec.Prev != prev {
			return Summary{}, &ChainError{Line: line, Seq: want, Reason: "previous-hash link broken (record deleted, inserted or reordered)"}
		}
		h, err := computeHash(key, &rec)
		if err != nil {
			return Summary{}, &ChainError{Line: line, Seq: want, Reason: "cannot encode record: " + err.Error()}
		}
		if !hmac.Equal([]byte(h), []byte(rec.Hash)) {
			return Summary{}, &ChainError{Line: line, Seq: want, Reason: "hash mismatch (record edited or wrong key)"}
		}
		if cfg.checkpoint != nil && cfg.checkpoint.Seq == rec.Seq {
			if cfg.checkpoint.Hash != rec.Hash {
				return Summary{}, &ChainError{Line: line, Seq: want, Reason: "record does not match checkpoint"}
			}
			checkpointSeen = true
		}
		prev = rec.Hash
		sum.Records++
		sum.Head = Checkpoint{Seq: rec.Seq, Hash: rec.Hash}
		sum.Totals[rec.Event] += rec.Quantity
	}
	if err := sc.Err(); err != nil {
		return Summary{}, &ChainError{Line: line + 1, Seq: uint64(line + 1), Reason: "read error: " + err.Error()}
	}
	if cfg.checkpoint != nil && cfg.checkpoint.Seq > 0 && !checkpointSeen {
		return Summary{}, &ChainError{Reason: fmt.Sprintf("checkpoint seq %d not found (log truncated)", cfg.checkpoint.Seq)}
	}
	return sum, nil
}

// VerifyFile is Verify for a file on disk.
func VerifyFile(path string, key []byte, opts ...VerifyOption) (Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return Summary{}, err
	}
	defer f.Close()
	return Verify(f, key, opts...)
}

// Option configures a Log.
type Option func(*Log)

// WithClock overrides the time source used to stamp records.
func WithClock(now func() time.Time) Option {
	return func(l *Log) {
		if now != nil {
			l.now = now
		}
	}
}

// WithoutSync disables the fsync after each append. This is faster but a
// crash may lose the most recent records.
func WithoutSync() Option {
	return func(l *Log) { l.sync = false }
}

// Log is an append-only, hash-chained usage log backed by a file. It is safe
// for concurrent use within one process; do not open the same file from two
// processes at once.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	key  []byte
	now  func() time.Time
	sync bool
	head Checkpoint
}

// Open opens (or creates) the log at path. An existing log is verified first
// and Open fails with ErrTampered if it is not intact, so new records are
// never appended to a broken chain.
func Open(path string, key []byte, opts ...Option) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("meter: open log: %w", err)
	}
	sum, err := Verify(f, key)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	k := make([]byte, len(key))
	copy(k, key)
	l := &Log{f: f, key: k, now: time.Now, sync: true, head: sum.Head}
	for _, o := range opts {
		o(l)
	}
	return l, nil
}

// Append records an event and returns the written record.
func (l *Log) Append(event string, quantity int64, meta map[string]string) (Record, error) {
	if event == "" {
		return Record{}, ErrInvalidEvent
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return Record{}, os.ErrClosed
	}
	prev := l.head.Hash
	if l.head.Seq == 0 {
		prev = genesisHash
	}
	var m map[string]string
	if len(meta) > 0 {
		m = make(map[string]string, len(meta))
		for k, v := range meta {
			m[k] = v
		}
	}
	rec := Record{
		Seq:      l.head.Seq + 1,
		Time:     l.now().UTC(),
		Event:    event,
		Quantity: quantity,
		Meta:     m,
		Prev:     prev,
	}
	h, err := computeHash(l.key, &rec)
	if err != nil {
		return Record{}, fmt.Errorf("meter: encode record: %w", err)
	}
	rec.Hash = h
	b, err := json.Marshal(rec)
	if err != nil {
		return Record{}, fmt.Errorf("meter: encode record: %w", err)
	}
	b = append(b, '\n')
	if _, err := l.f.Write(b); err != nil {
		return Record{}, fmt.Errorf("meter: write record: %w", err)
	}
	if l.sync {
		if err := l.f.Sync(); err != nil {
			return Record{}, fmt.Errorf("meter: sync log: %w", err)
		}
	}
	l.head = Checkpoint{Seq: rec.Seq, Hash: rec.Hash}
	return rec, nil
}

// Checkpoint returns the head of the log as of the last append.
func (l *Log) Checkpoint() Checkpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
