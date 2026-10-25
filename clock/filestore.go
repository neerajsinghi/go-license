package clock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const fileStoreVersion = "v1"

// FileStore is a Store that keeps the high-water mark in a small text file.
// Writes are atomic (write to a temporary file, then rename).
//
// When a key is supplied, every saved value carries an HMAC-SHA256 tag and
// Load returns ErrStateTampered if the tag is missing or wrong. Deleting the
// file entirely resets the state; applications that care should treat a
// missing state file on a previously activated install as suspicious.
type FileStore struct {
	path string
	key  []byte
}

// NewFileStore returns a FileStore backed by path. key may be nil to disable
// integrity protection.
func NewFileStore(path string, key []byte) *FileStore {
	k := make([]byte, len(key))
	copy(k, key)
	return &FileStore{path: path, key: k}
}

// Path returns the file the store reads and writes.
func (s *FileStore) Path() string { return s.path }

// Load implements Store. A missing file yields the zero time.
func (s *FileStore) Load() (time.Time, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("clock: read state: %w", err)
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 || fields[0] != fileStoreVersion {
		return time.Time{}, fmt.Errorf("%w: unrecognised format", ErrStateTampered)
	}
	nanos, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: bad timestamp", ErrStateTampered)
	}
	if len(s.key) > 0 {
		if len(fields) != 3 {
			return time.Time{}, fmt.Errorf("%w: missing integrity tag", ErrStateTampered)
		}
		got, err := hex.DecodeString(fields[2])
		if err != nil || !hmac.Equal(got, s.mac(fields[1])) {
			return time.Time{}, fmt.Errorf("%w: integrity tag mismatch", ErrStateTampered)
		}
	} else if len(fields) > 3 {
		return time.Time{}, fmt.Errorf("%w: unrecognised format", ErrStateTampered)
	}
	return time.Unix(0, nanos).UTC(), nil
}

// Save implements Store.
func (s *FileStore) Save(t time.Time) error {
	ts := strconv.FormatInt(t.UnixNano(), 10)
	line := fileStoreVersion + " " + ts
	if len(s.key) > 0 {
		line += " " + hex.EncodeToString(s.mac(ts))
	}
	line += "\n"

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("clock: create state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".clockstate-*")
	if err != nil {
		return fmt.Errorf("clock: write state: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.WriteString(line); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("clock: write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("clock: write state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("clock: write state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("clock: write state: %w", err)
	}
	return nil
}

func (s *FileStore) mac(ts string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("go-license/clock/" + fileStoreVersion + "\x00" + ts))
	return m.Sum(nil)
}
