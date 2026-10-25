package license

import (
	"errors"
	"fmt"
	"strings"

	"github.com/neerajsinghi/go-license/clock"
)

// Sentinel errors. Errors returned by this package wrap one of these, so
// callers should compare with errors.Is.
var (
	// ErrMalformed means the token could not be decoded: wrong shape, bad
	// base64, bad JSON or missing required claims.
	ErrMalformed = errors.New("license: malformed token")
	// ErrUnsupportedVersion means the token uses a format version this
	// package does not understand.
	ErrUnsupportedVersion = errors.New("license: unsupported token version")
	// ErrBadSignature means the signature does not match the payload under
	// the verifier's public key (tampered token or wrong key).
	ErrBadSignature = errors.New("license: signature verification failed")
	// ErrExpired means the license's expiry time has passed.
	ErrExpired = errors.New("license: expired")
	// ErrNotYetValid means the license's not-before time is in the future.
	ErrNotYetValid = errors.New("license: not yet valid")
	// ErrFeatureNotLicensed is matched by *FeatureError.
	ErrFeatureNotLicensed = errors.New("license: feature not licensed")
	// ErrLimitExceeded is matched by *LimitError.
	ErrLimitExceeded = errors.New("license: limit exceeded")
	// ErrInvalidLicense is returned by Issuer.Issue for license contents that
	// cannot be issued (e.g. missing licensee, expiry before not-before).
	ErrInvalidLicense = errors.New("license: invalid license")
	// ErrInvalidKey means a key has the wrong size or encoding.
	ErrInvalidKey = errors.New("license: invalid key")
	// ErrClockRollback is re-exported from the clock package for
	// convenience; Verify returns it when a configured clock guard detects
	// that the system time moved backwards.
	ErrClockRollback = clock.ErrClockRollback
)

// FeatureError reports features that a license does not grant.
type FeatureError struct {
	// Missing lists the requested features absent from the license, in
	// request order.
	Missing []string
}

// Error implements error.
func (e *FeatureError) Error() string {
	return fmt.Sprintf("license: feature not licensed: %s", strings.Join(e.Missing, ", "))
}

// Is reports whether target is ErrFeatureNotLicensed.
func (e *FeatureError) Is(target error) bool { return target == ErrFeatureNotLicensed }

// LimitError reports a usage count above a license limit.
type LimitError struct {
	// Kind is the limit that was exceeded, e.g. "seats" or "instances".
	Kind string
	// Limit is the licensed maximum.
	Limit int
	// Requested is the count that was checked.
	Requested int
}

// Error implements error.
func (e *LimitError) Error() string {
	return fmt.Sprintf("license: %s limit exceeded: %d requested, %d licensed", e.Kind, e.Requested, e.Limit)
}

// Is reports whether target is ErrLimitExceeded.
func (e *LimitError) Is(target error) bool { return target == ErrLimitExceeded }
