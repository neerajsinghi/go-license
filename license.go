// Package license issues and verifies offline, Ed25519-signed license keys
// and provides feature gating for Go applications.
//
// A vendor holds an Ed25519 private key and uses an Issuer to sign License
// values into compact tokens:
//
//	lic1.<base64url(JSON payload)>.<base64url(signature)>
//
// The application embeds only the public key and uses a Verifier to check
// tokens without any network access. The verified *License then answers
// questions such as HasFeature("sso") or CheckSeats(n).
//
// Related packages: clock detects system-clock rollback (plug a clock.Guard
// into the Verifier with WithClockGuard), and meter keeps a tamper-evident
// usage log.
package license

import (
	"slices"
	"time"
)

// License is the set of claims carried by a license token. Times have
// one-second precision once encoded.
type License struct {
	// ID uniquely identifies the license. Issuer.Issue generates a random
	// ID when it is empty.
	ID string
	// Licensee is the customer the license was issued to. Required.
	Licensee string
	// IssuedAt is when the license was signed. Issuer.Issue sets it to the
	// current time when zero.
	IssuedAt time.Time
	// NotBefore, if non-zero, is the earliest time the license is valid.
	NotBefore time.Time
	// ExpiresAt, if non-zero, is when the license stops being valid. A
	// zero value means the license never expires.
	ExpiresAt time.Time
	// MaxSeats is the number of licensed users; 0 means unlimited.
	MaxSeats int
	// MaxInstances is the number of licensed installs/instances; 0 means
	// unlimited.
	MaxInstances int
	// Features lists enabled feature flags. Issuer.Issue sorts and
	// de-duplicates it.
	Features []string
	// Metadata carries arbitrary vendor-defined key/value pairs.
	Metadata map[string]string
}

// HasFeature reports whether the license grants the named feature. Feature
// names are case-sensitive. A nil license grants nothing.
func (l *License) HasFeature(name string) bool {
	if l == nil {
		return false
	}
	return slices.Contains(l.Features, name)
}

// Require returns nil if the license grants every named feature, and a
// *FeatureError (matching ErrFeatureNotLicensed) listing the missing ones
// otherwise.
func (l *License) Require(features ...string) error {
	var missing []string
	for _, f := range features {
		if !l.HasFeature(f) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return &FeatureError{Missing: missing}
	}
	return nil
}

// CheckSeats returns a *LimitError if n exceeds MaxSeats (when limited).
func (l *License) CheckSeats(n int) error {
	if l == nil {
		return &LimitError{Kind: "seats", Requested: n}
	}
	return checkLimit("seats", l.MaxSeats, n)
}

// CheckInstances returns a *LimitError if n exceeds MaxInstances (when
// limited).
func (l *License) CheckInstances(n int) error {
	if l == nil {
		return &LimitError{Kind: "instances", Requested: n}
	}
	return checkLimit("instances", l.MaxInstances, n)
}

func checkLimit(kind string, limit, n int) error {
	if limit > 0 && n > limit {
		return &LimitError{Kind: kind, Limit: limit, Requested: n}
	}
	return nil
}

// Perpetual reports whether the license has no expiry.
func (l *License) Perpetual() bool { return l != nil && l.ExpiresAt.IsZero() }

// ValidAt checks the license's time window against t, allowing leeway of
// clock skew on both ends. It returns an error wrapping ErrNotYetValid or
// ErrExpired, or nil.
func (l *License) ValidAt(t time.Time, leeway time.Duration) error {
	if l == nil {
		return ErrMalformed
	}
	if leeway < 0 {
		leeway = 0
	}
	if !l.NotBefore.IsZero() && t.Add(leeway).Before(l.NotBefore) {
		return &timeError{base: ErrNotYetValid, at: l.NotBefore}
	}
	if !l.ExpiresAt.IsZero() && !t.Add(-leeway).Before(l.ExpiresAt) {
		return &timeError{base: ErrExpired, at: l.ExpiresAt}
	}
	return nil
}

type timeError struct {
	base error
	at   time.Time
}

func (e *timeError) Error() string {
	switch e.base {
	case ErrExpired:
		return "license: expired at " + e.at.UTC().Format(time.RFC3339)
	default:
		return "license: not valid before " + e.at.UTC().Format(time.RFC3339)
	}
}

func (e *timeError) Unwrap() error { return e.base }

// clone returns a deep copy so callers cannot mutate shared state.
func (l License) clone() License {
	l.Features = slices.Clone(l.Features)
	if l.Metadata != nil {
		m := make(map[string]string, len(l.Metadata))
		for k, v := range l.Metadata {
			m[k] = v
		}
		l.Metadata = m
	}
	return l
}
