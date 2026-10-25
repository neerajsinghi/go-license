package license

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"time"

	"github.com/neerajsinghi/go-license/clock"
)

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithClock overrides the time source used for expiry checks.
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) {
		if now != nil {
			v.now = now
		}
	}
}

// WithLeeway tolerates clock skew of up to d when checking not-before and
// expiry.
func WithLeeway(d time.Duration) VerifierOption {
	return func(v *Verifier) {
		if d > 0 {
			v.leeway = d
		}
	}
}

// WithClockGuard makes every Verify call record the current time in g and
// fail with ErrClockRollback if the system clock has been wound back. The
// guard is consulted only for tokens with a valid signature.
func WithClockGuard(g *clock.Guard) VerifierOption {
	return func(v *Verifier) { v.guard = g }
}

// Verifier checks license tokens against an Ed25519 public key. It is safe
// for concurrent use.
type Verifier struct {
	pub    ed25519.PublicKey
	now    func() time.Time
	leeway time.Duration
	guard  *clock.Guard
}

// NewVerifier returns a Verifier for pub.
func NewVerifier(pub ed25519.PublicKey, opts ...VerifierOption) (*Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d", ErrInvalidKey, len(pub), ed25519.PublicKeySize)
	}
	v := &Verifier{pub: slices.Clone(pub), now: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// Verify decodes token, checks its signature, consults the clock guard (if
// any) and checks the validity window. On success it returns the license.
//
// Errors wrap ErrMalformed, ErrUnsupportedVersion, ErrBadSignature,
// ErrClockRollback, ErrNotYetValid or ErrExpired.
func (v *Verifier) Verify(token string) (*License, error) {
	l, err := v.VerifySignature(token)
	if err != nil {
		return nil, err
	}
	now := v.now()
	if v.guard != nil {
		if err := v.guard.Observe(now); err != nil {
			return nil, err
		}
	}
	if err := l.ValidAt(now, v.leeway); err != nil {
		return nil, err
	}
	return l, nil
}

// VerifySignature checks only the token's encoding and signature, ignoring
// the validity window and clock guard. It is useful for tooling that wants
// to show an expired-but-authentic license.
func (v *Verifier) VerifySignature(token string) (*License, error) {
	payloadB64, payload, sig, err := splitToken(token)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(v.pub, signingInput(payloadB64), sig) {
		return nil, ErrBadSignature
	}
	c, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	return c.license(), nil
}
