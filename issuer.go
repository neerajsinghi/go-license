package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"
)

// IssuerOption configures an Issuer.
type IssuerOption func(*Issuer)

// WithIssuerClock overrides the time source used for IssuedAt defaults.
func WithIssuerClock(now func() time.Time) IssuerOption {
	return func(i *Issuer) {
		if now != nil {
			i.now = now
		}
	}
}

// WithRandom overrides the randomness source used to generate license IDs.
func WithRandom(r io.Reader) IssuerOption {
	return func(i *Issuer) {
		if r != nil {
			i.rand = r
		}
	}
}

// Issuer signs licenses with an Ed25519 private key. It is safe for
// concurrent use.
type Issuer struct {
	priv ed25519.PrivateKey
	now  func() time.Time
	rand io.Reader
}

// NewIssuer returns an Issuer for priv.
func NewIssuer(priv ed25519.PrivateKey, opts ...IssuerOption) (*Issuer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key is %d bytes, want %d", ErrInvalidKey, len(priv), ed25519.PrivateKeySize)
	}
	i := &Issuer{priv: slices.Clone(priv), now: time.Now, rand: rand.Reader}
	for _, o := range opts {
		o(i)
	}
	return i, nil
}

// PublicKey returns the public key matching the issuer's private key.
func (i *Issuer) PublicKey() ed25519.PublicKey {
	return slices.Clone(i.priv.Public().(ed25519.PublicKey))
}

// Issue validates l, fills in defaults (random ID, IssuedAt = now),
// normalises features (sorted, de-duplicated) and returns the signed token.
// The passed License is not modified.
func (i *Issuer) Issue(l License) (string, error) {
	tok, _, err := i.IssueLicense(l)
	return tok, err
}

// IssueLicense is like Issue but also returns the License exactly as it was
// encoded (with defaults applied and times truncated to seconds).
func (i *Issuer) IssueLicense(l License) (string, *License, error) {
	l = l.clone()
	if l.ID == "" {
		var b [16]byte
		if _, err := io.ReadFull(i.rand, b[:]); err != nil {
			return "", nil, fmt.Errorf("license: generate id: %w", err)
		}
		l.ID = hex.EncodeToString(b[:])
	}
	if l.IssuedAt.IsZero() {
		l.IssuedAt = i.now()
	}
	l.IssuedAt = truncate(l.IssuedAt)
	l.NotBefore = truncate(l.NotBefore)
	l.ExpiresAt = truncate(l.ExpiresAt)
	if len(l.Features) > 0 {
		slices.Sort(l.Features)
		l.Features = slices.Compact(l.Features)
	} else {
		l.Features = nil
	}
	if len(l.Metadata) == 0 {
		l.Metadata = nil
	}
	if err := validateForIssue(&l); err != nil {
		return "", nil, err
	}
	payload, err := json.Marshal(toClaims(&l))
	if err != nil {
		return "", nil, fmt.Errorf("license: encode payload: %w", err)
	}
	if len(payload) > MaxTokenSize/2 {
		return "", nil, fmt.Errorf("%w: payload too large (%d bytes)", ErrInvalidLicense, len(payload))
	}
	return encodeToken(i.priv, payload), &l, nil
}

func truncate(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return time.Unix(t.Unix(), 0).UTC()
}

func validateForIssue(l *License) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidLicense, fmt.Sprintf(format, args...))
	}
	switch {
	case l.Licensee == "":
		return invalid("licensee is required")
	case l.IssuedAt.Unix() <= 0:
		return invalid("issued-at must be after the Unix epoch")
	case !l.NotBefore.IsZero() && l.NotBefore.Unix() <= 0:
		return invalid("not-before must be after the Unix epoch")
	case l.MaxSeats < 0:
		return invalid("max seats must not be negative")
	case l.MaxInstances < 0:
		return invalid("max instances must not be negative")
	}
	if !l.ExpiresAt.IsZero() {
		start := l.IssuedAt
		if !l.NotBefore.IsZero() {
			start = l.NotBefore
		}
		if !l.ExpiresAt.After(start) {
			return invalid("expiry %s is not after the start of validity %s",
				l.ExpiresAt.Format(time.RFC3339), start.Format(time.RFC3339))
		}
	}
	for _, f := range l.Features {
		if f == "" {
			return invalid("feature names must not be empty")
		}
	}
	return nil
}
