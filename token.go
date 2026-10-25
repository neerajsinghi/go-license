package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	// tokenPrefix identifies format version 1.
	tokenPrefix = "lic1"
	// payloadVersion is the "v" claim of format version 1.
	payloadVersion = 1
	// MaxTokenSize is the largest token, in bytes, that will be parsed.
	MaxTokenSize = 64 << 10
)

var b64 = base64.RawURLEncoding.Strict()

// claims is the wire form of a License.
type claims struct {
	V         int               `json:"v"`
	ID        string            `json:"id"`
	Licensee  string            `json:"sub"`
	IssuedAt  int64             `json:"iat"`
	NotBefore int64             `json:"nbf,omitempty"`
	ExpiresAt int64             `json:"exp,omitempty"`
	Seats     int               `json:"seats,omitempty"`
	Instances int               `json:"inst,omitempty"`
	Features  []string          `json:"feat,omitempty"`
	Metadata  map[string]string `json:"meta,omitempty"`
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

func toClaims(l *License) claims {
	return claims{
		V:         payloadVersion,
		ID:        l.ID,
		Licensee:  l.Licensee,
		IssuedAt:  unixOrZero(l.IssuedAt),
		NotBefore: unixOrZero(l.NotBefore),
		ExpiresAt: unixOrZero(l.ExpiresAt),
		Seats:     l.MaxSeats,
		Instances: l.MaxInstances,
		Features:  l.Features,
		Metadata:  l.Metadata,
	}
}

func (c *claims) license() *License {
	return &License{
		ID:           c.ID,
		Licensee:     c.Licensee,
		IssuedAt:     timeOrZero(c.IssuedAt),
		NotBefore:    timeOrZero(c.NotBefore),
		ExpiresAt:    timeOrZero(c.ExpiresAt),
		MaxSeats:     c.Seats,
		MaxInstances: c.Instances,
		Features:     c.Features,
		Metadata:     c.Metadata,
	}
}

// signingInput returns the bytes covered by the signature. Including the
// prefix binds the signature to the format version.
func signingInput(payloadB64 string) []byte {
	return []byte(tokenPrefix + "." + payloadB64)
}

func encodeToken(priv ed25519.PrivateKey, payload []byte) string {
	p := b64.EncodeToString(payload)
	sig := ed25519.Sign(priv, signingInput(p))
	return tokenPrefix + "." + p + "." + b64.EncodeToString(sig)
}

// splitToken parses the token envelope without checking the signature.
func splitToken(token string) (payloadB64 string, payload, sig []byte, err error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", nil, nil, fmt.Errorf("%w: empty token", ErrMalformed)
	}
	if len(token) > MaxTokenSize {
		return "", nil, nil, fmt.Errorf("%w: token larger than %d bytes", ErrMalformed, MaxTokenSize)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, nil, fmt.Errorf("%w: expected 3 dot-separated parts, got %d", ErrMalformed, len(parts))
	}
	if parts[0] != tokenPrefix {
		if strings.HasPrefix(parts[0], "lic") {
			return "", nil, nil, fmt.Errorf("%w: %q", ErrUnsupportedVersion, parts[0])
		}
		return "", nil, nil, fmt.Errorf("%w: unknown prefix %q", ErrMalformed, parts[0])
	}
	payload, err = b64.DecodeString(parts[1])
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err = b64.DecodeString(parts[2])
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return "", nil, nil, fmt.Errorf("%w: signature is %d bytes, want %d", ErrMalformed, len(sig), ed25519.SignatureSize)
	}
	return parts[1], payload, sig, nil
}

// decodeClaims unmarshals and sanity-checks a payload.
func decodeClaims(payload []byte) (*claims, error) {
	var c claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: payload JSON: %v", ErrMalformed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after payload", ErrMalformed)
	}
	if c.V != payloadVersion {
		return nil, fmt.Errorf("%w: payload version %d", ErrUnsupportedVersion, c.V)
	}
	switch {
	case c.ID == "":
		return nil, fmt.Errorf("%w: missing license id", ErrMalformed)
	case c.Licensee == "":
		return nil, fmt.Errorf("%w: missing licensee", ErrMalformed)
	case c.IssuedAt <= 0:
		return nil, fmt.Errorf("%w: missing issued-at", ErrMalformed)
	case c.Seats < 0 || c.Instances < 0:
		return nil, fmt.Errorf("%w: negative limit", ErrMalformed)
	}
	return &c, nil
}

// ParseUnverified decodes a token WITHOUT checking its signature or validity
// window. Use it only for display or debugging (e.g. "golicense inspect");
// never make licensing decisions based on its result.
func ParseUnverified(token string) (*License, error) {
	_, payload, _, err := splitToken(token)
	if err != nil {
		return nil, err
	}
	c, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	return c.license(), nil
}
