package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/neerajsinghi/go-license/clock"
)

var now = time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func newPair(t *testing.T) (*Issuer, *Verifier) {
	t.Helper()
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(priv, WithIssuerClock(fixedClock(now)))
	if err != nil {
		t.Fatal(err)
	}
	ver, err := NewVerifier(pub, WithClock(fixedClock(now)))
	if err != nil {
		t.Fatal(err)
	}
	return iss, ver
}

func sample() License {
	return License{
		Licensee:     "Acme Corp",
		ExpiresAt:    now.Add(365 * 24 * time.Hour),
		MaxSeats:     25,
		MaxInstances: 3,
		Features:     []string{"sso", "audit", "sso"},
		Metadata:     map[string]string{"plan": "enterprise"},
	}
}

func TestRoundTrip(t *testing.T) {
	iss, ver := newPair(t)
	in := sample()
	tok, issued, err := iss.IssueLicense(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "lic1.") || strings.Count(tok, ".") != 2 {
		t.Fatalf("unexpected token shape %q", tok)
	}
	got, err := ver.Verify(tok + "\n") // trailing whitespace from files is fine
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || len(got.ID) != 32 {
		t.Fatalf("expected generated 32-char id, got %q", got.ID)
	}
	if got.Licensee != in.Licensee || got.MaxSeats != 25 || got.MaxInstances != 3 {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if !got.IssuedAt.Equal(now) || !got.ExpiresAt.Equal(in.ExpiresAt) || !got.NotBefore.IsZero() {
		t.Fatalf("times mismatch: %+v", got)
	}
	if strings.Join(got.Features, ",") != "audit,sso" {
		t.Fatalf("features not normalised: %v", got.Features)
	}
	if got.Metadata["plan"] != "enterprise" {
		t.Fatalf("metadata lost: %v", got.Metadata)
	}
	if issued.ID != got.ID {
		t.Fatalf("IssueLicense returned id %q, token has %q", issued.ID, got.ID)
	}
	// Input must not be mutated by Issue.
	if len(in.Features) != 3 || in.ID != "" {
		t.Fatalf("Issue mutated input: %+v", in)
	}
}

func TestDeterministicID(t *testing.T) {
	_, priv, _ := GenerateKey(nil)
	iss, _ := NewIssuer(priv, WithRandom(bytes.NewReader(make([]byte, 16))), WithIssuerClock(fixedClock(now)))
	tok, err := iss.Issue(License{Licensee: "x"})
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	if l.ID != strings.Repeat("0", 32) {
		t.Fatalf("id = %q", l.ID)
	}
}

func TestValidityWindow(t *testing.T) {
	iss, _ := newPair(t)
	pub := iss.PublicKey()
	day := 24 * time.Hour
	tests := []struct {
		name    string
		lic     License
		at      time.Time
		leeway  time.Duration
		wantErr error
	}{
		{"active", License{Licensee: "a", ExpiresAt: now.Add(day)}, now, 0, nil},
		{"perpetual", License{Licensee: "a"}, now.Add(100 * 365 * day), 0, nil},
		{"expired", License{Licensee: "a", ExpiresAt: now.Add(day)}, now.Add(2 * day), 0, ErrExpired},
		{"exactly at expiry", License{Licensee: "a", ExpiresAt: now.Add(day)}, now.Add(day), 0, ErrExpired},
		{"expired within leeway", License{Licensee: "a", ExpiresAt: now.Add(day)}, now.Add(day + time.Minute), 5 * time.Minute, nil},
		{"not yet valid", License{Licensee: "a", NotBefore: now.Add(day)}, now, 0, ErrNotYetValid},
		{"not before within leeway", License{Licensee: "a", NotBefore: now.Add(time.Minute)}, now, 5 * time.Minute, nil},
		{"inside window", License{Licensee: "a", NotBefore: now.Add(day), ExpiresAt: now.Add(3 * day)}, now.Add(2 * day), 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := iss.Issue(tt.lic)
			if err != nil {
				t.Fatal(err)
			}
			v, _ := NewVerifier(pub, WithClock(fixedClock(tt.at)), WithLeeway(tt.leeway))
			_, err = v.Verify(tok)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Fatalf("want %v, got %v", tt.wantErr, err)
			}
			// Signature-only verification ignores the window.
			if _, err := v.VerifySignature(tok); err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
		})
	}
}

func TestWrongKey(t *testing.T) {
	iss, _ := newPair(t)
	_, other := newPair(t)
	tok, err := iss.Issue(sample())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Verify(tok); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// reencode replaces the payload of tok with a modified one, keeping the
// original signature: the classic tampering attack.
func reencode(t *testing.T, tok string, mutate func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	nb, _ := json.Marshal(m)
	return parts[0] + "." + b64.EncodeToString(nb) + "." + parts[2]
}

func TestTamperedPayload(t *testing.T) {
	iss, ver := newPair(t)
	tok, err := iss.Issue(sample())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"extend expiry", func(m map[string]any) { m["exp"] = float64(now.Add(100 * 365 * 24 * time.Hour).Unix()) }},
		{"remove expiry", func(m map[string]any) { delete(m, "exp") }},
		{"add feature", func(m map[string]any) { m["feat"] = []string{"audit", "sso", "unlimited"} }},
		{"raise seats", func(m map[string]any) { m["seats"] = float64(10000) }},
		{"change licensee", func(m map[string]any) { m["sub"] = "Evil Corp" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ver.Verify(reencode(t, tok, tt.mutate)); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("want ErrBadSignature, got %v", err)
			}
		})
	}

	t.Run("flip signature bit", func(t *testing.T) {
		parts := strings.Split(tok, ".")
		sig, _ := b64.DecodeString(parts[2])
		sig[0] ^= 1
		bad := parts[0] + "." + parts[1] + "." + b64.EncodeToString(sig)
		if _, err := ver.Verify(bad); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
	})
}

func TestMalformed(t *testing.T) {
	iss, ver := newPair(t)
	good, _ := iss.Issue(sample())
	parts := strings.Split(good, ".")
	signed := func(payload string) string {
		// Correctly signed by the verifier's own issuer key so that only
		// payload validation can reject it.
		return encodeToken(iss.priv, []byte(payload))
	}

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{"empty", "", ErrMalformed},
		{"whitespace", "   \n", ErrMalformed},
		{"one part", "lic1", ErrMalformed},
		{"two parts", "lic1.abc", ErrMalformed},
		{"four parts", good + ".x", ErrMalformed},
		{"unknown prefix", "jwt." + parts[1] + "." + parts[2], ErrMalformed},
		{"future version prefix", "lic2." + parts[1] + "." + parts[2], ErrUnsupportedVersion},
		{"bad payload base64", "lic1.***." + parts[2], ErrMalformed},
		{"padded base64", "lic1." + parts[1] + "=." + parts[2], ErrMalformed},
		{"bad signature base64", "lic1." + parts[1] + ".!!", ErrMalformed},
		{"short signature", "lic1." + parts[1] + "." + b64.EncodeToString([]byte("short")), ErrMalformed},
		{"too large", "lic1." + strings.Repeat("A", MaxTokenSize) + "." + parts[2], ErrMalformed},
		{"payload not json", signed("hello"), ErrMalformed},
		{"payload trailing data", signed(`{"v":1,"id":"a","sub":"b","iat":5} {}`), ErrMalformed},
		{"payload wrong version", signed(`{"v":2,"id":"a","sub":"b","iat":5}`), ErrUnsupportedVersion},
		{"payload missing id", signed(`{"v":1,"sub":"b","iat":5}`), ErrMalformed},
		{"payload missing licensee", signed(`{"v":1,"id":"a","iat":5}`), ErrMalformed},
		{"payload missing iat", signed(`{"v":1,"id":"a","sub":"b"}`), ErrMalformed},
		{"payload negative seats", signed(`{"v":1,"id":"a","sub":"b","iat":5,"seats":-1}`), ErrMalformed},
		{"payload wrong types", signed(`{"v":1,"id":7,"sub":"b","iat":5}`), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ver.Verify(tt.token)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("want %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestIssueValidation(t *testing.T) {
	iss, _ := newPair(t)
	tests := []struct {
		name string
		lic  License
	}{
		{"missing licensee", License{}},
		{"negative seats", License{Licensee: "a", MaxSeats: -1}},
		{"negative instances", License{Licensee: "a", MaxInstances: -1}},
		{"expiry before issue", License{Licensee: "a", ExpiresAt: now.Add(-time.Hour)}},
		{"expiry equals issue", License{Licensee: "a", ExpiresAt: now}},
		{"expiry before not-before", License{Licensee: "a", NotBefore: now.Add(2 * time.Hour), ExpiresAt: now.Add(time.Hour)}},
		{"empty feature", License{Licensee: "a", Features: []string{"sso", ""}}},
		{"pre-epoch issue", License{Licensee: "a", IssuedAt: time.Unix(-10, 0)}},
		{"huge payload", License{Licensee: strings.Repeat("x", MaxTokenSize)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := iss.Issue(tt.lic); !errors.Is(err, ErrInvalidLicense) {
				t.Fatalf("want ErrInvalidLicense, got %v", err)
			}
		})
	}
}

func TestFeatureGating(t *testing.T) {
	lic := &License{Features: []string{"audit", "sso"}}
	tests := []struct {
		name    string
		require []string
		missing []string
	}{
		{"none required", nil, nil},
		{"one present", []string{"sso"}, nil},
		{"all present", []string{"sso", "audit"}, nil},
		{"one missing", []string{"sso", "reports"}, []string{"reports"}},
		{"case sensitive", []string{"SSO"}, []string{"SSO"}},
		{"several missing", []string{"a", "sso", "b"}, []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lic.Require(tt.require...)
			if tt.missing == nil {
				if err != nil {
					t.Fatalf("unexpected %v", err)
				}
				return
			}
			var fe *FeatureError
			if !errors.As(err, &fe) || !errors.Is(err, ErrFeatureNotLicensed) {
				t.Fatalf("want *FeatureError, got %v", err)
			}
			if strings.Join(fe.Missing, ",") != strings.Join(tt.missing, ",") {
				t.Fatalf("missing = %v, want %v", fe.Missing, tt.missing)
			}
		})
	}
	if !lic.HasFeature("sso") || lic.HasFeature("nope") {
		t.Fatal("HasFeature wrong")
	}
	var nilLic *License
	if nilLic.HasFeature("sso") || nilLic.Require("sso") == nil || nilLic.Perpetual() {
		t.Fatal("nil license must grant nothing")
	}
}

func TestLimits(t *testing.T) {
	tests := []struct {
		name      string
		lic       *License
		seats     int
		instances int
		seatErr   bool
		instErr   bool
	}{
		{"unlimited", &License{}, 1 << 20, 1 << 20, false, false},
		{"within", &License{MaxSeats: 10, MaxInstances: 2}, 10, 2, false, false},
		{"over seats", &License{MaxSeats: 10}, 11, 1, true, false},
		{"over instances", &License{MaxInstances: 2}, 1, 3, false, true},
		{"nil license", nil, 1, 1, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.lic.CheckSeats(tt.seats); (err != nil) != tt.seatErr || (err != nil && !errors.Is(err, ErrLimitExceeded)) {
				t.Fatalf("CheckSeats: %v", err)
			}
			if err := tt.lic.CheckInstances(tt.instances); (err != nil) != tt.instErr || (err != nil && !errors.Is(err, ErrLimitExceeded)) {
				t.Fatalf("CheckInstances: %v", err)
			}
		})
	}
}

func TestClockGuardIntegration(t *testing.T) {
	pub, priv, _ := GenerateKey(nil)
	iss, _ := NewIssuer(priv, WithIssuerClock(fixedClock(now)))
	tok, err := iss.Issue(License{Licensee: "a", ExpiresAt: now.Add(30 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	guard := clock.NewGuard(&clock.MemoryStore{}, time.Hour)
	at := now.Add(20 * 24 * time.Hour)
	ver, _ := NewVerifier(pub, WithClock(func() time.Time { return at }), WithClockGuard(guard))
	if _, err := ver.Verify(tok); err != nil {
		t.Fatal(err)
	}
	// The user winds the clock back: still inside the license window, but
	// far behind the high-water mark.
	at = now.Add(time.Hour)
	if _, err := ver.Verify(tok); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("want ErrClockRollback, got %v", err)
	}
	// Bad tokens never advance the guard.
	at = now.Add(1000 * 24 * time.Hour)
	if _, err := ver.Verify("garbage"); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	last, _ := guard.LastSeen()
	if !last.Equal(now.Add(20 * 24 * time.Hour)) {
		t.Fatalf("guard advanced by invalid token: %v", last)
	}
}

func TestKeyEncoding(t *testing.T) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, err := ParsePrivateKey(privPEM)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private round trip: %v", err)
	}
	gotPub, err := ParsePublicKey(pubPEM)
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public round trip: %v", err)
	}

	bad := []struct {
		name string
		fn   func() error
	}{
		{"public as private", func() error { _, err := ParsePrivateKey(pubPEM); return err }},
		{"private as public", func() error { _, err := ParsePublicKey(privPEM); return err }},
		{"garbage private", func() error { _, err := ParsePrivateKey([]byte("nope")); return err }},
		{"garbage public", func() error { _, err := ParsePublicKey(nil); return err }},
		{"corrupt der", func() error {
			_, err := ParsePublicKey([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"))
			return err
		}},
		{"short private marshal", func() error { _, err := MarshalPrivateKey(ed25519.PrivateKey{1}); return err }},
		{"short public marshal", func() error { _, err := MarshalPublicKey(ed25519.PublicKey{1}); return err }},
		{"short issuer key", func() error { _, err := NewIssuer(nil); return err }},
		{"short verifier key", func() error { _, err := NewVerifier(ed25519.PublicKey{1, 2}); return err }},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("want ErrInvalidKey, got %v", err)
			}
		})
	}
}

func TestParseUnverified(t *testing.T) {
	iss, _ := newPair(t)
	tok, _ := iss.Issue(sample())
	tampered := reencode(t, tok, func(m map[string]any) { m["sub"] = "Someone Else" })
	l, err := ParseUnverified(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if l.Licensee != "Someone Else" {
		t.Fatalf("got %q", l.Licensee)
	}
}

func FuzzVerify(f *testing.F) {
	pub, priv, _ := GenerateKey(nil)
	iss, _ := NewIssuer(priv)
	tok, _ := iss.Issue(License{Licensee: "fuzz", Features: []string{"a"}})
	f.Add(tok)
	f.Add("lic1..")
	f.Add("lic1.e30.AAAA")
	ver, _ := NewVerifier(pub)
	f.Fuzz(func(t *testing.T, s string) {
		l, err := ver.Verify(s)
		if err == nil && l == nil {
			t.Fatal("nil license without error")
		}
		_, _ = ParseUnverified(s)
	})
}
