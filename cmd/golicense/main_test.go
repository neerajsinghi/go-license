package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var cliNow = time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, now time.Time, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb, func() time.Time { return now })
	return result{code, out.String(), errb.String()}
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "k.pem")
	pub := filepath.Join(dir, "p.pem")
	lic := filepath.Join(dir, "acme.lic")

	if r := runCLI(t, cliNow, "", "keygen", "-priv", priv, "-pub", pub); r.code != 0 {
		t.Fatalf("keygen: %+v", r)
	}
	if fi, err := os.Stat(priv); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key perms: %v %v", fi, err)
	}
	if r := runCLI(t, cliNow, "", "keygen", "-priv", priv, "-pub", pub); r.code != exitUsage {
		t.Fatalf("keygen should refuse to overwrite: %+v", r)
	}

	r := runCLI(t, cliNow, "", "issue", "-key", priv, "-licensee", "Acme Corp", "-id", "LIC-1",
		"-features", "sso, audit", "-expires", "30d", "-seats", "10", "-meta", "plan=pro", "-out", lic)
	if r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}

	tests := []struct {
		name     string
		now      time.Time
		args     []string
		wantCode int
		wantOut  string
	}{
		{"valid", cliNow, []string{"verify", "-pub", pub, lic}, 0, "OK: license LIC-1"},
		{"required features present", cliNow, []string{"verify", "-pub", pub, "-require", "sso,audit", lic}, 0, "OK"},
		{"required feature missing", cliNow, []string{"verify", "-pub", pub, "-require", "reports", lic}, 1, "feature not licensed: reports"},
		{"expired", cliNow.Add(31 * 24 * time.Hour), []string{"verify", "-pub", pub, lic}, 1, "expired"},
		{"expired via -at", cliNow, []string{"verify", "-pub", pub, "-at", "2027-01-01T00:00:00Z", lic}, 1, "expired"},
		{"missing pub flag", cliNow, []string{"verify", lic}, exitUsage, ""},
		{"no file", cliNow, []string{"verify", "-pub", pub}, exitUsage, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runCLI(t, tt.now, "", tt.args...)
			if r.code != tt.wantCode || !strings.Contains(r.stdout, tt.wantOut) {
				t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
			}
		})
	}

	// Wrong key.
	otherPriv, otherPub := filepath.Join(dir, "k2.pem"), filepath.Join(dir, "p2.pem")
	runCLI(t, cliNow, "", "keygen", "-priv", otherPriv, "-pub", otherPub)
	if r := runCLI(t, cliNow, "", "verify", "-pub", otherPub, lic); r.code != 1 || !strings.Contains(r.stdout, "signature") {
		t.Fatalf("wrong key: %+v", r)
	}

	// Stdin input.
	tok, _ := os.ReadFile(lic)
	if r := runCLI(t, cliNow, string(tok), "verify", "-pub", pub, "-"); r.code != 0 {
		t.Fatalf("stdin: %+v", r)
	}

	// Inspect with signature check.
	r = runCLI(t, cliNow, "", "inspect", "-pub", pub, lic)
	if r.code != 0 {
		t.Fatalf("inspect: %+v", r)
	}
	var view inspectView
	if err := json.Unmarshal([]byte(r.stdout), &view); err != nil {
		t.Fatalf("inspect output not JSON: %v\n%s", err, r.stdout)
	}
	if view.ID != "LIC-1" || view.Signature != "valid" || view.Status != "active" || view.Metadata["plan"] != "pro" || view.MaxSeats != 10 {
		t.Fatalf("inspect view %+v", view)
	}
	// Inspect with the wrong key reports an invalid signature.
	if r := runCLI(t, cliNow, "", "inspect", "-pub", otherPub, lic); r.code != 1 || !strings.Contains(r.stdout, "INVALID") {
		t.Fatalf("inspect wrong key: %+v", r)
	}
}

func TestVerifyRollbackState(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "p.pem")
	lic, state := filepath.Join(dir, "a.lic"), filepath.Join(dir, "clock.state")
	runCLI(t, cliNow, "", "keygen", "-priv", priv, "-pub", pub)
	if r := runCLI(t, cliNow, "", "issue", "-key", priv, "-licensee", "A", "-expires", "2027-01-01", "-out", lic); r.code != 0 {
		t.Fatalf("issue: %+v", r)
	}
	if r := runCLI(t, cliNow.Add(48*time.Hour), "", "verify", "-pub", pub, "-state", state, lic); r.code != 0 {
		t.Fatalf("verify: %+v", r)
	}
	r := runCLI(t, cliNow, "", "verify", "-pub", pub, "-state", state, lic)
	if r.code != 1 || !strings.Contains(r.stdout, "backwards") {
		t.Fatalf("expected rollback detection: %+v", r)
	}
}

func TestIssueErrors(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "p.pem")
	runCLI(t, cliNow, "", "keygen", "-priv", priv, "-pub", pub)
	tests := []struct {
		name string
		args []string
		code int
	}{
		{"no args", []string{}, exitUsage},
		{"unknown command", []string{"frobnicate"}, exitUsage},
		{"help", []string{"help"}, exitOK},
		{"issue missing licensee", []string{"issue", "-key", priv}, exitUsage},
		{"issue bad expiry", []string{"issue", "-key", priv, "-licensee", "a", "-expires", "soon"}, exitUsage},
		{"issue bad meta", []string{"issue", "-key", priv, "-licensee", "a", "-meta", "novalue"}, exitUsage},
		{"issue public key as private", []string{"issue", "-key", pub, "-licensee", "a"}, exitInvalid},
		{"issue missing key file", []string{"issue", "-key", filepath.Join(dir, "nope"), "-licensee", "a"}, exitInvalid},
		{"issue expiry in past", []string{"issue", "-key", priv, "-licensee", "a", "-expires", "2020-01-01"}, exitInvalid},
		{"issue extra args", []string{"issue", "-key", priv, "-licensee", "a", "extra"}, exitUsage},
		{"issue to stdout", []string{"issue", "-key", priv, "-licensee", "a", "-expires", "12h"}, exitOK},
		{"inspect garbage", []string{"inspect", filepath.Join(dir, "k.pem")}, exitInvalid},
		{"flag help", []string{"verify", "-h"}, exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := runCLI(t, cliNow, "", tt.args...); r.code != tt.code {
				t.Fatalf("code=%d want %d; stdout=%q stderr=%q", r.code, tt.code, r.stdout, r.stderr)
			}
		})
	}
}

func TestParseWhen(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		{"", time.Time{}, false},
		{"30d", cliNow.Add(30 * 24 * time.Hour), false},
		{"12h", cliNow.Add(12 * time.Hour), false},
		{"2027-02-03", time.Date(2027, 2, 3, 0, 0, 0, 0, time.UTC), false},
		{"2027-02-03T04:05:06Z", time.Date(2027, 2, 3, 4, 5, 6, 0, time.UTC), false},
		{"-5d", time.Time{}, true},
		{"xd", time.Time{}, true},
		{"tomorrow", time.Time{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseWhen(tt.in, cliNow)
			if (err != nil) != tt.wantErr || !got.Equal(tt.want) {
				t.Fatalf("parseWhen(%q) = %v, %v", tt.in, got, err)
			}
		})
	}
}
