// Command golicense generates signing keys and issues, verifies and inspects
// go-license tokens.
//
// Usage:
//
//	golicense keygen  -priv license.key.pem -pub license.pub.pem
//	golicense issue   -key license.key.pem -licensee "Acme Corp" -features sso,audit -expires 365d -out acme.lic
//	golicense verify  -pub license.pub.pem -require sso acme.lic
//	golicense inspect [-pub license.pub.pem] acme.lic
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	license "github.com/neerajsinghi/go-license"
	"github.com/neerajsinghi/go-license/clock"
)

// Exit codes.
const (
	exitOK      = 0
	exitInvalid = 1 // the license (or input) is invalid
	exitUsage   = 2 // bad command line
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, time.Now))
}

type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	now            func() time.Time
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, now func() time.Time) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, now: now}
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "keygen":
		return e.keygen(rest)
	case "issue":
		return e.issue(rest)
	case "verify":
		return e.verify(rest)
	case "inspect":
		return e.inspect(rest)
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "golicense: unknown command %q\n\n", cmd)
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `golicense - offline Ed25519 license keys

Commands:
  keygen   generate an Ed25519 signing key pair (PEM)
  issue    sign a new license token with a private key
  verify   verify a license token with a public key
  inspect  decode a license token and print its claims

Run "golicense <command> -h" for command flags.
`)
}

func (e *env) errorf(format string, args ...any) {
	fmt.Fprintf(e.stderr, "golicense: "+format+"\n", args...)
}

func (e *env) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("golicense "+name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

// parse runs fs.Parse and converts the result into an exit code (or -1 to
// continue).
func parse(fs *flag.FlagSet, args []string) int {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	return -1
}

// ---- keygen ----------------------------------------------------------------

func (e *env) keygen(args []string) int {
	fs := e.newFlagSet("keygen")
	privPath := fs.String("priv", "license.key.pem", "output path for the private key")
	pubPath := fs.String("pub", "license.pub.pem", "output path for the public key")
	force := fs.Bool("force", false, "overwrite existing files")
	if code := parse(fs, args); code >= 0 {
		return code
	}
	pub, priv, err := license.GenerateKey(nil)
	if err != nil {
		e.errorf("%v", err)
		return exitInvalid
	}
	privPEM, err := license.MarshalPrivateKey(priv)
	if err != nil {
		e.errorf("%v", err)
		return exitInvalid
	}
	pubPEM, err := license.MarshalPublicKey(pub)
	if err != nil {
		e.errorf("%v", err)
		return exitInvalid
	}
	if !*force {
		for _, p := range []string{*privPath, *pubPath} {
			if _, err := os.Stat(p); err == nil {
				e.errorf("%s already exists (use -force to overwrite)", p)
				return exitUsage
			}
		}
	}
	if err := os.WriteFile(*privPath, privPEM, 0o600); err != nil {
		e.errorf("write private key: %v", err)
		return exitInvalid
	}
	if err := os.WriteFile(*pubPath, pubPEM, 0o644); err != nil {
		e.errorf("write public key: %v", err)
		return exitInvalid
	}
	fmt.Fprintf(e.stdout, "wrote private key to %s (keep it secret)\nwrote public key to %s (embed it in your application)\n", *privPath, *pubPath)
	return exitOK
}

// ---- issue -----------------------------------------------------------------

type metaFlag map[string]string

func (m metaFlag) String() string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k+"="+m[k])
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func (m metaFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return fmt.Errorf("want key=value, got %q", s)
	}
	m[k] = v
	return nil
}

func (e *env) issue(args []string) int {
	fs := e.newFlagSet("issue")
	keyPath := fs.String("key", "", "path to the PEM private key (required)")
	licensee := fs.String("licensee", "", "licensee / customer name (required)")
	id := fs.String("id", "", "license ID (default: random)")
	features := fs.String("features", "", "comma-separated feature flags")
	expires := fs.String("expires", "", "expiry: duration from now (e.g. 30d, 720h) or RFC 3339 / YYYY-MM-DD; empty = perpetual")
	notBefore := fs.String("not-before", "", "start of validity, same formats as -expires")
	seats := fs.Int("seats", 0, "maximum seats (0 = unlimited)")
	instances := fs.Int("instances", 0, "maximum instances (0 = unlimited)")
	out := fs.String("out", "", "write the token to this file instead of stdout")
	meta := metaFlag{}
	fs.Var(meta, "meta", "metadata key=value (repeatable)")
	if code := parse(fs, args); code >= 0 {
		return code
	}
	if *keyPath == "" || *licensee == "" {
		e.errorf("issue: -key and -licensee are required")
		fs.Usage()
		return exitUsage
	}
	if fs.NArg() > 0 {
		e.errorf("issue: unexpected arguments %v", fs.Args())
		return exitUsage
	}
	now := e.now()
	exp, err := parseWhen(*expires, now)
	if err != nil {
		e.errorf("issue: -expires: %v", err)
		return exitUsage
	}
	nbf, err := parseWhen(*notBefore, now)
	if err != nil {
		e.errorf("issue: -not-before: %v", err)
		return exitUsage
	}
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		e.errorf("issue: %v", err)
		return exitInvalid
	}
	priv, err := license.ParsePrivateKey(keyPEM)
	if err != nil {
		e.errorf("issue: %v", err)
		return exitInvalid
	}
	iss, err := license.NewIssuer(priv, license.WithIssuerClock(e.now))
	if err != nil {
		e.errorf("issue: %v", err)
		return exitInvalid
	}
	tok, lic, err := iss.IssueLicense(license.License{
		ID:           *id,
		Licensee:     *licensee,
		NotBefore:    nbf,
		ExpiresAt:    exp,
		MaxSeats:     *seats,
		MaxInstances: *instances,
		Features:     splitList(*features),
		Metadata:     meta,
	})
	if err != nil {
		e.errorf("issue: %v", err)
		return exitInvalid
	}
	if *out == "" {
		fmt.Fprintln(e.stdout, tok)
		return exitOK
	}
	if err := os.WriteFile(*out, []byte(tok+"\n"), 0o644); err != nil {
		e.errorf("issue: %v", err)
		return exitInvalid
	}
	fmt.Fprintf(e.stdout, "issued license %s for %q to %s\n", lic.ID, lic.Licensee, *out)
	return exitOK
}

// parseWhen accepts "" (zero time), a duration relative to now such as
// "30d" or "720h" (a "d" suffix must stand alone), an RFC 3339 timestamp or
// a YYYY-MM-DD date (UTC midnight).
func parseWhen(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 || n > 100*366 {
			return time.Time{}, fmt.Errorf("invalid day count %q", s)
		}
		return now.Add(time.Duration(n) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a duration, RFC 3339 time or YYYY-MM-DD date", s)
	}
	return now.Add(d), nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// readToken reads a token from the named file, or stdin for "-".
func (e *env) readToken(fs *flag.FlagSet) (string, int) {
	if fs.NArg() != 1 {
		e.errorf("%s: expected exactly one license file argument (use - for stdin)", fs.Name())
		return "", exitUsage
	}
	var (
		b   []byte
		err error
	)
	if p := fs.Arg(0); p == "-" {
		b, err = io.ReadAll(io.LimitReader(e.stdin, license.MaxTokenSize+1))
	} else {
		b, err = os.ReadFile(p)
	}
	if err != nil {
		e.errorf("%s: %v", fs.Name(), err)
		return "", exitInvalid
	}
	return string(b), -1
}

// loadVerifier reads a PEM public key and builds a Verifier using the
// environment clock, followed by any extra options.
func (e *env) loadVerifier(path string, opts ...license.VerifierOption) (*license.Verifier, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := license.ParsePublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return license.NewVerifier(pub, append([]license.VerifierOption{license.WithClock(e.now)}, opts...)...)
}

// ---- verify ----------------------------------------------------------------

func (e *env) verify(args []string) int {
	fs := e.newFlagSet("verify")
	pubPath := fs.String("pub", "", "path to the PEM public key (required)")
	require := fs.String("require", "", "comma-separated features that must be licensed")
	at := fs.String("at", "", "verify as of this RFC 3339 time instead of now")
	leeway := fs.Duration("leeway", 0, "allowed clock skew for expiry checks")
	state := fs.String("state", "", "clock-rollback state file (enables rollback detection)")
	tolerance := fs.Duration("tolerance", 10*time.Minute, "allowed backwards clock drift with -state")
	if code := parse(fs, args); code >= 0 {
		return code
	}
	if *pubPath == "" {
		e.errorf("verify: -pub is required")
		fs.Usage()
		return exitUsage
	}
	tok, code := e.readToken(fs)
	if code >= 0 {
		return code
	}
	now := e.now
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			e.errorf("verify: -at: %v", err)
			return exitUsage
		}
		now = func() time.Time { return t }
	}
	opts := []license.VerifierOption{license.WithClock(now), license.WithLeeway(*leeway)}
	if *state != "" {
		opts = append(opts, license.WithClockGuard(clock.NewGuard(clock.NewFileStore(*state, nil), *tolerance)))
	}
	ver, err := e.loadVerifier(*pubPath, opts...)
	if err != nil {
		e.errorf("verify: %v", err)
		return exitInvalid
	}
	lic, err := ver.Verify(tok)
	if err != nil {
		fmt.Fprintf(e.stdout, "INVALID: %v\n", err)
		return exitInvalid
	}
	if err := lic.Require(splitList(*require)...); err != nil {
		fmt.Fprintf(e.stdout, "INVALID: %v\n", err)
		return exitInvalid
	}
	expiry := "never"
	if !lic.ExpiresAt.IsZero() {
		expiry = lic.ExpiresAt.Format(time.RFC3339)
	}
	fmt.Fprintf(e.stdout, "OK: license %s for %q, expires %s, features [%s]\n",
		lic.ID, lic.Licensee, expiry, strings.Join(lic.Features, ", "))
	return exitOK
}

// ---- inspect ---------------------------------------------------------------

type inspectView struct {
	ID           string            `json:"id"`
	Licensee     string            `json:"licensee"`
	IssuedAt     string            `json:"issued_at"`
	NotBefore    string            `json:"not_before,omitempty"`
	ExpiresAt    string            `json:"expires_at,omitempty"`
	MaxSeats     int               `json:"max_seats,omitempty"`
	MaxInstances int               `json:"max_instances,omitempty"`
	Features     []string          `json:"features,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Status       string            `json:"status"`
	Signature    string            `json:"signature"`
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (e *env) inspect(args []string) int {
	fs := e.newFlagSet("inspect")
	pubPath := fs.String("pub", "", "optional public key; when given, the signature is checked")
	if code := parse(fs, args); code >= 0 {
		return code
	}
	tok, code := e.readToken(fs)
	if code >= 0 {
		return code
	}
	lic, err := license.ParseUnverified(tok)
	if err != nil {
		e.errorf("inspect: %v", err)
		return exitInvalid
	}
	sig := "not checked (pass -pub)"
	exit := exitOK
	if *pubPath != "" {
		ver, err := e.loadVerifier(*pubPath)
		if err != nil {
			e.errorf("inspect: %v", err)
			return exitInvalid
		}
		if _, err := ver.VerifySignature(tok); err != nil {
			sig = "INVALID: " + err.Error()
			exit = exitInvalid
		} else {
			sig = "valid"
		}
	}
	status := "active"
	if err := lic.ValidAt(e.now(), 0); errors.Is(err, license.ErrExpired) {
		status = "expired"
	} else if errors.Is(err, license.ErrNotYetValid) {
		status = "not yet valid"
	}
	view := inspectView{
		ID:           lic.ID,
		Licensee:     lic.Licensee,
		IssuedAt:     fmtTime(lic.IssuedAt),
		NotBefore:    fmtTime(lic.NotBefore),
		ExpiresAt:    fmtTime(lic.ExpiresAt),
		MaxSeats:     lic.MaxSeats,
		MaxInstances: lic.MaxInstances,
		Features:     lic.Features,
		Metadata:     lic.Metadata,
		Status:       status,
		Signature:    sig,
	}
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(view); err != nil {
		e.errorf("inspect: %v", err)
		return exitInvalid
	}
	return exit
}
