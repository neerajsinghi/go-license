// Command basic walks through the whole go-license flow in one process:
// generate a key pair, issue a license, verify it with rollback detection,
// gate features, and meter usage in a tamper-evident log.
//
//	go run ./examples/basic
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	license "github.com/neerajsinghi/go-license"
	"github.com/neerajsinghi/go-license/clock"
	"github.com/neerajsinghi/go-license/meter"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "go-license-example-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// --- Vendor side: generate keys and issue a license. ---
	pub, priv, err := license.GenerateKey(nil)
	if err != nil {
		return err
	}
	issuer, err := license.NewIssuer(priv)
	if err != nil {
		return err
	}
	token, err := issuer.Issue(license.License{
		Licensee:  "Acme Corp",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		MaxSeats:  25,
		Features:  []string{"sso", "audit-log"},
		Metadata:  map[string]string{"plan": "enterprise"},
	})
	if err != nil {
		return err
	}
	fmt.Printf("token (%d bytes): %.48s...\n", len(token), token)

	// --- Application side: only the public key is shipped. ---
	guard := clock.NewGuard(clock.NewFileStore(filepath.Join(dir, "clock.state"), []byte("app-secret")), 10*time.Minute)
	verifier, err := license.NewVerifier(pub, license.WithClockGuard(guard), license.WithLeeway(time.Minute))
	if err != nil {
		return err
	}
	lic, err := verifier.Verify(token)
	if err != nil {
		return fmt.Errorf("license rejected: %w", err)
	}
	fmt.Printf("licensed to %s (id %s), expires %s\n", lic.Licensee, lic.ID, lic.ExpiresAt.Format(time.DateOnly))

	// Feature gating.
	fmt.Println("sso enabled:", lic.HasFeature("sso"))
	if err := lic.Require("sso", "reports"); errors.Is(err, license.ErrFeatureNotLicensed) {
		fmt.Println("gated:", err)
	}
	if err := lic.CheckSeats(30); errors.Is(err, license.ErrLimitExceeded) {
		fmt.Println("gated:", err)
	}

	// A tampered token is rejected.
	tampered := token[:len(token)-2] + "AA"
	if _, err := verifier.Verify(tampered); err != nil {
		fmt.Println("tampered token:", err)
	}

	// --- Usage metering. ---
	key := []byte("metering-secret")
	logPath := filepath.Join(dir, "usage.log")
	usage, err := meter.Open(logPath, key)
	if err != nil {
		return err
	}
	for _, ev := range []string{"export", "export", "api_call"} {
		if _, err := usage.Append(ev, 1, map[string]string{"license": lic.ID}); err != nil {
			return err
		}
	}
	cp := usage.Checkpoint()
	if err := usage.Close(); err != nil {
		return err
	}
	sum, err := meter.VerifyFile(logPath, key, meter.WithCheckpoint(cp))
	if err != nil {
		return err
	}
	fmt.Printf("usage log intact: %d records, totals %v\n", sum.Records, sum.Totals)

	// Editing a record breaks the chain.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return err
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(logPath, raw, 0o600); err != nil {
		return err
	}
	if _, err := meter.VerifyFile(logPath, key); errors.Is(err, meter.ErrTampered) {
		fmt.Println("edited usage log:", err)
	}
	return nil
}
