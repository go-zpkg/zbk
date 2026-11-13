package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-zpkg/zpkb/support"
)

// Seams: the network call and the clock, so the whole command is drivable
// without either. The clock matters as much as the fetch here — a verdict that
// depends on today's date cannot be tested against a fixed answer otherwise,
// and "expiring in three days" is exactly the state worth pinning.
var (
	eolFetch = fetchProduct
	eolNow   = time.Now
	// eolBaseURL is a seam so the fetch itself can be driven against a test
	// server. Without it the only testable part of fetchProduct is the URL
	// it fails to build, and the behaviour that matters — a 404 must not
	// arrive as an empty product — would be asserted by proxy.
	eolBaseURL = "https://endoflife.date/api/v1/products/"
)

// runEOL implements `bk eol`: is the version we publish on an upstream release
// line that is still supported?
//
// ⛔ IT ASKS WHAT A VULNERABILITY DATABASE CANNOT. OSV answers "what is known
// to be wrong with this version". A line upstream has abandoned has nothing
// known about it yet and never will, because nobody is looking and no fix is
// coming — so `bk vulnfetch` and the daily sweep return a clean zero for a
// package whose upstream stopped issuing fixes years ago. End-of-life is not a
// CVE, and nothing here could say so until this existed.
//
// Measured 2026-10-29, which is why it was written: the registry publishes
// openssl 3.2, 3.3, 3.4, 3.5, 3.6 and 4.0. 3.2 and 3.3 were already out of
// support, 3.4 went out on 2026-10-22, and 3.6 goes out on 2026-11-01 — while
// `^3` resolves to the newest 3.x, which is 3.6. The default resolution was
// three days from an unsupported line, with the 3.5 LTS sitting unused in the
// same registry.
//
//	bk eol -product openssl 3.4.7 3.6.4 3.5.8
//	bk eol -product openssl -fail -within 90d 3.6.4     # as a gate
func runEOL(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	product := fs.String("product", "", "the endoflife.date product these versions belong to (required)")
	within := fs.Duration("within", 90*24*time.Hour, "treat a line ending inside this window as expiring")
	failOn := fs.Bool("fail", false, "exit 1 if any version is end-of-life or expiring")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *product == "" {
		fmt.Fprintln(stderr, "eol: -product is required (the endoflife.date name, e.g. openssl)")
		return 2
	}
	versions := fs.Args()
	if len(versions) == 0 {
		fmt.Fprintln(stderr, "eol: name at least one version")
		return 2
	}

	body, err := eolFetch(*product)
	if err != nil {
		fmt.Fprintln(stderr, "eol:", err)
		return 1
	}
	p, err := support.ParseProduct(body)
	if err != nil {
		fmt.Fprintln(stderr, "eol:", err)
		return 1
	}

	now := eolNow().UTC()
	bad := 0
	for _, v := range versions {
		verdict := support.Judge(v, p, now, *within)
		switch verdict.State {
		case support.StateEOL, support.StateExpiring:
			bad++
		}
		fmt.Fprintf(stdout, "%-12s %-12s %s\n", v, verdict.State, verdict.Why)
	}

	// ⛔ NAME THE DESTINATION. "openssl 3.6 ends on Sunday" is a problem;
	// "and 3.5 is supported to 2030" is the next step. A report that leaves
	// the reader to find the answer is a chore, and chores get deferred.
	if bad > 0 {
		if best, ok := support.BestLine(p, now); ok {
			lts := ""
			if best.IsLTS {
				lts = " (LTS)"
			}
			fmt.Fprintf(stdout, "\nlongest-supported %s line: %s%s, until %s\n", p.Name, best.Name, lts, best.EOLFrom)
		} else {
			// Every line over is worse news than any single finding, and
			// saying it beats naming the least-dead line as a destination.
			fmt.Fprintf(stdout, "\nno %s line is still supported\n", p.Name)
		}
	}
	if p.Policy != "" {
		fmt.Fprintf(stdout, "release policy: %s\n", p.Policy)
	}
	if *failOn && bad > 0 {
		return 1
	}
	return 0
}

// fetchProduct asks endoflife.date for one product's release lines.
//
// ⛔ THE STATUS IS CHECKED BEFORE THE BODY. endoflife.date answers an unknown
// product with a 404 carrying a JSON error document, which decodes without
// complaint into a struct with no releases — so a misspelled product would
// otherwise arrive as "no release line claims this version" for everything,
// which reads like a measurement rather than a typo.
func fetchProduct(product string) ([]byte, error) {
	url := eolBaseURL + product
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("endoflife.date: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife.date: %s says %s (is %q its product name?)", url, resp.Status, product)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
