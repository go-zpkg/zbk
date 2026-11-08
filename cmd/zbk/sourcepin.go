package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/go-zpkg/zbk/fetch"
)

// fetchDigest is a seam: the command is driven in tests without a network.
var fetchDigest = fetch.Digest

// runSourcePin implements `zbk sourcepin <url>`: fetch a source archive and
// print the `sha256` a recipe should pin, in the form the schema wants.
//
// ⛔⛔ IT EXISTS SO THE AUTHOR AND THE BUILD USE THE SAME FETCHER. Every other
// distribution computes a pinned digest with a tool that is not the one its
// build runs — `shasum`, `nix-prefetch-url`, `spack checksum` — so a host quirk
// the build will meet is not met while authoring. fetch.Digest is the
// builder's own download path: non-2xx is an error, a 5xx is retried, a
// truncated body is resumed and length-checked, the User-Agent is ours, and a
// body whose magic bytes are not the archive's is refused.
//
// The hazard is why this is a command and not a line in a runbook. Authoring a
// recipe by hand on 2026-11-08, with GitHub's release CDN flapping 504:
//
//	$ curl -sSL -o xz-5.8.4.tar.gz https://…/xz-5.8.4.tar.gz   # 504
//	$ shasum -a 256 xz-5.8.4.tar.gz
//	bef140a1a96994029153dca8c00b1750b9a5a764fb9db2dc68d7bb40e8a29e8a
//
// 92 bytes of error page, and a digest indistinguishable from a good one. A
// pinned digest is FAIL-CLOSED by design, so a wrong pin is worse than none:
// every later build of that version fails, and the pin looks authoritative
// while doing it. Printing the size beside the digest is part of the point —
// 92 bytes is visible in a way a hex string is not.
func runSourcePin(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("sourcepin", flag.ContinueOnError)
	fset.SetOutput(stderr)
	version := fset.String("version", "", "the version this URL serves; prints only the keyed form")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if fset.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: zbk sourcepin [--version V] <url>")
		return 2
	}
	url := fset.Arg(0)

	digest, size, err := fetchDigest(url)
	if err != nil {
		fmt.Fprintf(stderr, "sourcepin: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "%s\n  %d bytes, fetched with the builder's own fetcher\n", url, size)
	if *version != "" {
		// The keyed form is the one a recipe wants: the url interpolates
		// {{version.raw}}, so one scalar would serve exactly one of the
		// versions it can resolve.
		fmt.Fprintf(stdout, "\n  sha256 = {\n    %q = %q\n  }\n", *version, digest)
		return 0
	}
	fmt.Fprintf(stdout, "\n  sha256 = %q                 # only for a recipe that resolves ONE version\n", digest)
	fmt.Fprintf(stdout, "  sha256 = { \"<version>\" = %q }   # what you almost certainly want\n", digest)
	return 0
}
