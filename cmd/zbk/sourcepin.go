package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/go-zpkg/zbk/fetch"
)

// Seams: the command is driven in tests without a network.
var (
	fetchDigest   = fetch.Digest
	fetchVerified = fetch.DigestVerified
	readKeyFile   = os.ReadFile
)

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
	// ⛔⛔ THREE FLAGS, AND THE SECOND TWO HAVE NO DEFAULTS ON PURPOSE. --sig
	// asks who signed the bytes; --key says against which key, and --key-source
	// says how the author came to trust that key. Not one of Gentoo, Arch,
	// Debian or Guix records the last one — Debian's uscan(1) says "you must
	// verify the downloaded OpenPGP key using its full fingerprint value WHICH
	// YOU KNOW IS THE TRUSTED ONE", which is unauditable by construction. A
	// fingerprint nobody can trace back to a page and a date is a fingerprint
	// the next reader has to trust on your word.
	sig := fset.String("sig", "", "the detached signature's URL, or `auto` to try <url>.asc then <url>.sig")
	keyFile := fset.String("key", "", "the author's public key file (armored or binary); required with --sig")
	keySource := fset.String("key-source", "", "where that key's fingerprint came from — a URL, a page, a person; required with --sig")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if fset.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: zbk sourcepin [--version V] [--sig URL|auto --key FILE --key-source TEXT] <url>")
		return 2
	}
	url := fset.Arg(0)

	// ⛔ A FLAG THAT SILENTLY DOES NOTHING IS WORSE THAN A MISSING ONE, and
	// here the something it would silently not do is the verification. --sig
	// without a key would print a digest that looks checked.
	if *sig != "" && (*keyFile == "" || *keySource == "") {
		fmt.Fprintln(stderr, "sourcepin: --sig needs --key (nothing is ever fetched from a "+
			"keyserver, so the key comes from a file you chose) and --key-source (where that "+
			"key's fingerprint came from, which is the one thing no other distribution records)")
		return 2
	}
	if *sig == "" && (*keyFile != "" || *keySource != "") {
		fmt.Fprintln(stderr, "sourcepin: --key and --key-source only mean something with --sig")
		return 2
	}

	if *sig != "" {
		return pinSigned(url, *sig, *keyFile, *keySource, *version, stdout, stderr)
	}

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
	// ⛔ SAID EVERY TIME, because 1 upstream recipe in 904 pins a checksum and
	// exactly one names a `sig:` (go-zpkg/zbk#282). An author who never hears
	// that a signature was available will not go looking for one.
	fmt.Fprintf(stdout, "\n  Nothing says WHO produced these bytes. If the project publishes a\n"+
		"  detached signature, --sig <url>|auto --key <file> --key-source <text>\n"+
		"  records that too, and prints the provenance block to paste.\n")
	return 0
}

// pinSigned is `sourcepin --sig`: the digest, plus who vouched for the bytes
// and how the author came to trust them.
//
// It prints a `provenance` block rather than a new schema field, deliberately.
// The schema's `provenance { read / consulted / note }` already exists for
// exactly this kind of claim — what the recipe was written from — and a key is
// that kind of claim. Adding a field before any recipe carries one would be an
// API written against a guess.
func pinSigned(url, sig, keyFile, keySource, version string, stdout, stderr io.Writer) int {
	key, err := readKeyFile(keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "sourcepin: %v\n", err)
		return 1
	}

	// `auto` mirrors Debian's `Pgp-Mode: auto`, documented as "uscan checks
	// possible URLs for the signature file". Both names are tried because both
	// are in the wild, and the one that answered is printed: a recipe should
	// record the URL that worked rather than the guess that produced it.
	cands := []string{sig}
	if sig == "auto" {
		cands = []string{url + ".asc", url + ".sig"}
	}

	pin, err := fetchVerified(url, cands, key)
	if err != nil {
		fmt.Fprintf(stderr, "sourcepin: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "%s\n  %d bytes, fetched with the builder's own fetcher\n", url, pin.Size)
	fmt.Fprintf(stdout, "  signed by %s\n  %s\n  verified against %s — no keyserver was asked\n",
		pin.Fingerprint, pin.Identity, keyFile)

	if version != "" {
		fmt.Fprintf(stdout, "\n  sha256 = {\n    %q = %q\n  }\n", version, pin.SHA256)
	} else {
		fmt.Fprintf(stdout, "\n  sha256 = { \"<version>\" = %q }\n", pin.SHA256)
	}
	fmt.Fprintf(stdout, "  sig    = %q\n", pin.SigURL)

	// The block to paste. The fingerprint is uppercase hex with no separators,
	// which is Arch's documented rule and the strictest of the three read.
	fmt.Fprintf(stdout, "\nprovenance {\n  note = <<EOT\n"+
		"The source archive is signed, and the signature was checked when this\n"+
		"digest was recorded rather than at every build: the signature's job is to\n"+
		"justify WRITING the hash, and the hash is the durable pin. That is Guix's\n"+
		"division (its `origin` record has no signature field; `guix refresh` does\n"+
		"the checking) and it is why nothing here needs the key at build time.\n\n"+
		"  signature  %s\n"+
		"  key        %s\n"+
		"  identity   %s\n"+
		"  fingerprint came from: %s\n\n"+
		"No keyserver was consulted. Guix's --key-download defaults to `auto`,\n"+
		"which it documents as `interactive` on a TTY and \"else always\" — so in CI\n"+
		"an unknown key is fetched and accepted, and the check degrades to\n"+
		"\"somebody signed it\". Here an unknown key is a refusal.\nEOT\n}\n",
		pin.SigURL, keyFile, pin.Identity, keySource)
	return 0
}
