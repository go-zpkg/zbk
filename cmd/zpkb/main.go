// Command bk is the pure-Go brewkit — a from-scratch reimplementation of
// pkgx's build tool that is Target≠Host by design (first-class cross-compile,
// notably Windows PE artifacts built on a linux/darwin host).
//
// This entrypoint currently exposes the pieces implemented so far:
//
//	bk target            print the resolved build target (honours ZPKB_TARGET / --platform)
//	bk fixup <prefix>    run the post-build relocatability fix-ups on an install prefix
//	bk versions          list a recipe's candidate versions
//	bk build             build a recipe into an artifact
//	bk publish           push a built artifact to an OCI registry
//	bk closure           print a project set's transitive runtime closure (topological)
//	bk catalog           build (and publish, signed) the catalogue pkgx ls
//	                     and <TAB> read
//	bk runlog            read a factory job log: counts, stages, and whether
//	                     the parse agrees with bk's own totals
//	bk lock              resolve a set to the versions it means today, write them down, and --check them later
//	                     (-runnable pins what is PUBLISHED, so `zpkx --lock` can run the file)
//	bk factory           build a recipe set's whole closure and publish every artifact
//	bk source            fetch the source a published artifact attests it was built from
//	bk vulnid            say, per project, the name a vulnerability database will
//	                     accept — derived from the recipe, or declared in a table
//	bk advisories        validate a tree of per-project advisory records and say
//	                     what state each one is in
//	bk vulnfetch         ask OSV what it knows about a pantry, in one request,
//	                     and (with -write) record it as dated detections
//	bk eol               whether a version is on an upstream release line that
//	                     is still supported — the question OSV cannot answer,
//	                     because an abandoned line has no advisories YET
//	bk attest            say what a PUBLISHED artifact carries — SBOM, provenance,
//	                     signature, OpenVEX — and --require it
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/config"
	"github.com/go-zpkg/zpkb/fixup"
	"github.com/go-zpkg/zpkb/target"
)

// trustEmbeddedCAs makes every HTTPS call bk performs — version listings, source
// downloads, go-git clones — trust the Mozilla bundle artifact embeds, on top of
// the system store. A FROM-scratch builder image has NO system trust store, so
// without this bk cannot even list a version there:
//
//	versions: ls-remote https://github.com/lz4/lz4: tls: failed to verify
//	certificate: x509: certificate signed by unknown authority
//
// Setting it on the default transport covers the standard library clients and
// go-git alike, rather than threading a client through every call site.
func trustEmbeddedCAs() {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return
	}
	tr = tr.Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: artifact.CertPool()}
	// HTTP/1.1 for the same reason artifact pulls use it: these are long,
	// single-stream transfers (a source tarball, or github's ref advertisement
	// for a repo the size of openssl's), and h2 flow control makes them stall —
	// `ls-remote https://github.com/openssl/openssl: context deadline exceeded`
	// from inside the builder, where every byte goes through this transport.
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	http.DefaultTransport = tr
	http.DefaultClient.Transport = tr
	// go-git does NOT go through http.DefaultTransport — it keeps its own
	// protocol client — so the version listing (`ls-remote` over smart HTTP)
	// needs the store installed separately, or it keeps failing on its own.
	client.InstallProtocol("https", githttp.NewClient(&http.Client{Transport: tr}))
}

var osExit = os.Exit

func main() {
	trustEmbeddedCAs()
	// Multi-call ("busybox-style") dispatch: bk is materialised into a build's
	// libexec dir as symlinks named after brewkit shims. When a recipe execs one
	// (e.g. `fix-shebangs.ts bin/*`), argv[0] is the symlink path, so its
	// basename selects the pure-Go helper — no shell interpreter is involved.
	switch filepath.Base(os.Args[0]) {
	case "fix-shebangs.ts":
		osExit(fixShebangs(os.Args[1:], os.Stderr))
		return
	case "zpkvenv":
		osExit(zpkvenv(os.Args[1:], os.Stderr))
		return
	case "python-venv.sh":
		osExit(pythonVenvSh(os.Args[1:], os.Stderr))
		return
	case "python-venv.py":
		osExit(pythonVenvPy(os.Args[1:], os.Stderr))
		return
	case "python-venv-stubber.sh":
		osExit(pythonVenvStubber(os.Args[1:], os.Stderr))
		return
	case "libtool":
		osExit(libtoolShim(os.Args[1:], os.Stderr))
		return
	}
	// The compiler shims, including the triple-prefixed spellings autoconf
	// reaches for first (`x86_64-pc-linux-gnu-gcc`). Matched by SUFFIX so one
	// case covers every triple rather than a list that has to be kept level
	// with the one in buildscript.
	if isCompilerShim(filepath.Base(os.Args[0])) {
		osExit(ccShim(filepath.Base(os.Args[0]), os.Args[1:], os.Stderr))
		return
	}
	osExit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// printVersion writes the one line both spellings produce.
//
// It prints exactly what bkVersion() returns — WITH the leading "v" — because
// that is the string bk writes into a lock's `bk = "…"` field. A prettier
// rendering here would make the two disagree, and the whole use of this
// command is reading a lock and asking "do I have that bk?".
//
// There is no -ldflags stamp. The siblings inject `-X main.version=<tag>`,
// which can be set to anything regardless of what was compiled; this reads
// debug.ReadBuildInfo, so it cannot disagree with the binary it is in.
func printVersion(w io.Writer) {
	// ⛔ THE BINARY SAYS ITS OWN NAME. The command is `zpkb` since the rename,
	// and `bk` is now free for upstream's brewkit to occupy on the same PATH
	// — which is what renaming ours was for. Measured: `zpkb --version`
	// answered `bk v0.59.0`.
	fmt.Fprintln(w, "zpkb", bkVersion())
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("zpkb", flag.ContinueOnError)
	fs.SetOutput(stderr)
	platform := fs.String("platform", "", "cross-build target, eg. windows/x86-64 (also ZPKB_TARGET)")
	version := fs.Bool("version", false, "print the version this zpkb writes into every lock")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// ⛔ BOTH SPELLINGS, BECAUSE NEITHER WORKED. Measured 2026-10-09:
	//
	//	$ bk --version
	//	flag provided but not defined: -version
	//	$ bk version
	//	unknown command: version
	//
	// bk could not say which bk it was, which matters more here than in its
	// siblings: it writes its own version into every lock it produces
	// (`bk = "v0.15.0"`), so "which bk wrote this lock" was a question only
	// `go version -m` could answer, and only if you still had the binary.
	//
	// The flag form is parsed BEFORE the empty-args check so that
	// `bk --version` on its own is not a usage error.
	if *version {
		printVersion(stdout)
		return 0
	}
	if *platform != "" {
		os.Setenv("ZPKB_TARGET", *platform)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: zpkb [--platform p] <version|buildenv|origin|target|fixup|versions|build|test|publish|closure|lock|tools|tohcl|lint|vulnid|advisories|vulnfetch|attest|overrides|depgaps|builder|factory|source|reproduce|sign> [args]")
		return 2
	}

	// The TARGET is resolved by the two subcommands that use one, not before
	// the switch. Resolving it here meant `bk lint`, `bk overrides` and `bk
	// tohcl` — none of which builds anything — refused to run on a machine
	// whose ZPKB_TARGET named a platform bk does not support:
	//
	//	error: unsupported target platform: "plan9"
	//
	// The factory SETS that variable, so a CI lane checking recipes beside a
	// build would inherit it.
	switch rest[0] {
	case "version":
		printVersion(stdout)
		return 0
	case "buildenv":
		return runBuildEnv(rest[1:], stdout, stderr)
	case "origin":
		return runOrigin(rest[1:], stdout, stderr)
	case "target":
		tgt, err := target.Resolve()
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fmt.Fprintf(stdout, "%s/%s triple=%s cross=%v\n", tgt.Platform, tgt.Arch, tgt.Triple, tgt.Cross())
		return 0
	case "fixup":
		if len(rest) < 2 {
			fmt.Fprintln(stderr, "usage: zpkb fixup <prefix>")
			return 2
		}
		tgt, err := target.Resolve()
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		err = fixup.FixUp(fixup.Options{
			Prefix:   rest[1],
			Platform: tgt.Platform,
			ZpkgDir:  config.ZpkgDir(),
			Log:      func(s string) { fmt.Fprintln(stdout, s) },
		})
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	case "versions":
		return runVersions(rest[1:], stdout, stderr)
	case "build":
		return runBuild(rest[1:], stdout, stderr)
	case "test":
		return runTest(rest[1:], stdout, stderr)
	case "publish":
		return runPublish(rest[1:], stdout, stderr)
	case "closure":
		return runClosure(rest[1:], stdout, stderr)
	case "catalog":
		return runCatalog(rest[1:], stdout, stderr)
	case "runlog":
		return runRunlog(rest[1:], stdout, stderr)
	case "lock":
		return runLock(rest[1:], stdout, stderr)
	case "depgaps":
		return runDepgaps(rest[1:], stdout, stderr)
	case "depsplit":
		return runDepsplit(rest[1:], stdout, stderr)
	case "undeclared":
		return runUndeclared(rest[1:], stdout, stderr)
	case "unlinked":
		return runUnlinked(rest[1:], stdout, stderr)
	case "provides":
		return runProvides(rest[1:], stdout, stderr)
	case "unresolved":
		return runUnresolved(rest[1:], stdout, stderr)
	case "overrides":
		return runOverrides(rest[1:], stdout, stderr)
	case "lint":
		return runLint(rest[1:], stdout, stderr)
	case "vulnid":
		return runVulnID(rest[1:], stdout, stderr)
	case "advisories":
		return runAdvisories(rest[1:], stdout, stderr)
	case "vulnfetch":
		return runVulnFetch(rest[1:], stdout, stderr)
	case "eol":
		return runEOL(rest[1:], stdout, stderr)
	case "attest":
		return runAttest(rest[1:], stdout, stderr)
	case "tohcl":
		return runToHCL(rest[1:], stdout, stderr)
	case "tools":
		return runTools(rest[1:], stdout, stderr)
	case "sonames":
		return runSonames(rest[1:], stdout, stderr)
	case "bakedpaths":
		return runBakedPaths(rest[1:], stdout, stderr)
	case "weather":
		return runWeather(rest[1:], stdout, stderr)
	case "builder":
		return runBuilder(rest[1:], stdout, stderr)
	case "factory":
		return runFactory(rest[1:], stdout, stderr)
	case "source":
		return runSource(rest[1:], stdout, stderr)
	case "sourcepin":
		return runSourcePin(rest[1:], stdout, stderr)
	case "reproduce":
		return runReproduce(rest[1:], stdout, stderr)
	case "sign":
		return runSign(rest[1:], stdout, stderr)
	case "copy":
		return runCopy(rest[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command:", rest[0])
		return 2
	}
}
