// Package target is the single source of truth for the *target* platform/arch
// of a build.
//
// brewkit is historically a *native* build tool: everything pivots on the host
// == the machine it runs on == the thing it builds for. To cross-compile
// (notably Windows PE bottles built on a linux/darwin host) we split "where am
// I running" (Host) from "what am I building for" (Target). Only OUTPUT/target
// decisions consult Target:
//
//   - the `if:` guards in a recipe's build/test script
//   - platform-keyed env selection
//   - fix-up (POSIX relocation) selection
//   - the bottle slug (platform-key)
//
// Shell-environment decisions ("which TMPDIR does *this* host use") keep using
// Host. The target is taken from (first match wins):
//
//  1. the ZBK_TARGET env var  (eg. "windows/x86-64" or "windows+x86-64")
//  2. Host()  (native build — byte-for-byte unchanged behaviour)
package target

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Target is the resolved build target.
type Target struct {
	Platform string // darwin | linux | windows | wasip1
	Arch     string // x86-64 | aarch64 | s390x | wasm (wasip1 only)
	// Triple is the compiler triple — and for every target but windows it is
	// the triple of the machine bk RUNS ON, not the one named here.
	//
	//	$ ZBK_TARGET=linux/s390x bk target        # on a Mac
	//	linux/s390x triple=aarch64-apple-darwin cross=true
	//
	// That is correct today and reads as a bug, which is why it is written
	// down rather than left to be rediscovered. bk cross-compiles to windows
	// and nowhere else: a unix target is always built natively or under
	// emulation, so host and target coincide and the value is right. The
	// windows branch of Resolve computes a real cross triple because windows
	// is the case where they differ.
	//
	// It matters because the value does not stay here. It names the compiler
	// shims autoconf probes for, and it reaches every recipe as {{hw.target}}
	// — a name that promises the target. A recipe author reading that name
	// will believe it, and one of ours did: rust-lang.org/cargo picks its
	// bootstrap archive by this triple, which is right only while the two
	// coincide, and the comment there says so.
	//
	// A unix→unix cross build would need this computed from Platform/Arch.
	// Changing it before then is a fix to a case that cannot arise, and the
	// test below pins the current answer deliberately.
	Triple string
}

// Cross reports whether Platform/Arch differ from the running host.
func (t Target) Cross() bool {
	h := Host()
	return t.Platform != h.Platform || t.Arch != h.Arch
}

// Slug is the pkgx bottle platform key, eg. "linux/x86-64".
func (t Target) Slug() string { return t.Platform + "/" + t.Arch }

var (
	// platformArches is the table of what bk can build FOR: platform -> arches.
	// Arch validity is per platform, because wasm is an architecture only of
	// wasip1 and `linux/wasm` or `wasip1/x86-64` name no machine at all.
	//
	// wasip1 is GOOS=wasip1 GOARCH=wasm: pure-Go builds (CGO_ENABLED=0) that
	// produce a .wasm module, published as OCI platform os=wasip1
	// architecture=wasm. C toolchains (wasi-sdk) are not part of this target.
	platformArches = map[string]map[string]bool{
		// s390x joined the unix list when a LinuxONE runner came online. An arch
		// with no machine behind it is a guess, and this is the one place that
		// should not hold one.
		//
		// Host() has never had a list -- it passes GOARCH through pkgxArch -- so
		// until now the same architecture was legal natively and refused the
		// moment a build NAMED it. That asymmetry is how `--platform linux/s390x`
		// reached
		//
		//	factory: unsupported target arch: "s390x"
		//
		// on a runner that had already checked the repo out and installed bk.
		"darwin":  {"x86-64": true, "aarch64": true, "s390x": true},
		"linux":   {"x86-64": true, "aarch64": true, "s390x": true},
		"windows": {"x86-64": true, "aarch64": true, "s390x": true},
		"wasip1":  {"wasm": true},
		// ⛔ THE BSDs ARE x86-64 ONLY, FOR THE REASON THIS MAP EXISTS. The
		// machine behind them is the `vmactions/{freebsd,netbsd,openbsd}-vm`
		// qemu guest that go-zpkg/pkgm already runs its tests in, and those
		// actions offer amd64 and nothing else. aarch64 joins the day there is
		// a machine, exactly as s390x did — adding it now would put a guess in
		// the one place that must not hold one.
		//
		// `bottle` has known these three since before any bottle existed for
		// them (host.go, pkgx.go's platform slugs), and says so on purpose:
		// "no bottle for <project> (freebsd/aarch64)". So the consumer side
		// was ready and the FACTORY was the gap.
		"freebsd": {"x86-64": true},
		"openbsd": {"x86-64": true},
		"netbsd":  {"x86-64": true},
	}
	// llvm.org/mingw-w64 cross triples (see the go-zpkg/packages Windows
	// factories: x86_64-w64-mingw32-clang / aarch64-w64-mingw32-clang).
	windowsTriples = map[string]string{
		"x86-64":  "x86_64-w64-mingw32",
		"aarch64": "aarch64-w64-mingw32",
	}
	overrideRE = regexp.MustCompile(`^([a-z0-9_]+)[/+]([a-z0-9-]+)$`)
)

// wasip1Triple is the LLVM name of the Go wasip1/wasm target (Go's GOOS=wasip1
// GOARCH=wasm; WASI preview 1 on a 32-bit wasm machine).
const wasip1Triple = "wasm32-wasip1"

// zpkgArch maps a Go GOARCH to the arch naming this project's catalogue and
// bottles use ("x86-64", "aarch64").
//
// ⛔ IT WAS CALLED pkgxArch, AND THE COMMENT SAID "pkgx's arch naming". That
// was true while the fork tracked upstream and is not any more: the direct
// filiation is broken and this project is no longer compatible with pkgx
// (go-zpkg/packages#431). The spellings are OURS now, and a name saying
// otherwise points a reader at a compatibility that does not exist.
func zpkgArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86-64"
	case "arm64":
		return "aarch64"
	default:
		return goarch
	}
}

// nativeTriple is a best-effort native compiler triple for the running host.
func nativeTriple() string { return nativeTripleFor(runtime.GOOS, runtime.GOARCH) }

// nativeTripleFor is the pure, testable core of nativeTriple.
func nativeTripleFor(goos, goarch string) string {
	arch := goarch
	switch goarch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	}
	switch goos {
	case "wasip1":
		return wasip1Triple
	case "darwin":
		return arch + "-apple-darwin"
	case "windows":
		return arch + "-w64-mingw32"
	case "freebsd", "openbsd", "netbsd":
		// ⛔ THE DEFAULT BELOW WOULD CALL A BSD HOST "linux-gnu". These builds
		// are NATIVE — the compiler runs inside the BSD guest — so the triple
		// is what that guest's clang already calls itself, and handing it
		// `x86_64-unknown-linux-gnu` is how a native build acquires a cross
		// build's problems for no reason.
		return arch + "-unknown-" + goos
	default:
		return arch + "-unknown-linux-gnu"
	}
}

// Host is the platform/arch/triple of the machine bk is running on.
// IsPlatform and IsArch are the ONE vocabulary of platform names.
//
// There were two. buildscript kept its own `platforms`/`arches` maps to
// decide what a recipe's `env: {aarch64: …}` key and its `if: linux/x86-64`
// guard mean, and when s390x was added here that copy was not. The
// consequences were silent in both directions: an `env` keyed by s390x
// became a literal variable of that name, and a step guarded `if: s390x`
// ran on EVERY platform, because matchGuard lets an unrecognised condition
// through rather than dropping the step.
//
// Predicates rather than the maps, so a caller cannot hold a reference and
// drift again.
func IsPlatform(s string) bool { _, ok := platformArches[s]; return ok }

// IsArch reports whether s is an architecture this factory builds for on SOME
// platform, in pkgx's spelling (`x86-64`, not `amd64` — see pkgxArch). It is
// the recipe vocabulary (`env: {wasm: …}`); whether a given platform/arch PAIR
// is buildable is IsPair.
func IsArch(s string) bool {
	for _, arches := range platformArches {
		if arches[s] {
			return true
		}
	}
	return false
}

// IsPair reports whether platform/arch names a machine bk can build for:
// `wasip1/wasm` and `linux/x86-64` do, `linux/wasm` and `wasip1/x86-64` do not.
func IsPair(platform, arch string) bool { return platformArches[platform][arch] }

// Platforms and Arches list the vocabulary, sorted, for callers that need a
// set (a recipe-key regexp) and must not restate it.
func Platforms() []string {
	out := make([]string, 0, len(platformArches))
	for p := range platformArches {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Arches is the sorted union of every platform's arches.
func Arches() []string {
	seen := map[string]bool{}
	for _, arches := range platformArches {
		for a := range arches {
			seen[a] = true
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func Host() Target {
	p := runtime.GOOS
	return Target{Platform: p, Arch: zpkgArch(runtime.GOARCH), Triple: nativeTriple()}
}

// Override parses & validates ZBK_TARGET, returning ok=false when unset.
// It returns an error for a malformed or unsupported value.
//
// ⛔⛔ THE VARIABLE WAS `BREWKIT_TARGET`, AND NO ALIAS WAS KEPT. The command is
// `zbk`; `BREWKIT_TARGET` is upstream brewkit's name, and upstream's brewkit can
// sit on the same PATH as ours — which is the entire reason the binaries were
// renamed. A variable read by both would be the same collision the rename
// existed to remove, left in the place that decides what a build targets.
//
// An alias would be worse than the old name alone: a tree with both set would
// take one of them by a precedence nobody could see, and every document would
// have to explain two spellings forever. The old name is simply not read, and
// `TestTheOldVariableNameIsNotRead` is the gate that says so — because "we
// removed it" is a claim about code that nothing was asserting.
//
// It is a breaking change, below v1, in the same release line as the binaries'
// own rename. Nothing in this organisation set it outside its own sources: the
// only other mentions were two recipe comments, two READMEs and one docs page,
// all updated with it.
func Override() (platform, arch string, ok bool, err error) {
	raw := strings.TrimSpace(os.Getenv("ZBK_TARGET"))
	if raw == "" {
		return "", "", false, nil
	}
	m := overrideRE.FindStringSubmatch(raw)
	if m == nil {
		return "", "", false, fmt.Errorf("invalid ZBK_TARGET: %q (expected eg. 'windows/x86-64')", raw)
	}
	platform, arch = m[1], m[2]
	if !IsPlatform(platform) {
		return "", "", false, fmt.Errorf("unsupported target platform: %q", platform)
	}
	if !IsPair(platform, arch) {
		// amd64 and arm64 are Go's spellings for two of these machines and the
		// mistake actually made, since every other arch name here is shared.
		// Refusing without saying so sends the reader looking for a missing
		// port rather than at the two characters that differ.
		if zpkgx := zpkgArch(arch); zpkgx != arch && IsPair(platform, zpkgx) {
			return "", "", false, fmt.Errorf("unsupported target arch: %q (pkgx spells it %q)", arch, zpkgx)
		}
		return "", "", false, fmt.Errorf("unsupported target arch %q for platform %q", arch, platform)
	}
	return platform, arch, true, nil
}

// IsCross reports whether a ZBK_TARGET override is set (a cross build).
func IsCross() (bool, error) {
	_, _, ok, err := Override()
	return ok, err
}

// Resolve returns the build target, falling back to Host() for native builds.
func Resolve() (Target, error) {
	platform, arch, ok, err := Override()
	if err != nil {
		return Target{}, err
	}
	if !ok {
		return Host(), nil
	}
	triple := nativeTriple()
	if platform == "wasip1" {
		// Like windows, a real cross triple: the module is never the machine
		// bk runs on.
		triple = wasip1Triple
	}
	if platform == "windows" {
		// This used to read `triple = windowsTriples[arch]` under a comment
		// saying every supported arch had an entry, so the lookup was total.
		// Widening supportedArches ended that, and a map miss does not fail:
		// it yields "", and a build carries an empty triple to whichever step
		// first needs a compiler, which is a long way from here.
		t, ok := windowsTriples[arch]
		if !ok {
			return Target{}, fmt.Errorf("no windows cross triple for arch %q (llvm-mingw targets %s)", arch, tripleArches())
		}
		triple = t
	}
	return Target{Platform: platform, Arch: arch, Triple: triple}, nil
}

// tripleArches lists the arches llvm-mingw can be targeted at, for the error
// above. Read from the table rather than restated, so it cannot describe a
// table it no longer matches.
func tripleArches() string {
	out := make([]string, 0, len(windowsTriples))
	for a := range windowsTriples {
		out = append(out, a)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
