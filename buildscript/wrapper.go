package buildscript

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-zpkg/zpkb/target"
)

// WrapOptions carries the environment the porcelain wrapper sets up around the
// user script (the output of Generate). It is a port of libpkgx brewkit's
// make_build_script.
type WrapOptions struct {
	UserScript string   // the pantry script, already rendered by Generate
	Deps       []string // LINK dependencies: what the artefact is built against
	// ToolDeps are what the build RUNS — build dependencies and the base
	// toolchain — resolved in their OWN `pkgx +…` closure.
	//
	// Two closures, not one, because a build tool's runtime requirement and the
	// product's link requirement answer different questions and do not have to
	// agree. qt.io could not build at all while they shared one: it links
	// unicode.org ^71 and its build runs nodejs.org, which needs ^73 to start,
	// and ICU changes its major — and its soname — every release.
	//
	// The tool eval is emitted FIRST so that the link eval's directories land
	// ahead of it in every search path: pkgx writes each variable as
	// VAR="new${VAR:+:$VAR}", so the last eval wins. Nothing is dropped, so a
	// recipe that names a header-bearing dependency under build.dependencies
	// still finds it — one place later than before.
	ToolDeps    []string
	Target      target.Target // what we build FOR — drives FLAGS
	Host        target.Target // where we run — drives TMPDIR
	Home        string        // a fresh HOME for the build
	SrcRoot     string        // the build directory (also SRCROOT / cd target)
	ZpkgDir     string        // $ZPKG_DIR — the rpath root and CMAKE_PREFIX_PATH
	Install     string        // the final install prefix ($ZPKG_DIR/project/vX.Y.Z)
	Project     string        // the project being built, so we never preset a tool IT provides
	BrewkitPath string        // dir prepended to PATH for the build shims (optional)
	ZpkxBin     string        // path to the zpkx binary (for the deps eval + $ZPKGX)
	BashPath    string        // shebang interpreter (default /bin/bash)
	HasCompiler bool          // a compiler (llvm.org / gnu.org/gcc) is already a dep
	// Bootstrap takes the compiler from the HOST instead of adding the llvm.org
	// artifact, for the first generation on an architecture no registry has. It
	// travels with build.Runner.Bootstrap, which drops the base toolchain for
	// the same reason: a compiler is a tool that RUNS the build, not something
	// the artefact carries.
	//
	// Without it --bootstrap stops one step further along than it used to and
	// no further:
	//
	//	zpkx: GET https://dist.pkgx.dev/llvm.org/linux/s390x/versions.txt: Not Found
	//	zpkb: the dependency environment failed: zpkx +llvm.org
	//
	// which reads as a network fault and is not one. artifact falls back to the
	// upstream dist for a project our registry does not carry -- right for
	// llvm.org on x86-64, where upstream HAS it -- and upstream carries no
	// s390x at all.
	Bootstrap   bool
	HasBinutils bool // gnu.org/binutils is a dep (darwin AR/RANLIB workaround)
	// LibcZpkx targets the pkgx gnu.org/glibc artifact instead of the build
	// container's system glibc (linux only): the output links its crt objects,
	// libc and dynamic linker from the artifact, so the artifact owes nothing to the
	// debian build container — the sovereign FROM-scratch end state. Opt-in
	// (default off); the caller also adds gnu.org/glibc to Deps so the artifact is
	// present in the eval. C-only for now: the pkgx llvm.org artifact ships no
	// libc++/libunwind, so C++ recipes still need the system libstdc++.
	LibcZpkx bool
	// Glibc, when set (with LibcZpkx), pins the exact pkgx gnu.org/glibc version
	// used as the sysroot — so the output links THAT glibc's symbols and runs on
	// any host whose kernel satisfies it (a chosen HPC floor, e.g. "2.27.0").
	// Empty = newest available. wrapFlags then resolves that sole installed
	// version dir, so no change is needed there.
	Glibc string
	// PrefixMap is the OLD=NEW of -ffile-prefix-map, from PrefixMapFor. Empty
	// means no map (tests of other things); the runner always sets it.
	PrefixMap string
}

// ArtifactBuildDir is what the cache root is rewritten to in compiled output.
const ArtifactBuildDir = "/build"

// PrefixMapFor derives the -ffile-prefix-map value from the cache root the
// build ACTUALLY uses, and refuses to produce one that could not match: a map
// whose OLD is not a prefix of every build directory is a silent no-op, which
// is the failure this exists to rule out (go-zpkg/bk#387).
func PrefixMapFor(root string, dirs ...string) (string, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Dir(root) == root {
		return "", fmt.Errorf("prefix map: cache root %q is not a usable absolute directory", root)
	}
	if strings.ContainsAny(root, "=:,") {
		return "", fmt.Errorf("prefix map: cache root %q contains '=', ':' or ',', which -ffile-prefix-map and -Wl,-oso_prefix cannot express", root)
	}
	for _, d := range dirs {
		if rel, err := filepath.Rel(root, d); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("prefix map: build directory %q is outside the cache root %q, so the map would not cover it", d, root)
		}
	}
	return root + "=" + ArtifactBuildDir, nil
}

// Wrap assembles the complete, runnable build script: a sanitized env, the
// dependency environment (`eval "$(pkgx +…)"`), target-specific compiler/linker
// FLAGS, a per-host TMPDIR, then the user script run from SRCROOT.
func Wrap(o WrapOptions) string {
	bash := o.BashPath
	if bash == "" {
		bash = "/bin/bash"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#!%s\n\nset -eo pipefail\n\n", bash)
	b.WriteString("export ZPKG_HOME=\"$HOME\"\n")
	if o.Bootstrap {
		// The last of the implicit injections a first fill runs into, and the
		// one that stops everything rather than one thing: artifact adds
		// gnu.org/glibc to EVERY linux closure, so on an architecture with no
		// glibc artifact, `pkgx +anything` fails -- including an artifact this
		// factory has just built and published.
		//
		// Written into the SCRIPT rather than passed in the process
		// environment, so the reason a seed build differs is visible in the
		// artefact that ran it.
		b.WriteString("# bootstrap: this machine has a libc; the registry does not yet\n")
		b.WriteString("export ZPKG_IMPLICIT_ROOTS=none\n")
	}

	zpkxBin := o.ZpkxBin
	if zpkxBin == "" {
		zpkxBin = "zpkx"
	}
	// Tools first: each variable zpkx writes PREPENDS, so whatever is evaluated
	// last comes first on the path. The link closure must win.
	writeDepEval(&b, zpkxBin, o.toolPlus(), "tool", 1)
	writeDepEval(&b, zpkxBin, o.depPlus(), "dependency", 1)
	if o.BrewkitPath != "" {
		fmt.Fprintf(&b, "export PATH=\"%s:$PATH\"\n", o.BrewkitPath)
	}
	if o.ZpkgDir != "" {
		fmt.Fprintf(&b, "export CMAKE_PREFIX_PATH=\"%s${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}\"\n", o.ZpkgDir)
	}
	// ⛔ $ZPKX, MEASURED SAFE RATHER THAN ASSUMED. A recipe may read this, so
	// the question was how many do. Of the 1700 recipes in pkgxdev/pantry
	// (shallow clone, 2026-11-10): 21 name PKGX_DIR — which this builder
	// already exports as ZPKG_DIR, a separate and older gap — and ZERO read a
	// bare $PKGX. Our own overlay's two mentions are PKGX_DIR as well.
	//
	// ⛔⛔ BOTH NAMES ARE EXPORTED, because the OLD one is the published side
	// of a rename and a build script is not a place that can refuse. Every
	// other retired spelling in this fleet is refused with a message naming
	// its replacement — ZPKGM_PREFIX, ZPKGE_SPECS, PKGX_DIR — but that works
	// only where a command reads a variable and can stop. Here WE are the
	// writer: a recipe reading $ZPKGX gets nothing and fails somewhere else
	// entirely, with no line connecting it to this rename. Writing both costs
	// one line of generated script and cannot break a recipe either way.
	// Measured above: nothing in our trees reads it, so this protects only
	// recipes we cannot see — which is exactly who a published name is for.
	if o.ZpkxBin != "" {
		fmt.Fprintf(&b, "export ZPKX=\"%s\"\n", o.ZpkxBin)
		fmt.Fprintf(&b, "export ZPKGX=\"%s\"\n", o.ZpkxBin) // retired spelling
	}
	fmt.Fprintf(&b, "export HOME=%q\n", o.Home)
	fmt.Fprintf(&b, "export SRCROOT=%q\n", o.SrcRoot)
	b.WriteString(tmpdirLine(o.Host) + "\n")
	b.WriteString("if [ -n \"$CI\" ]; then export FORCE_UNSAFE_CONFIGURE=1; fi\n")
	if o.PrefixMap != "" {
		// Read by bk's compiler shims, which append -ffile-prefix-map=$value to
		// every compiler call. Not put in CFLAGS: a recipe's env replaces those
		// whole.
		fmt.Fprintf(&b, "export ZPKB_FILE_PREFIX_MAP=%q\n", o.PrefixMap)
		if o.Target.Platform == "darwin" {
			// ld64 writes the object paths of the debug map (OSO stabs) itself, so
			// -ffile-prefix-map never reaches them. The same root, handed to the
			// linker as -oso_prefix by the shim at link time only (go-zpkg/bk#400).
			old, _, _ := strings.Cut(o.PrefixMap, "=")
			fmt.Fprintf(&b, "export ZPKB_OSO_PREFIX=%q\n", old+"/")
		}
	}
	b.WriteString(toolVars(o.Project))
	b.WriteString("mkdir -p $HOME\n")
	for _, f := range wrapFlags(o.Target, o.ZpkgDir, o.Install, o.HasBinutils, o.LibcZpkx) {
		b.WriteString(f + "\n")
	}
	// A redacted DUMP of the environment into the build log, not an unset —
	// `env` with no command prints and exits, and `-u` removes those two names
	// from what it prints. Measured, because it reads like the opposite: after
	// this line GITHUB_TOKEN is still exported, and deliberately so
	// (SanitizedEnv passes it through for recipes that fetch from GitHub).
	//
	// WrapTest has no counterpart: a test's environment is the package and its
	// test dependencies, which the eval above already names in full.
	b.WriteString("env -u GH_TOKEN -u GITHUB_TOKEN\n\n")

	b.WriteString("set -x\n")
	fmt.Fprintf(&b, "cd %q\n\n", o.SrcRoot)
	b.WriteString(strings.TrimRight(o.UserScript, "\n"))
	b.WriteString("\n")
	return b.String()
}

// depPlus renders the `+spec` dependency list for the pkgx env eval, adding
// llvm.org as the default compiler unless one is already present, the host is
// darwin (uses the system toolchain), or the target is a windows cross build
// (its compiler comes from the recipe's llvm-mingw dep).
// writeDepEval emits one `eval "$(pkgx +…)"` block, or nothing when the set is
// empty.
//
// The environment must be a HARD failure. `eval "$(pkgx +…)"` swallows it: when
// pkgx errors, the substitution is empty, `eval ""` succeeds, and the build
// carries on with NO deps — then dies much later with something unrelated ("C
// compiler cannot create executables", "cannot find -lncursesw") that costs an
// hour to trace back. Capture the output, check the status, and say which
// command failed, naming WHICH of the two closures it was.
// The exit code lets a CALLER tell "I could not assemble the environment"
// from "the thing I ran said no". A build has no use for the distinction —
// either way it did not build — so it passes 1. A test does: see
// EnvFailExit.
func writeDepEval(b *strings.Builder, zpkx, plus, what string, code int) {
	if plus == "" {
		return
	}
	b.WriteString("set -a\n")
	fmt.Fprintf(b, "__bk_deps_env=\"$(CLICOLOR_FORCE=1 %s %s)\" || {\n", zpkx, plus)
	fmt.Fprintf(b, "  echo \"zpkb: the %s environment failed: %s %s\" >&2\n", what, zpkx, plus)
	fmt.Fprintf(b, "  exit %d\n}\n", code)
	b.WriteString("eval \"$__bk_deps_env\"\n")
	b.WriteString("unset __bk_deps_env\n")
	b.WriteString("set +a\n")
}

// toolPlus is the `+spec` list for the tool closure. It gets none of the
// compiler/libc additions below: those decide what the ARTEFACT links, and a
// build tool has no opinion about that.
func (o WrapOptions) toolPlus() string {
	parts := make([]string, 0, len(o.ToolDeps))
	for _, d := range o.ToolDeps {
		parts = append(parts, `"+`+d+`"`)
	}
	return strings.Join(parts, " ")
}

func (o WrapOptions) depPlus() string {
	parts := make([]string, 0, len(o.Deps)+1)
	for _, d := range o.Deps {
		parts = append(parts, `"+`+d+`"`)
	}
	wasi := o.Target.Platform == "wasip1"
	// A wasip1 target ALWAYS wants the llvm.org artifact, whatever the host: the
	// system toolchain of a darwin host has no wasm backend, and a recipe's
	// own compiler dependency is not one that can target wasm32-wasip1.
	if wasi || (!o.HasCompiler && !o.Bootstrap && o.Target.Platform != "windows" && o.Host.Platform != "darwin") {
		parts = append(parts, `"+llvm.org"`)
	}
	if wasi {
		parts = append(parts, `"+github.com/WebAssembly/wasi-libc"`, `"+compiler-rt.llvm.org/wasi"`)
	}
	// pkgx-libc mode needs the gnu.org/glibc artifact present in the eval so its
	// headers/crt/libc/loader are on disk under $ZPKG_DIR for wrapFlags to point
	// the compiler at (linux only). kernel.org/linux-headers supplies the Linux
	// kernel headers (linux/*.h, asm/*.h) glibc's own headers include — glibc's
	// recipe depends on it for exactly this reason; the artifact doesn't bundle
	// them and --sysroot cuts off the container's copy.
	if o.LibcZpkx && o.Target.Platform == "linux" {
		// gnu.org/binutils supplies ar/ranlib (the pkgx llvm.org artifact ships
		// llvm-ar, not a plain `ar`, and the sovereign mode must not fall back to
		// the container's binutils). Linking still uses lld via -fuse-ld=lld.
		// libcxx.llvm.org supplies the C++ runtime the bare llvm.org artifact omits:
		// its recipe builds libc++ + libc++abi + libunwind, so C++ recipes link
		// -stdlib=libc++ instead of the container's GNU libstdc++.
		glibcSpec := `"+gnu.org/glibc"`
		if o.Glibc != "" {
			// Pin the exact glibc version as the sysroot floor. Only this version
			// is then installed under $ZPKG_DIR, so wrapFlags' version-sort picks it.
			//
			// The pin is `@<version>` with NO operator: pkgx accepts a bare numeric
			// after `@` and REJECTS `@=2.27.0` with "Error: invalid semver". That
			// error aborts the whole env eval, so nothing at all gets installed —
			// which is how a pinned build ended up with unexpanded glibc globs AND
			// the container's gcc (the eval never put the pkgx llvm bin/cc on PATH).
			glibcSpec = `"+gnu.org/glibc@` + strings.TrimPrefix(o.Glibc, "=") + `"`
		}
		parts = append(parts, glibcSpec, `"+kernel.org/linux-headers"`, `"+gnu.org/binutils"`, `"+libcxx.llvm.org"`)
	}
	return strings.Join(parts, " ")
}

// libtoolToolVars neutralises the absolute tool paths libtool bakes into the
// scripts it ships.
//
// `libtoolize` opens with `: ${SED="<path>"}` — the path of the sed on the
// machine that BUILT libtool. In the pkgx artifact that is
// /__w/_actions/pkgxdev/brewkit/v1/libexec/sed, which exists nowhere else, so
// libtoolize's every sed call fails. It still exits 0, and prints its version
// with the program name stripped off (the name comes through that sed), so
// autogen.sh's version probe reads it as absent and says:
//
//	You must have libtoolize version >= 2.x.x, but you have none.
//
// which names neither libtool nor a path. Measured on the shipped artifact:
// bare `libtoolize --version` prints " (GNU libtool) 2.6.2" with two
// no-such-file errors; SED=sed prints "libtoolize (GNU libtool) 2.6.2" clean.
//
// GREP/EGREP/FGREP default to /bin/grep, which happens to exist in the debian
// build container and does NOT in a from-scratch sovereign one — the same
// failure waiting for --libc=pkgx.
//
// `: ${VAR=...}` only assigns when unset, so exporting these wins, and := keeps
// a value a recipe set deliberately. Every one of them is on PATH from the
// gnu.org/sed and gnu.org/grep artifacts the build env already carries.
const libtoolToolVars = `export SED="${SED:-sed}" GREP="${GREP:-grep}" EGREP="${EGREP:-grep -E}" FGREP="${FGREP:-grep -F}"
`

// toolVarProvider names the package each variable stands for. Presetting a
// variable for the package that PROVIDES it is the same mistake as putting a
// package's own artifact on the PATH of its own build: the factory hands the
// build an answer about the very thing being built.
var toolVarProvider = map[string]string{
	"SED":   "gnu.org/sed",
	"GREP":  "gnu.org/grep",
	"EGREP": "gnu.org/grep",
	"FGREP": "gnu.org/grep",
}

// toolVars is libtoolToolVars minus the variables the project being built
// provides itself.
//
// GNU grep's configure refuses OUTRIGHT if either is set — not if it is set to
// something bad, if it is set at all:
//
//	if test -n "$GREP" || test -n "$EGREP"; then
//	  as_fn_error $? "no working 'grep' found
//	  A working 'grep' command is needed to build GNU Grep.
//
// The message names a missing tool; the condition is a present variable. So
// gnu.org/grep could not be built here at all, and the error sent three
// separate investigations after the grep on PATH — which was fine the whole
// time (exit 0, valid signature, "uses PCRE2 10.48"). Reproduced locally: with
// GREP unset the same configure exits 0, and with GREP set to the absolute path
// of a working GNU grep it still refuses.
func toolVars(project string) string {
	var keep []string
	for _, v := range []string{"SED", "GREP", "EGREP", "FGREP"} {
		if toolVarProvider[v] == project {
			continue
		}
		switch v {
		case "EGREP":
			keep = append(keep, `EGREP="${EGREP:-grep -E}"`)
		case "FGREP":
			keep = append(keep, `FGREP="${FGREP:-grep -F}"`)
		default:
			keep = append(keep, v+`="${`+v+`:-`+strings.ToLower(v)+`}"`)
		}
	}
	if len(keep) == 0 {
		return ""
	}
	return "export " + strings.Join(keep, " ") + "\n"
}

// tmpdirLine sets TMPDIR (POSIX) or TMP/TEMP (windows host) under $HOME.
func tmpdirLine(host target.Target) string {
	if host.Platform == "windows" {
		return `export TMP="$HOME/tmp"; export TEMP="$HOME/tmp"; mkdir -p "$TMP"`
	}
	return `export TMPDIR="$HOME/tmp"; mkdir -p "$TMPDIR"`
}

// glibcLoader is the arch-specific ELF interpreter (PT_INTERP) filename glibc
// ships. It lives in the artifact's lib/glibc-<ver>/ dir.
//
// It reports ok=false for an arch it has not been told about, where it used to
// fall through to the x86-64 name. That default was the dangerous kind: nothing
// checks a --dynamic-linker path, the linker just writes it into PT_INTERP, so
// the build succeeds and every binary it produced dies at the first exec with
// "No such file or directory" naming a loader for the wrong machine.
//
// s390x is the reason this is a lookup and not a pattern. Its loader is
// ld64.so.1 -- not named after the architecture at all, unlike the other two --
// so a name derived from them would have been wrong in exactly that silent way.
func glibcLoader(arch string) (string, bool) {
	switch arch {
	case "aarch64", "arm64":
		return "ld-linux-aarch64.so.1", true
	case "x86-64", "amd64", "x86_64":
		return "ld-linux-x86-64.so.2", true
	case "s390x":
		// readelf -l /bin/true on the LinuxONE runner: [Requesting program
		// interpreter: /lib/ld64.so.1]
		return "ld64.so.1", true
	}
	return "", false
}

// darwinRpaths returns the -rpath flags a darwin link needs: the relative ones
// that make the artifact relocatable, then the absolute $ZPKG_DIR.
//
// The depth comes from where the package installs — $ZPKG_DIR/<project>/vX.Y.Z
// is three levels for a two-segment project and two for a one-segment one, and
// counting it by hand is how a wrong rpath gets shipped. A binary in bin/ or a
// dylib in lib/ is one level below that; libexec/<sub>/ is one more, so both
// are named. During the build the staging tree is <install>+brewing, the same
// depth, so the relative rpath resolves there too.
func darwinRpaths(zpkgDir, install string) []string {
	var out []string
	if rel, err := filepath.Rel(zpkgDir, install); err == nil && !strings.HasPrefix(rel, "..") && rel != "." {
		depth := len(strings.Split(filepath.ToSlash(rel), "/"))
		for _, extra := range rpathExtraDepths {
			up := strings.TrimSuffix(strings.Repeat("../", depth+extra), "/")
			out = append(out, "-Wl,-rpath,@loader_path/"+up)
		}
	}
	return append(out, "-Wl,-rpath,"+zpkgDir)
}

// rpathExtraDepths is how far below the prefix a Mach-O may sit and still get a
// relative rpath that reaches $ZPKG_DIR.
//
// 1 and 2 cover bin/ and lib/ — where almost everything lives — and they were
// enough until a guard started refusing artifacts that could only run on the
// machine that built them. libX11 then failed on
//
//	lib/X11/locale/common/ximcp.2
//
// a loadable input-method module four levels under the prefix, whose only rpath
// reaching a sibling package was the absolute one. The guard was right: that
// module resolved on the build machine and nowhere else, and had been shipping
// that way.
//
// An LC_RPATH cannot be lengthened after the fact, so the entry has to be
// linked in from the start or never exist. Four spare entries in every binary
// is a handful of bytes against a module tree that silently does not work.
var rpathExtraDepths = []int{1, 2, 3, 4, 5}

// wrapFlags returns the target-keyed compiler/linker FLAGS exports. A windows
// target gets none (PEs have no rpath and mingw rejects -pie).
func wrapFlags(tgt target.Target, zpkgDir, install string, hasBinutils, libcZpkx bool) []string {
	var out []string
	var ld []string
	switch tgt.Platform {
	case "darwin":
		// A darwin binary records its dependencies by ABSOLUTE install name, and
		// fixup rewrites those into @rpath/… so the artifact resolves wherever
		// $ZPKG_DIR happens to be. That only works if the binary carries an
		// LC_RPATH that reaches $ZPKG_DIR from where it is installed — and unlike
		// ELF's RUNPATH, an LC_RPATH cannot be lengthened after the fact: the
		// string lives in a fixed-size load command, and "@loader_path/../../../.."
		// is LONGER than the absolute path it would replace.
		//
		// So the relative rpath is linked in from the start. Its depth is a fact
		// about where this package installs, which we know here and the linker
		// does not. The absolute one stays as well, so anything that runs out of
		// the build tree keeps resolving the way it does today.
		ld = append(ld, darwinRpaths(zpkgDir, install)...)
		// Slack between the load commands and the first section, so fixup can
		// LENGTHEN an install name rather than skip it.
		//
		// CMake's default on darwin writes @rpath/<soname> — a bare name that
		// resolves nowhere, since a consumer's rpath reaches $ZPKG_DIR and not
		// the library's own lib dir. The correct name,
		// @rpath/facebook.com/zstd/v1.5.7/lib/libzstd.1.dylib, is longer than
		// the wrong one, and a Mach-O load command can only grow into slack the
		// linker left. It usually leaves plenty — 8284 bytes in our zstd dylib,
		// 5604 in its `zstd` binary — but "usually" is not a property to build
		// a fixup on. This makes it a guarantee, and it is what Homebrew links
		// every formula with, for the same reason.
		// -Wno-unused-command-line-argument travels WITH it, and is not
		// decoration. A linker flag handed to a COMPILE-ONLY invocation is
		// `'linker' input unused`, which under the -Werror that many configure
		// probes use is a hard error:
		//
		//   clang: error: -Wl,-headerpad_max_install_names: 'linker' input
		//     unused [-Werror,-Wunused-command-line-argument]
		//
		// A probe that fails does not stop the build — it turns a feature OFF,
		// silently, and the failure surfaces a thousand lines later as an
		// undeclared symbol. That is exactly why the linux driver carries the
		// same suppression (the xz case: "CFLAGS contains something that makes
		// -Werror complain"), and adding a linker flag to the darwin side
		// without it reopened the hole. Measured: the suppression works in
		// either order relative to -Werror, because -Werror promotes warnings
		// that are ENABLED and -Wno- disables this one outright.
		ld = append(ld, "-Wl,-headerpad_max_install_names", "-Wno-unused-command-line-argument")
	case "wasip1":
		// C/C++ for wasm32-wasip1, with OUR toolchain: the llvm.org artifact's clang
		// and wasm-ld, the wasi-libc sysroot and the compiler-rt builtins, each a
		// artifact built from source (wasi-sdk's recipe, taken apart; see
		// compiler-rt.llvm.org/wasi and github.com/WebAssembly/wasi-libc in the
		// pantry overlay). Nothing comes from the host distribution.
		//
		// The setting that must hold for EVERY recipe is in $ZPKB_CC/$ZPKB_CXX, the
		// stencil the cc/gcc/clang shims re-exec (cmd/zpkb/ccshim.go), and not in
		// CFLAGS/LDFLAGS, which a recipe's env replaces whole. $CC/$CXX default to
		// it for the recipes that do read them, as the sovereign linux mode does.
		//
		// -resource-dir points at the compiler-rt artifact, which carries clang's own
		// headers next to libclang_rt.builtins.a (wasi-sdk's wasi-resource-dir);
		// -mcpu=lime1 is wasi-sdk's WASI_SDK_CPU_CFLAGS default.
		//
		// AR/RANLIB are the LLVM ones, as darwin's are fixed to /usr/bin/ar below:
		// the host binutils cannot write a wasm object index.
		out = append(out, wasiResolve...)
	case "linux":
		// Both arches get an absolute -Wl,-rpath,$ZPKG_DIR so the linker emits a
		// DT_RUNPATH *slot* fixup/rpath.go later rewrites $ORIGIN-relative. A
		// literal "$ORIGIN" here would be mangled by shell/make re-expansion, so
		// we pass the absolute ZPKG_DIR and relocate it at fixup time.
		//
		// We deliberately do NOT add -pie. gcc already defaults to PIE for
		// executables (measured: debian gcc 14.2 `gcc main.c` → a PIE executable),
		// so an explicit -pie buys nothing there — but it ALSO lands on -shared
		// library links, where it conflicts with -shared and makes ld try to build
		// an executable → "undefined reference to `main`" (this broke every
		// shared-lib recipe on x86-64, e.g. openssl's libcrypto.so.4, so those
		// artifacts never published for linux/x86-64). -fPIC in CFLAGS still gives
		// the position-independent objects both PIE executables and shared libs
		// need; PIE-ness of the final executable is the toolchain default.
		ld = append(ld, "-Wl,-rpath,"+zpkgDir)
	}

	// pkgx-libc mode (linux): resolve the gnu.org/glibc artifact in the eval'd
	// $ZPKG_DIR at build time (its version isn't known here, so glob + version-
	// sort in the shell), then point the compiler driver at its headers, crt
	// objects, libc and dynamic linker. --rtlib=compiler-rt keeps the runtime on
	// llvm's builtins (the pkgx llvm.org artifact ships compiler-rt but no libgcc);
	// --unwindlib=none avoids the libgcc_s unwinder the C toolchain would
	// otherwise pull (fine for exception-free C — the mode's scope). The result
	// links its interpreter + libc from the artifact, not the debian container.
	var glibcCC, glibcCXX, glibcLD string
	if libcZpkx && tgt.Platform == "linux" {
		// Resolve the newest installed version dir of each artifact. Two hazards:
		// pkgx creates a symlink literally NAMED "v*" (alongside v2, v2.44,
		// v2.44.0) which a "v*/" glob would match and — worse — sort -V ranks
		// LAST, so the chosen value would still contain a wildcard that re-globs
		// into every version dir when the unquoted CFLAGS reach the linker. The
		// "v[0-9]*/" pattern skips that symlink and lands on a concrete version
		// dir (no metacharacters, glob-safe downstream). The `set +f` re-enables
		// globbing in each subshell in case pkgx's env eval left the shell noglob.
		//
		// The glob must NOT carry the trailing slash: `sort -V` compares "v2/"
		// ABOVE "v2.27.0/" (the '/' outranks '.'), so a trailing-slash pattern
		// selects the LEAST specific entry — `v2`, a FLOATING symlink. A binary
		// whose PT_INTERP goes through `v2` silently loads whatever glibc `v2`
		// points at later, which defeats the whole point of pinning a floor.
		// Globbing without the slash sorts v2 < v2.27 < v2.27.0, so the concrete
		// version dir wins; the slash is appended afterwards.
		// bkresolve prints the newest concrete version dir of an artifact, or NOTHING
		// when that artifact is not installed. A shell leaves an unmatched pattern
		// LITERAL, and a literal `v[0-9]*` in the flags poisons the link — that is
		// how a build with no libcxx artifact ended up passing
		// `-L/pkgx/libcxx.llvm.org/v[0-9]*/lib` to the linker and failing
		// configure's very first "can the compiler create executables" probe.
		out = append(out, sysrootResolve...)
		// Shared driver flags: glibc sysroot (its headers + the kernel headers it
		// includes), glibc crt/libc, and llvm's compiler-rt builtins (no libgcc).
		// -L takes NO space: libtool parses the flag itself and rejects a
		// separated form outright ("require no space between '-L' and '/…'"),
		// which is what broke pcre2. -Wno-unused-command-line-argument keeps the
		// LINK flags (--rtlib/--unwindlib/-fuse-ld) from making clang warn when
		// it is merely compiling: a warning there turns into an error under the
		// -Werror probe several configure scripts run, and xz then refuses to
		// configure at all ("CFLAGS contains something that makes -Werror
		// complain").
		// ${ZPKB_LIBGCC:+…}: rustc emits a bare `-lgcc` of its own — the unwind
		// and compiler_builtins crates name it in `#[link]` on *-linux-gnu —
		// which --rtlib=compiler-rt does NOT remove. It is a SEARCH PATH that is
		// missing, so it belongs with the other driver flags rather than in
		// RUSTFLAGS: see the note where RUSTFLAGS used to be set.
		base := baseSysrootFlags
		// C: no unwinder (exception-free C). C++: libc++ headers + its libunwind,
		// from the libcxx.llvm.org artifact (-stdlib=libc++ makes the driver link
		// -lc++ itself when it links a C++ target).
		glibcCC = base + ` --unwindlib=none`
		// libc++'s headers MUST precede glibc's on the search path — its <cstdio>
		// pulls libc++'s own <stdio.h> wrapper and #errors if a C <stdio.h> is
		// found first — so the libc++ -isystem goes BEFORE base's glibc/kernel ones.
		// ${VAR:+…} so an ABSENT libcxx artifact contributes nothing at all rather
		// than an unmatched pattern.
		glibcCXX = `${ZPKB_LIBCXX_PREFIX:+-stdlib=libc++ -isystem "${ZPKB_LIBCXX_PREFIX}include/c++/v1"} ` + base + ` ${ZPKB_LIBCXX_PREFIX:+--unwindlib=libunwind}`
		// PT_INTERP = the artifact's loader; search paths for glibc + libc++/libunwind
		// libs (the $ORIGIN rewrite by fixup drops these, so at deploy libc.so.6 /
		// libc++.so.1 come from their artifacts via LD_LIBRARY_PATH — the mkscratch
		// closure model). --disable-new-dtags emits DT_RPATH (searched for the
		// loader's own NEEDED libs).
		// --undefined-version: lld 17 flipped its default to --no-undefined-version,
		// where GNU ld tolerates a version script naming a symbol the build did not
		// produce. Recipes are written against GNU ld, so the strict default turns
		// a long-standing warning into a fatal error — gnu.org/gettext dies with
		//   ld.lld: error: version script assignment of 'global' to symbol
		//   'iconv_ostream_create' failed: symbol not defined
		// because libtextstyle's script exports symbols its configure left out.
		// Distros switching to lld restore the permissive behaviour the same way.
		glibcLD = `-Wl,-rpath,"$ZPKB_GLIBC_LIB" ${ZPKB_LIBCXX_PREFIX:+-L"${ZPKB_LIBCXX_PREFIX}lib" -Wl,-rpath,"${ZPKB_LIBCXX_PREFIX}lib"} -Wl,--disable-new-dtags -Wl,--undefined-version`
		if loader, ok := glibcLoader(tgt.Arch); ok {
			glibcLD = `-Wl,--dynamic-linker="${ZPKB_GLIBC_LIB}` + loader + `" ` + glibcLD
		}
		// No --dynamic-linker for an arch glibcLoader does not know: the link
		// then keeps lld's own default, which for the native build this always
		// is names the HOST's loader. That is the host's glibc rather than the
		// artifact's -- a weaker guarantee, and visible in the resulting binary --
		// where naming another machine's loader produces one that cannot start
		// at all. A new arch belongs in glibcLoader; this is what happens until
		// someone puts it there.
		ld = append(ld, glibcLD)
		// Pin the compiler to the pkgx llvm one AND carry the whole driver
		// configuration inside it.
		//
		// Two reasons, both measured. (a) The flag set is clang's
		// (--rtlib/--unwindlib/-fuse-ld=lld) while the artifact provides `cc` and
		// `clang` but NOT `gcc`, and autoconf probes `gcc` FIRST — so a
		// ./configure recipe silently picked the container's gcc and died with
		// `cc: error: unrecognized command-line option '--unwindlib=none'`.
		// (b) libtool builds its own compile and LINK command lines and does not
		// pass the recipe's CFLAGS/LDFLAGS to them, so a libtool link fell back
		// to the GCC runtime — `ld.lld: cannot open crti.o … unable to find
		// -lgcc`. It does preserve $CC verbatim, so the sysroot, the crt/lib
		// search paths and the runtime choice belong there. (This is what
		// distributions do for cross toolchains.)
		//
		// Scoped to this mode: a global CC=clang was measured and rejected for
		// ordinary builds, where the flags stay compiler-neutral.
		out = append(out,
			`export CC="${CC:-clang `+glibcCC+`}"`,
			`export CXX="${CXX:-clang++ `+glibcCXX+`}"`,
			// What the cc/gcc/c++/g++ shims re-exec. A recipe that calls the
			// compiler by name instead of through $CC (sqlite's autosetup: "No
			// working C compiler found. Tried cc and gcc") then still gets the
			// sovereign driver.
			`export ZPKB_CC="clang `+glibcCC+`"`,
			`export ZPKB_CXX="clang++ `+glibcCXX+`"`,
			// What bindgen reads, because it never asks the driver. APPENDED
			// to whatever a recipe set, not substituted for it: a recipe
			// naming an extra -I has a reason, and the sysroot is not ours to
			// drop on its behalf.
			`export BINDGEN_EXTRA_CLANG_ARGS="`+bindgenSysrootFlags+` ${BINDGEN_EXTRA_CLANG_ARGS:-}"`,
			// The driver for a build that is FREESTANDING by construction: the
			// pinned pkgx clang and nothing else. A kernel supplies its own
			// headers and its own runtime, and glibc's headers are not merely
			// unnecessary there — they are wrong.
			//
			// arch/arm64/include/asm/neon-intrinsics.h redefines __INT64_TYPE__ to
			// `long long` so that THE COMPILER's stdint.h derives an int64_t
			// compatible with the kernel's s64. glibc's stdint.h derives nothing:
			// its bits/types.h fixes __int64_t at `long`. So arch/arm64/lib/xor-neon.c
			// — the one file in the tree that includes <arm_neon.h>, which includes
			// <stdint.h> — died with
			//   bits/stdint-intn.h:27: error: typedef redefinition with different
			//     types ('__int64_t' (aka 'long') vs 's64' (aka 'long long'))
			// and the include trace went arm_neon.h -> glibc/include/stdint.h
			// DIRECTLY: clang's own stdint.h was never opened.
			//
			// The kernel already asks for the right thing and cannot get it. It
			// passes `-nostdinc -isystem $(CC -print-file-name=include)`, and
			// neither half reaches the -isystem above, measured:
			//   clang -E -v -nostdinc -isystem FAKELIBC        -> FAKELIBC only
			//     (-nostdinc drops the standard and builtin dirs, never an
			//      explicit -isystem)
			//   clang -isystem FAKELIBC -E -v -nostdinc -isystem $RESOURCE_DIR
			//                                                  -> FAKELIBC, then
			//      $RESOURCE_DIR — the driver's entry is PREPENDED and outranks
			//      what the caller adds, whatever the caller adds.
			// Same shape as #111: the caller cannot filter what the driver
			// prepends, so the escape has to be offered here.
			//
			// -ffreestanding is NOT that escape and was tried: it sets
			// __STDC_HOSTED__ to 0, which is the condition inside clang's stdint.h
			// — a file that is never reached. The flag moved nothing; the same
			// error came back with `KCFLAGS=-ffreestanding` on the make line.
			//
			// A recipe must pass this on the make COMMAND LINE (`make CC=...`):
			// kbuild assigns CC in the makefile, which beats the environment, so a
			// kernel otherwise compiles through the `gcc` shim and back into the
			// hosted driver.
			`export ZPKB_CC_FREESTANDING="clang"`,
			// rustc does NOT go through $CC: it invokes `cc` itself as the
			// linker driver, with its own arguments. That is survivable only
			// because `cc` on PATH is bk's own shim, which re-execs $ZPKB_CC — so
			// everything above (sysroot, crt and lib search paths, the runtime
			// choice, and now the libgcc search path) reaches rustc's link after
			// all. Anything NOT in $ZPKB_CC does not.
			//
			// rustc emits a bare `-lgcc` of its own on *-linux-gnu, which
			// --rtlib=compiler-rt does not remove, and a tree with no
			// distribution has no libgcc on any default search path:
			//   ld.lld: error: unable to find library -lgcc
			// which is every Rust recipe, not one — it surfaced on getrandom and
			// zerocopy, build scripts of crates nobody named.
			//
			// RUSTFLAGS was the first vehicle for that path and was the WRONG
			// one: a recipe may set `env: RUSTFLAGS:`, and a recipe's env is
			// emitted AFTER this preamble, so it overwrites the variable whole.
			// crates.io/wasm-pack and crates.io/spider_cli both do exactly that
			// (`-A warnings`, `-C target-cpu=x86-64 -C link-args=-pie`), and
			// both went on failing with
			//   ld.lld: error: unable to find library -lgcc
			// while pqrs and typos — which set no RUSTFLAGS — built fine. Two
			// recipes out of fourteen was enough to read the fix as general when
			// it was not.
			//
			// --rtlib=compiler-rt moves the BUILTINS; the unwinder is separate,
			// and on linux-gnu rustc's unwind crate links `gcc_s` by name
			// (library/unwind/src/lib.rs), an ordinary lib/ entry of the
			// gnu.org/gcc artifact that resolves when that artifact is in the
			// closure. What was missing was only libgcc.a's DIRECTORY.
		)
	}

	if len(ld) > 0 {
		out = append(out, `export LDFLAGS="`+strings.Join(ld, " ")+` $LDFLAGS"`)
	}

	// rustc does not read LDFLAGS. It invokes the linker itself, so the
	// -Wl,-rpath just put in LDFLAGS never reaches a Rust link.
	//
	// On linux that is survivable: `cc` on PATH is bk's own shim, which re-execs
	// $ZPKB_CC with every sovereign flag. On DARWIN there is no shim — they are
	// materialised only in pkgx-libc mode — so a Rust package that links a pkgx
	// dylib publishes a binary with NO LC_RPATH at all, and `@rpath/...` can
	// never resolve:
	//
	//   dyld: Library not loaded: @rpath/openssl.org/v3.6.4/lib/libssl.3.dylib
	//     Referenced from: …/.pkgx/rust-lang.org/cargo/v0.99.0/bin/cargo
	//     Reason: no LC_RPATH's found
	//
	// It went unnoticed because cargo's darwin artifact had always been MIRRORED
	// from upstream, which links its own rpath. The first time we built it
	// ourselves, it came out unable to start — published, signed and attested.
	//
	// Composed with any RUSTFLAGS the recipe sets rather than replacing it: a
	// recipe's env is emitted after this preamble and would otherwise take the
	// variable away, which is exactly how the -lgcc fix was lost once already.
	//
	// It takes the SAME list as LDFLAGS, relative entries included. Handing
	// rustc only the absolute one would leave every Rust package with no rpath
	// reaching $ZPKG_DIR from where it installs — and fixup, which checks that
	// before rewriting an install name into @rpath/…, would then correctly
	// refuse to touch it. The artifact would build, publish and run on the
	// runner, and be exactly as unrelocatable as before. Measured on the
	// republished pqrs and getzola artifacts, which carried `/Users/runner/.pkgx`
	// and nothing else after LDFLAGS alone had been fixed.
	if tgt.Platform == "darwin" {
		var rf []string
		for _, r := range darwinRpaths(zpkgDir, install) {
			rf = append(rf, "-C link-arg="+r)
		}
		// The install-name slack, for the same reason as LDFLAGS: a Rust cdylib
		// gets its install name from the same linker, and leaving it out here
		// would be an asymmetry with no reason behind it.
		rf = append(rf, "-C link-arg=-Wl,-headerpad_max_install_names")
		out = append(out, `export RUSTFLAGS="${RUSTFLAGS:-} `+strings.Join(rf, " ")+`"`)
	}
	if tgt.Platform == "linux" {
		// Relax the C23 hard errors that gcc-14 / clang-16 turned on by default
		// (implicit function/int declarations, int<->pointer conversions). Many
		// long-standing C recipes still trip these and upstream has not adapted;
		// the whole distro ecosystem (Fedora, Debian, …) demotes them back to
		// warnings for the mass rebuild, so the toolchain default doesn't gate an
		// otherwise-buildable recipe. C-only — CXXFLAGS keeps just the PIC flag.
		cflags := "-Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion"
		if glibcCC != "" {
			// CLANG ONLY, and only in sovereign mode, which is the only mode that
			// compiles with clang. gcc has no -Wincompatible-function-pointer-types
			// (it spells the check -Wincompatible-pointer-types), and an unknown
			// warning name inside -Wno-error= is a hard error rather than the
			// silent no-op an unknown -Wno- gets:
			//
			//   cc1: error: '-Wno-error=incompatible-function-pointer-types':
			//   no option '-Wincompatible-function-pointer-types'; did you mean
			//   '-Wincompatible-pointer-types'?
			//
			// which is how kernel.org/libcap stopped building in CI — where bk uses
			// the runner's gcc — while the sovereign builder was unaffected.
			//
			// -Wno-error= (not -Wno-) because an incompatible function pointer is a
			// real type error that can crash at run time, unlike an implicit
			// declaration: the diagnostic stays VISIBLE in the build log even though
			// it no longer fails the build. gnu.org/gettext trips it
			// (iconv-ostream.c:297, an ostream vtable initialiser).
			cflags = glibcCC + " " + cflags + " -Wno-error=incompatible-function-pointer-types"
		}
		if tgt.Arch == "x86-64" {
			cflags = "-fPIC " + cflags
			cxxflags := "-fPIC"
			if glibcCXX != "" {
				cxxflags = glibcCXX + " " + cxxflags
			}
			out = append(out, `export CXXFLAGS="`+cxxflags+` $CXXFLAGS"`)
		} else if glibcCXX != "" {
			out = append(out, `export CXXFLAGS="`+glibcCXX+` $CXXFLAGS"`)
		}
		out = append(out, `export CFLAGS="`+cflags+` $CFLAGS"`)
	}
	if tgt.Platform == "darwin" {
		out = append(out, "export MACOSX_DEPLOYMENT_TARGET=11.0")
		if hasBinutils {
			out = append(out, "export AR=/usr/bin/ar", "export RANLIB=/usr/bin/ranlib")
		}
	}
	return out
}

// wasiFlags is the driver stencil of a wasip1/wasm build: target, sysroot,
// resource dir (compiler-rt builtins + clang headers) and the wasm CPU
// baseline. Quoted paths: a $ZPKG_DIR with a space must not split them.
//
// --rtlib=compiler-rt: the llvm.org artifact's clang defaults to libgcc, so a wasm
// LINK asked wasm-ld for -lgcc ("wasm-ld: error: unable to find library -lgcc",
// sqlite3, wasip1-c run 40369903497). wasi-sdk builds its clang with
// CLANG_DEFAULT_RTLIB=compiler-rt; we state it in the stencil instead, as the
// linux sovereign mode does.
const wasiFlags = `--target=wasm32-wasip1 --sysroot="$ZPKB_WASI_SYSROOT" -resource-dir="$ZPKB_WASI_RT" -mcpu=lime1 --rtlib=compiler-rt -Wno-unused-command-line-argument`

// wasiResolve locates the two wasip1 toolchain artifacts and exports the stencil.
// It fails the build when either is absent: a missing sysroot would not stop
// clang, which would fall back to compiling for wasm32 with NO libc, and the
// failure would surface as an undeclared stdio.h a thousand lines later.
var wasiResolve = []string{
	sysrootResolve[0],
	`export ZPKB_WASI_SYSROOT="$(bkresolve "$ZPKG_DIR/github.com/WebAssembly/wasi-libc/v[0-9]*")"`,
	`export ZPKB_WASI_RT="$(bkresolve "$ZPKG_DIR/compiler-rt.llvm.org/wasi/v[0-9]*")"`,
	`[ -n "$ZPKB_WASI_SYSROOT" ] && [ -n "$ZPKB_WASI_RT" ] || { echo "zpkb: the wasip1 toolchain is not installed (github.com/WebAssembly/wasi-libc, compiler-rt.llvm.org/wasi)" >&2; exit 1; }`,
	`export ZPKB_CC="clang ` + wasiFlags + `"`,
	// libc++/libc++abi are a separate artifact (libcxx.llvm.org/wasi), present only
	// when the recipe asked for it. A sysroot cannot carry it — it is wasi-libc's —
	// so the C++ stencil names its headers and its libraries itself. -nostdinc++
	// keeps the driver from also looking for c++/v1 under the wasi-libc sysroot;
	// the -L is a link flag, which the shim drops for compile-only steps.
	// -fno-exceptions because that is how libc++ is built here: clang does not
	// default to it for wasm32-wasip1, and a TU that throws needs __cxa_throw,
	// which this libc++abi (exceptions off, no unwinder) does not provide
	// ("undefined symbol: __cxa_allocate_exception", simdjson, run 40389842826).
	`export ZPKB_WASI_CXX="$(bkresolve "$ZPKG_DIR/libcxx.llvm.org/wasi/v[0-9]*")"`,
	`export ZPKB_CXX="clang++ ` + wasiFlags + `${ZPKB_WASI_CXX:+ -fno-exceptions -stdlib=libc++ -nostdinc++ -isystem $ZPKB_WASI_CXX/include/wasm32-wasip1/c++/v1 -L$ZPKB_WASI_CXX/lib/wasm32-wasip1}"`,
	`export CC="${CC:-$ZPKB_CC}" CXX="${CXX:-$ZPKB_CXX}"`,
	`export AR=llvm-ar RANLIB=llvm-ranlib NM=llvm-nm STRIP=llvm-strip`,
}

const baseSysrootFlags = `--sysroot="$ZPKB_GLIBC_PREFIX" -isystem "${ZPKB_GLIBC_PREFIX}include" -isystem "${ZPKB_KHDR_PREFIX}include" -B "$ZPKB_GLIBC_LIB" -L"$ZPKB_GLIBC_LIB"${ZPKB_LIBGCC:+ -L"$ZPKB_LIBGCC"} --rtlib=compiler-rt -fuse-ld=lld -Wno-unused-command-line-argument`

// bindgenSysrootFlags is the HEADER-FINDING half of the flags above, for a
// tool that never links.
//
// ⛔ BINDGEN DOES NOT GO THROUGH THE COMPILER DRIVER. Everything sovereign
// about this environment reaches a build through `cc` — the shim that
// re-execs $ZPKB_CC — or through $CC. bindgen drives **libclang** in-process
// instead, so it sees none of it, and parsing openssl's headers died on
//
//	/pkgx/openssl.org/v3.6.4/include/openssl/asn1.h:27:10:
//	  fatal error: 'stdio.h' file not found
//
// on rpm.org/rpm-sequoia (go-zpkg/packages run 40498046156) — openssl 3 was
// found and configured correctly, and then a C library's first #include was
// unreachable because libclang had no sysroot.
//
// bindgen's own documentation names this case and this variable:
// "End-users of the crate may need to set the BINDGEN_EXTRA_CLANG_ARGS
// environment variable to … --sysroot=/path/to/sysroot" (bindgen/lib.rs:260).
//
// Only the flags that find headers. --rtlib, -fuse-ld and -L are link-time
// options for a tool that produces no binary, and handing them to libclang
// is noise at best.
const bindgenSysrootFlags = `--sysroot="$ZPKB_GLIBC_PREFIX" -isystem "${ZPKB_GLIBC_PREFIX}include" -isystem "${ZPKB_KHDR_PREFIX}include"`

// sysrootResolve locates the artifacts a pkgx-supplied libc toolchain needs and
// exports their prefixes. Shared with the TEST wrapper, which needs the same
// sysroot for the same reason and must not grow a second copy that drifts.
var sysrootResolve = []string{
	`bkresolve() { set +f; for d in $1; do case "$d" in *'*'*|*'['*) continue;; esac; printf '%s\n' "$d"; done | sort -V | tail -n1; }`,
	`export ZPKB_GLIBC_PREFIX="$(bkresolve "$ZPKG_DIR/gnu.org/glibc/v[0-9]*")"`,
	`[ -n "$ZPKB_GLIBC_PREFIX" ] && export ZPKB_GLIBC_PREFIX="$ZPKB_GLIBC_PREFIX/"`,
	`export ZPKB_GLIBC_LIB="$(bkresolve "${ZPKB_GLIBC_PREFIX}lib/glibc-[0-9]*")"`,
	`[ -n "$ZPKB_GLIBC_LIB" ] && export ZPKB_GLIBC_LIB="$ZPKB_GLIBC_LIB/"`,
	`export ZPKB_KHDR_PREFIX="$(bkresolve "$ZPKG_DIR/kernel.org/linux-headers/v[0-9]*")"`,
	`[ -n "$ZPKB_KHDR_PREFIX" ] && export ZPKB_KHDR_PREFIX="$ZPKB_KHDR_PREFIX/"`,
	`export ZPKB_LIBCXX_PREFIX="$(bkresolve "$ZPKG_DIR/libcxx.llvm.org/v[0-9]*")"`,
	`[ -n "$ZPKB_LIBCXX_PREFIX" ] && export ZPKB_LIBCXX_PREFIX="$ZPKB_LIBCXX_PREFIX/"`,
	`export ZPKB_LIBGCC="$(bkresolve "$ZPKG_DIR/gnu.org/gcc/v[0-9]*/lib/gcc/*/[0-9]*")"`,
}

// SysrootCC is the driver flag set for compiling C against a pkgx-supplied
// glibc. It is the sysroot and nothing else: no recipe CFLAGS, no rpath, no
// CMAKE_PREFIX_PATH. A test that compiles must be able to produce a binary at
// all; it must NOT be handed the flags that made the artefact link, or a
// artifact whose own headers are wrong would still pass.
const SysrootCC = baseSysrootFlags + ` --unwindlib=none`

// SysrootCXX is SysrootCC plus libc++.
const SysrootCXX = `${ZPKB_LIBCXX_PREFIX:+-stdlib=libc++ -isystem "${ZPKB_LIBCXX_PREFIX}include/c++/v1"} ` + baseSysrootFlags + ` ${ZPKB_LIBCXX_PREFIX:+--unwindlib=libunwind}`
