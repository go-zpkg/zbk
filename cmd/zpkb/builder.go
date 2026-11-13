package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/bottle"
)

// runBuilder implements `bk builder`: stage a FROM-scratch build environment as
// a DIRECTORY — a pkgx closure, the loader and /bin/sh posed at their canonical
// paths, stubs in /usr/bin, and the bk/pkgx binaries that drive a build.
//
// The image the sovereign pilot used was assembled by a Containerfile: a
// `FROM scratch` stage whose RUN step let pkgm install the toolchain from
// inside the image. That works, but it needs a container builder to exist and
// to be running the target's architecture, and it produces only an image —
// while the thing that actually consumes a builder rootfs, a micro-VM, boots a
// DIRECTORY (weft shares it over virtio-fs; an OCI image is unpacked back into
// a directory before boot). So the directory is the primitive, and this
// subcommand produces it directly, in Go, on any host: bottle.InstallFor and
// bottle.StubBinsStaged already know how to materialise another platform's
// userland.
//
// Nothing here needs root, docker, or a linux machine.
func runBuilder(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("builder", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory to stage the rootfs in (required)")
	platform := fs.String("platform", envOr("PLATFORM", "linux/aarch64"), "target os/arch")
	toolchain := fs.String("toolchain", "", "file listing the toolchain packages, one `project[constraint]` per line (default: the built-in list)")
	bkBin := fs.String("zpkb", "", "path to a target-arch zpkb binary to install at /usr/local/bin/zpkb")
	zpkgxBin := fs.String("zpkgx", "", "path to a target-arch zpkgx binary to install at /usr/local/bin/zpkgx")
	dist := fs.String("dist", "", "bottle registry to install from (default $ZPKG_DIST)")
	overlay := fs.String("overlay", "", "pantry overlay consulted before the upstream pantry (default $ZPKG_PANTRY_OVERLAY)")
	microvm := fs.Bool("microvm", false, "also write .weft-microvm/config.json so `weft microvm run` can boot the directory as-is")
	container := fs.Bool("container", false, "also write /etc/ld.so.conf listing every staged library directory, so the tree runs as a CONTAINER root and not only under bk's build wrapper")
	dryRun := fs.Bool("dry-run", false, "resolve the toolchain closure for --platform, print it, and stage nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" && !*dryRun {
		fmt.Fprintln(stderr, "usage: bk builder --out <dir> [--platform linux/aarch64] [--toolchain file]")
		return 2
	}
	osn, arch, _ := strings.Cut(*platform, "/")
	if osn != "linux" {
		fmt.Fprintf(stderr, "builder: %s images are not a thing — a scratch rootfs is a linux notion\n", osn)
		return 2
	}
	if *dist != "" {
		bottle.DistBase = strings.TrimRight(*dist, "/")
	}
	if *overlay != "" {
		bottle.PantryOverlay = strings.TrimRight(*overlay, "/")
	}

	roots, err := toolchainRoots(*toolchain)
	if err != nil {
		fmt.Fprintln(stderr, "builder:", err)
		return 1
	}

	if *dryRun {
		return dryRunClosure(roots, osn, arch, stdout, stderr)
	}

	if err := stageBuilder(stageOptions{
		Root:      *out,
		OS:        osn,
		Arch:      arch,
		Roots:     roots,
		BkBin:     *bkBin,
		ZpkgxBin:  *zpkgxBin,
		MicroVM:   *microvm,
		Container: *container,
		Overlay:   bottle.PantryOverlay,
		Dist:      bottle.DistBase,
		Log:       func(s string) { fmt.Fprintln(stdout, s) },
	}); err != nil {
		fmt.Fprintln(stderr, "builder:", err)
		return 1
	}
	return 0
}

// dryRunClosure answers one question, and it is the question asked before every
// sovereign job: does this ARCHITECTURE have the bottles the toolchain names?
//
// Resolution is the phase that fails when it does not. On 2026-08 the s390x
// lane died ninety seconds in with
//
//	builder: resolve closure: GET https://dist.pkgx.dev/gnu.org/glibc/linux/s390x/versions.txt: Not Found
//
// — a complete and correct answer, paid for with a runner, a checkout and a
// Go toolchain build. The same answer costs one HTTP round trip per project
// here, because PickVersionForAll reads a version list that is already
// per-platform: a version picked for linux/s390x is a version the registry
// lists for linux/s390x.
//
// What it does NOT prove is that each bottle can be unpacked and run — only
// staging and then building do that. It is a NECESSARY condition reported
// cheaply, not a sufficient one, and saying so is the difference between a
// pre-flight check and a false green.
func dryRunClosure(roots map[string]string, osn, arch string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "builder: resolving the toolchain closure for %s/%s (staging nothing)\n", osn, arch)
	closure, err := resolveClosureFor(roots, osn, arch)
	if err == nil {
		for _, r := range closure {
			fmt.Fprintf(stdout, "%s %s\n", r.Project, r.Version.Raw)
		}
		fmt.Fprintf(stdout, "builder: %d packages resolve for %s/%s; none was downloaded\n", len(closure), osn, arch)
		return 0
	}
	fmt.Fprintln(stderr, "builder: resolve closure:", err)
	reportRootGaps(roots, osn, arch, stdout)
	return 1
}

// reportRootGaps names EVERY root that cannot resolve, not the first.
//
// The joint resolution above is the authoritative answer and it stops at the
// first refusal, which is right for a build and useless for planning: on an
// architecture being brought up, each run then names one missing package and
// the next gap is only visible once that one is built. Learning a 25-entry
// toolchain's gaps that way costs 25 builds, serially, with a human between
// each.
//
// So on failure each root is resolved ON ITS OWN. A root's walk still covers
// its transitive dependencies, so a shared dependency that is missing shows up
// against every root that needs it — which reads as more gaps than there are
// packages to build, and is the truth: that is how many roots are blocked.
//
// This is diagnosis, not the verdict. A run where every root resolves alone
// can still fail jointly, because two roots may demand versions that do not
// intersect — that is what the error above says and this does not replace it.
func reportRootGaps(roots map[string]string, osn, arch string, stdout io.Writer) {
	names := make([]string, 0, len(roots))
	for p := range roots {
		names = append(names, p)
	}
	sort.Strings(names)
	var missing []string
	for _, p := range names {
		if _, err := resolveClosureFor(map[string]string{p: roots[p]}, osn, arch); err != nil {
			missing = append(missing, p)
			fmt.Fprintf(stdout, "  BLOCKED %s: %v\n", p, err)
		}
	}
	if len(missing) == 0 {
		fmt.Fprintf(stdout, "builder: every root resolves on its own — the refusal above is a CONFLICT between them, not a missing bottle\n")
		return
	}
	fmt.Fprintf(stdout, "builder: %d of %d roots cannot resolve for %s/%s: %s\n",
		len(missing), len(names), osn, arch, strings.Join(missing, " "))
}

// glibcLayout lists what the staged glibc actually contains, for the error
// that says the loader is not there.
//
// "Not found" is a fact about the LOOKUP as much as about the tree, and the
// two readings send a person to different places. FindLoaderFor globs
// `<dir>/gnu.org/glibc/v*/lib/glibc-*/<name>`; a bottle that puts its loader
// one directory over satisfies none of it and looks exactly like a bottle
// that has no loader at all.
//
// Measured need: the s390x lane refused with this message AFTER the loader
// NAME had been fixed (go-zpkg/bottle#105), so the name was right and the
// path was the question — and the log said nothing about the path. One round
// trip to a runner to learn a directory listing is one too many.
//
// Names only, and capped: this goes in an error, not a report.
func glibcLayout(zpkgDir string) string {
	roots, _ := filepath.Glob(filepath.Join(zpkgDir, bottle.GlibcProject, "v*"))
	if len(roots) == 0 {
		return "\n  (no gnu.org/glibc directory under " + zpkgDir + ")"
	}
	var b strings.Builder
	for _, r := range roots {
		for _, sub := range []string{"lib", "lib64"} {
			dir := filepath.Join(r, sub)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
				if len(names) == 12 {
					names = append(names, "…")
					break
				}
			}
			fmt.Fprintf(&b, "\n  %s: %s", dir, strings.Join(names, " "))
			// And one level into a versioned subdir, which is where the
			// loader belongs and where the glob looks.
			for _, e := range entries {
				if !e.IsDir() || !strings.HasPrefix(e.Name(), "glibc-") {
					continue
				}
				inner, err := os.ReadDir(filepath.Join(dir, e.Name()))
				if err != nil {
					continue
				}
				var ld, some []string
				for _, f := range inner {
					if strings.HasPrefix(f.Name(), "ld") {
						ld = append(ld, f.Name())
					}
					if len(some) < 8 {
						some = append(some, f.Name())
					}
				}
				// The COUNT alone was not enough, measured the hard way: the
				// s390x tree reported "2 entr(y/ies), ld*:" and a real glibc
				// has two hundred. That says the bottle is nearly empty, and
				// says nothing about WHICH two — which is the next question
				// every time. Name a few.
				fmt.Fprintf(&b, "\n  %s: %d entr(y/ies) [%s%s], ld*: %s",
					filepath.Join(dir, e.Name()), len(inner), strings.Join(some, " "),
					map[bool]string{true: " …"}[len(inner) > len(some)],
					strings.Join(ld, " "))
			}
		}
	}
	return b.String()
}

// alreadyStaged counts the closure members whose prefix is already on disk,
// which is exactly what bottle.InstallFor will skip.
func alreadyStaged(zpkgDir string, closure []bottle.Resolved) int {
	n := 0
	for _, r := range closure {
		if st, err := os.Stat(filepath.Join(zpkgDir, r.Project, "v"+r.Version.Raw)); err == nil && st.IsDir() {
			n++
		}
	}
	return n
}

// guestZpkgDir is where the staged bottles live once the rootfs is the root:
// the stubs, the loader symlinks and ZPKG_DIR must all agree on it.
//
// ⛔ IT WAS "/pkgx" UNTIL 2026-11-12, AND THAT WAS THE LAST PLACE UPSTREAM'S
// NAME DECIDED SOMETHING. Our prefix is zpkg: the user store is already
// ~/.zpkg (bottle.Dir), the environment variable is ZPKG_DIR, and only the
// guest root inside the build container still said otherwise. A build
// container that mounts somebody else's directory name has not been renamed,
// it has been relabelled — the same sentence bottle/zpkg.go:373 uses about
// what a command PRINTS.
//
// ⛔ This is a PRODUCT change, not a doc sweep: the stubs bake this path and
// a bottle built before it moves carries the old one. The decision to take
// it anyway is the user's, 2026-11-12 — published bottles are to be rebuilt
// if needed. The relocation stage (fixup/) is what makes that survivable:
// a bottle's rpaths are rewritten at install time, so the guest root is a
// build-time location rather than a promise to the artifact.
const guestZpkgDir = "/zpkg"

// defaultToolchain is the build environment of the sovereign builder when the
// caller names no file. Each entry earns its place — a toolchain nobody can
// explain is one nobody dares trim.
//
// It is a DEFAULT, not a mirror. The comment here used to claim it mirrored
// go-zpkg/packages\' builder/toolchain.txt, and the two had drifted apart in
// both directions: that file carries texinfo, freedesktop.org/pkg-config and
// gcc/libstdcxx, which are not here; this list carries flex, perl.org and
// gnu.org/pkg-config, which are not there. Both factory lanes pass
// `--toolchain builder/toolchain.txt`, so the drift cost nothing there and
// would have cost an evening to anyone running `bk builder` without the flag
// and reading the comment.
var defaultToolchain = []string{
	"llvm.org",                 // clang, lld, compiler-rt — the compiler itself
	"gnu.org/glibc",            // libc, crt objects and the dynamic loader
	"kernel.org/linux-headers", // glibc's headers include <linux/limits.h>
	"gnu.org/binutils",         // ar/ranlib: the llvm bottle ships llvm-ar, not `ar`
	"gnu.org/make",             // the build driver most recipes use
	"gnu.org/bash",             // `make` runs every recipe line through /bin/sh
	"gnu.org/coreutils",        // mkdir, install, ln… the vocabulary of a Makefile
	"gnu.org/sed",
	"gnu.org/grep",
	"gnu.org/gawk",      // config-header generation
	"gnu.org/m4",        // autoconf's macro processor
	"gnu.org/findutils", // find + xargs, used by recipes at install time
	"gnu.org/diffutils", // `cmp`, called by recipes' own test steps
	"gnu.org/patch",     // recipes that patch their own sources
	"gnu.org/autoconf",
	"gnu.org/automake",
	"gnu.org/libtool",
	"gnu.org/bison",
	"github.com/westes/flex",
	"gnu.org/pkg-config",
	"perl.org",         // openssl and friends drive their build with it
	"gnu.org/help2man", // generated man pages during `make install`
	"curl.se/ca-certs", // a scratch image has no trust store
	// tar and gzip are not conveniences on a FROM-scratch tree, which has only
	// what this list names. Two independent things need them: recipes that
	// fetch in their own script (`curl -L … | tar -xz` — gcloud, groonga and
	// mesa3d all died on `"tar": executable file not found in $PATH`), and
	// automake's own configure probe, which stops at
	//   checking how to create a ustar tar archive... none
	// and exits 77 before a compiler runs. GNU tar delegates `-z` to an
	// EXTERNAL gzip, so tar without gzip trades one missing executable for
	// another.
	"gnu.org/tar",
	"gnu.org/gzip",
}

// toolchainRoots reads the package list, or returns the built-in one. Lines are
// `project[constraint]`, `#` starts a comment, blanks are ignored — the same
// shape pkgm's -f file uses, so one list feeds both.
func toolchainRoots(path string) (map[string]string, error) {
	lines := defaultToolchain
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		lines = strings.Split(string(b), "\n")
	}
	roots := map[string]string{}
	for _, ln := range lines {
		if i := strings.IndexByte(ln, '#'); i >= 0 {
			ln = ln[:i]
		}
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		proj, constraint := splitToolchainSpec(ln)
		roots[proj] = constraint
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("toolchain list is empty")
	}
	return roots, nil
}

// splitToolchainSpec splits `project[@^~<>=constraint]` into its two halves,
// defaulting to "*". The delimiters match pkgx's own spec syntax.
func splitToolchainSpec(s string) (project, constraint string) {
	if i := strings.IndexAny(s, "@^~<>="); i > 0 {
		c := strings.TrimPrefix(s[i:], "@")
		if c == "" {
			c = "*"
		}
		return s[:i], c
	}
	return s, "*"
}

// stageOptions is the whole input of a staging run.
type stageOptions struct {
	Root      string
	OS, Arch  string
	Roots     map[string]string
	BkBin     string
	ZpkgxBin  string
	MicroVM   bool
	Container bool
	Overlay   string
	Dist      string
	Log       func(string)
}

// stageBuilder materialises the rootfs. Order matters: the closure has to be
// on disk before the loader can be found in it, and the loader has to be posed
// before a stub is worth writing.
func stageBuilder(o stageOptions) error {
	zpkgDir := filepath.Join(o.Root, "pkgx")
	o.Log(fmt.Sprintf("builder: resolving the toolchain closure for %s/%s", o.OS, o.Arch))
	closure, err := resolveClosureFor(o.Roots, o.OS, o.Arch)
	if err != nil {
		return fmt.Errorf("resolve closure: %w", err)
	}
	o.Log(fmt.Sprintf("builder: %d packages", len(closure)))
	if n := alreadyStaged(zpkgDir, closure); n > 0 {
		// bottle.InstallFor takes the EXISTENCE of <project>/v<ver> as "already
		// present" and returns without fetching:
		//
		//	if st, err := os.Stat(prefix); err == nil && st.IsDir() {
		//		return false, nil // already present
		//	}
		//
		// So a tree left half-written by a run that died mid-install is
		// indistinguishable from a complete one — and on a SELF-HOSTED runner,
		// which reuses $RUNNER_TEMP between jobs, that tree is inherited in
		// silence. Three successive s390x pilots reported "42 packages" and
		// installed nothing, staging a gnu.org/glibc whose lib/glibc-2.44 held
		// two files where a real one has two hundred.
		//
		// Said, not refused: re-staging into a complete tree is the ordinary
		// case and is why the skip exists. What was missing is that the log
		// claimed a number it had not fetched.
		o.Log(fmt.Sprintf("builder: %d of them are ALREADY in %s and will not be re-installed — "+
			"a tree left by an earlier run is reused as-is, however it ended", n, zpkgDir))
	}

	for _, r := range closure {
		fresh, err := installFor(r, zpkgDir, o.OS, o.Arch)
		if err != nil {
			return fmt.Errorf("install %s %s: %w", r.Project, r.Version.Raw, err)
		}
		if fresh {
			o.Log(fmt.Sprintf("  + %s %s", r.Project, r.Version.Raw))
		}
	}

	// The loader and /bin/sh have to answer at their canonical absolute paths:
	// every bottle ELF names PT_INTERP=/lib/ld-linux-*, and make runs each
	// recipe line through /bin/sh. Both symlinks must point at GUEST paths.
	loader := findLoaderFor(zpkgDir, o.Arch)
	if loader == "" {
		// TWO failures wear this one symptom, and they are nothing alike.
		//
		// On linux/s390x this said "is gnu.org/glibc in the toolchain?" with
		// gnu.org/glibc plainly in it and all 42 packages installed: the
		// loader table simply had no entry for the architecture, because
		// s390x's loader is ld64.so.1 and not ld-linux-s390x.so.1. The
		// message sent its reader to look at the toolchain file, which was
		// correct, and cost a detour.
		//
		// So name the architecture FIRST when it is the architecture, and
		// keep the toolchain question for the case it actually describes.
		if bottle.LoaderNameFor(o.Arch) == "" {
			return fmt.Errorf("no loader name is known for %s — bottle.LoaderNameFor has no entry, "+
				"and the name cannot be derived from the other architectures' "+
				"(s390x's is ld64.so.1, not ld-linux-s390x.so.1): read it off a published "+
				"bottle for %s and add it there", o.Arch, o.Arch)
		}
		return fmt.Errorf("no %s loader (%s) in the staged glibc — is gnu.org/glibc in the toolchain?%s",
			o.Arch, bottle.LoaderNameFor(o.Arch), glibcLayout(zpkgDir))
	}
	shell := bottle.FindClosureBin(closure, zpkgDir, "gnu.org/bash", "bash")
	if err := bottle.SetupScratchRootfsAt(o.Root,
		bottle.LoaderNameFor(o.Arch),
		guestPath(loader, zpkgDir),
		guestPath(shell, zpkgDir),
	); err != nil {
		return fmt.Errorf("pose loader + /bin/sh: %w", err)
	}

	// /usr, not /usr/local: bk builds under a sanitised PATH that lists
	// /usr/bin and /bin but not /usr/local/bin, so a stub outside it is a stub
	// the build cannot call.
	n, err := stubBinsStaged(closure, bottle.Stage{
		Dir:      zpkgDir,
		GuestDir: guestZpkgDir,
		Prefix:   filepath.Join(o.Root, "usr"),
		OS:       o.OS,
		Arch:     o.Arch,
	})
	if err != nil {
		return fmt.Errorf("stub binaries: %w", err)
	}
	o.Log(fmt.Sprintf("builder: %d stubs in /usr/bin", n))

	// A build writes: give it the directories every toolchain assumes exist.
	// 1777 on the temp dirs, as everywhere else — a build that drops privileges
	// still has to be able to write there.
	for _, d := range []string{"tmp", "var/tmp", "root", "usr/local/bin"} {
		if err := os.MkdirAll(filepath.Join(o.Root, d), 0o755); err != nil {
			return err
		}
	}
	for _, d := range []string{"tmp", "var/tmp"} {
		// 0o1777 is NOT the sticky bit in Go: os.FileMode keeps it in a HIGH bit
		// (os.ModeSticky), so the octal literal a chmod(1) user reaches for
		// silently sets 0777 and drops the sticky.
		if err := osChmod(filepath.Join(o.Root, d), 0o777|os.ModeSticky); err != nil {
			return err
		}
	}

	// ⛔ THE ROOTFS CARRIES THE NAMES THE PRODUCT HAS. These were staged as
	// `bk` and `pkgx` long after the binaries were renamed, so every build ran
	// inside an image whose tools introduced themselves by their retired
	// names — and a developer with upstream's `pkgx` on PATH could not tell
	// the two apart by looking at the tree.
	for _, b := range []struct{ src, name string }{{o.BkBin, "zpkb"}, {o.ZpkgxBin, "zpkgx"}} {
		if b.src == "" {
			continue
		}
		dst := filepath.Join(o.Root, "usr", "local", "bin", b.name)
		if err := copyExecutable(b.src, dst); err != nil {
			return fmt.Errorf("install %s: %w", b.name, err)
		}
		o.Log(fmt.Sprintf("builder: %s → /usr/local/bin/%s", b.src, b.name))
	}

	if o.MicroVM {
		if err := writeMicroVMConfig(o, closure, zpkgDir); err != nil {
			return fmt.Errorf("write .weft-microvm/config.json: %w", err)
		}
		o.Log("builder: .weft-microvm/config.json written — `weft microvm run` can boot this directory")
	}
	// Before the container file and after everything is on disk: the census
	// is about the tree as it will be ENTERED.
	o.Log(auditStagedSonames(zpkgDir))
	if o.Container {
		n, err := writeLdSoConf(o, zpkgDir)
		if err != nil {
			return fmt.Errorf("write /etc/ld.so.conf: %w", err)
		}
		o.Log(fmt.Sprintf("builder: /etc/ld.so.conf written — %d library director(ies)", n))
	}
	return nil
}

// writeLdSoConf lists every staged directory that holds a shared object, so a
// process started INSIDE the tree can find libc.
//
// The tree is not self-sufficient by its filesystem alone, and it took running
// it as a container to see why:
//
//   - Most bottles are MIRRORED: linked against a distro glibc, they carry
//     RUNPATH=$ORIGIN/../lib and find libc through the loader's search path.
//   - That path is compiled into the loader, and the mirrored glibc's is
//     /opt/gnu.org/glibc/<ver>+brewing/lib — upstream's build staging dir. Its
//     ldconfig has the same baked in, so `ldconfig -r <root>` cannot even build
//     a cache inside the tree.
//
// What remains is LD_LIBRARY_PATH, which bk's build wrapper exports and PID 1
// does not have. This file is the data an init needs to export it. Measured:
// without it, /bin/sh in an Incus container built from this tree dies with
// "libc.so.6: cannot open shared object file"; with it, clang compiles, links
// and runs.
//
// The directories are FOUND, not globbed: libc.so.6 lives in
// lib/glibc-2.44/, a versioned subdirectory a `*/v*/lib` pattern misses.
func writeLdSoConf(o stageOptions, zpkgDir string) (int, error) {
	seen := map[string]bool{}
	err := filepath.WalkDir(zpkgDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// A directory we cannot read means the list is INCOMPLETE, and an
			// incomplete ld.so.conf breaks the container silently: one library
			// missing and every binary that needs it dies with "cannot open
			// shared object file", pointing at nothing.
			return err
		}
		if d.IsDir() || !strings.Contains(d.Name(), ".so") {
			return nil
		}
		seen[guestPath(filepath.Dir(p), zpkgDir)] = true
		return nil
	})
	if err != nil {
		return 0, err
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	etc := filepath.Join(o.Root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return 0, err
	}
	body := strings.Join(dirs, "\n")
	if body != "" {
		body += "\n"
	}
	return len(dirs), os.WriteFile(filepath.Join(etc, "ld.so.conf"), []byte(body), 0o644)
}

// guestPath rewrites a staged path to the one it will have once the rootfs is
// the root. Returns "" unchanged, so a missing optional (no bash in the
// closure) stays missing rather than becoming "/pkgx".
func guestPath(p, zpkgDir string) string {
	if p == "" {
		return ""
	}
	rel, err := filepath.Rel(zpkgDir, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return p
	}
	return filepath.Join(guestZpkgDir, rel)
}

// copyExecutable copies src to dst with the executable bit set.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := ioCopy(f, in); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := closeWritten(f); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// microVMConfig is the process spec weft-microvm-init reads from
// <rootfs>/.weft-microvm/config.json — the same shape `weft microvm pull`
// derives from an OCI image config. Writing it here is what lets a staged
// directory be booted with no registry and no image at all: weft's Pull treats
// the file as its "already materialised" sentinel and skips straight to boot.
type microVMConfig struct {
	Process microVMProcess `json:"process"`
}

type microVMProcess struct {
	Args []string    `json:"args"`
	Env  []string    `json:"env"`
	Cwd  string      `json:"cwd"`
	User microVMUser `json:"user"`
}

type microVMUser struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

// writeMicroVMConfig records how to run bk inside the staged rootfs.
//
// LD_LIBRARY_PATH is spelled out rather than left to pkgx: in a container the
// image ENTRYPOINT ran bk THROUGH pkgx, which composed the environment at exec
// time, but a micro-VM's init execs the args verbatim. Without it the first
// thing that happens in the guest is /bin/sh failing to find libc.so.6 —
// measured, in exactly that way.
func writeMicroVMConfig(o stageOptions, closure []bottle.Resolved, zpkgDir string) error {
	libPath := strings.ReplaceAll(bottle.LibPath(closure, zpkgDir), zpkgDir, guestZpkgDir)
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LD_LIBRARY_PATH=" + libPath,
		"ZPKG_DIR=" + guestZpkgDir,
		"HOME=/root",
		"TMPDIR=/tmp",
	}
	if o.Dist != "" {
		env = append(env, "ZPKG_DIST="+o.Dist)
	}
	if o.Overlay != "" {
		env = append(env, "ZPKG_PANTRY_OVERLAY="+o.Overlay)
	}
	sort.Strings(env)

	cfg := microVMConfig{Process: microVMProcess{
		Args: []string{"/usr/local/bin/zpkb"},
		Env:  env,
		Cwd:  "/",
	}}
	b, err := jsonMarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(o.Root, ".weft-microvm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), append(b, '\n'), 0o644)
}

// Seams. Staging talks to a registry over the network; the tests drive these
// instead, so a builder test proves the ORCHESTRATION — closure before
// install, install before loader, loader before stubs — rather than re-proving
// bottle's transport.
var (
	resolveClosureFor = bottle.ResolveClosureFor
	installFor        = bottle.InstallFor
	findLoaderFor     = bottle.FindLoaderFor
	stubBinsStaged    = bottle.StubBinsStaged
)

// More seams, for the branches a filesystem will not produce on demand: a
// write that fails only on Close (a full disk, a network filesystem) and an
// encoder that cannot encode. Both messages are the only thing a user would
// ever see of these paths, so they are worth exercising.
var (
	ioCopy            = io.Copy
	closeWritten      = func(f *os.File) error { return f.Close() }
	jsonMarshalIndent = json.MarshalIndent
	osChmod           = os.Chmod
)
