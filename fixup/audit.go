package fixup

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// AuditRelocatable runs the Mach-O relocatability guards over an already-laid-out
// prefix WITHOUT modifying a byte, and reports what it found.
//
// `FixUp` runs these same checks while it rewrites a freshly built package, so
// nothing it produces can reach the registry unrunnable. A MIRRORED bottle is
// never unpacked — it is republished verbatim — so the guards have no bytes to
// look at and cannot fire. `git-scm.org 2.55.0` reached the catalogue that way:
// 164 of its 164 Mach-O files reach a sibling package only through
// `/Users/runner/.pkgx`, the build machine's own path, so `git` cannot load
// zlib on any other machine. It surfaced weeks later as some other recipe's
// build failure — `git-remote-https died of signal 6`.
//
// This reports and does not refuse. Whether a mirror is REQUIRED to be
// relocatable is a question about what our signature claims, and it is
// go-zpkg/packages#147's to answer; what a publisher should not have to do is
// find out from a third package's dyld error.
func AuditRelocatable(prefix, zpkgDir string) (checked int, problems []error) {
	opts := Options{ZpkgDir: zpkgDir}
	_ = walkExes(prefix, func(p string) error {
		if !isMachO(p) {
			return nil
		}
		checked++
		if err := checkRpathResolvable(p, opts); err != nil {
			problems = append(problems, err)
		}
		if err := checkNoDuplicateRpath(p); err != nil {
			problems = append(problems, err)
		}
		if err := checkMachoMagic(p); err != nil {
			problems = append(problems, err)
		}
		if err := checkMachoSignature(p); err != nil {
			problems = append(problems, err)
		}
		if err := checkAbsoluteRefs(p, nil); err != nil {
			problems = append(problems, err)
		}
		return nil
	})
	return checked, problems
}

// ErrMissingRef means a Mach-O names a file under $ZPKG_DIR that is not there.
//
// The reference records a decision taken when the binary was LINKED —
// @rpath/gnome.org/libxml2/v2/lib/libxml2.2.dylib — and the resolver takes the
// same decision again, separately, when a consumer installs. Nothing keeps the
// two in agreement, and they disagree on both axes:
//
//	libxml2 2.13.9 -> 2.15.4   same pkgx major, DIFFERENT soname (libxml2.2 -> libxml2.16)
//	gettext 0.26   -> 1.0.0    different major, SAME soname (libintl.8, compat 13)
//
// So a major-versioned reference can be satisfied and still not resolve, and an
// ABI-compatible upgrade can look like a break. Measured over 26519 Mach-O in
// 272 installed closures: 51 packages name a file that is not there.
//
// REPORTED, not refused. qt.io is among the 51 and runs: a dangling reference in
// a module nothing loads never faults. Refusing would stop a fifth of the
// catalogue from building over defects that are latent — the backlog has to
// drain first.
var ErrMissingRef = errors.New("fixup: @rpath reference names a file that is not there")

// checkRefExists reports an @rpath reference naming a path under $ZPKG_DIR that
// does not exist. During a build the closure installed is exactly what the
// recipe declared, so this is that build's own disagreement and not an
// inherited one.
func checkRefExists(exe string, opts Options) error {
	if opts.ZpkgDir == "" {
		return nil
	}
	refs, err := readMachoRefs(exe)
	if err != nil {
		return err
	}
	for _, r := range refs {
		rest, ok := strings.CutPrefix(r, "@rpath/")
		if !ok || !strings.Contains(rest, "/") {
			continue // a BARE soname is checkRpathResolvable's business
		}
		cand := filepath.Join(opts.ZpkgDir, filepath.FromSlash(rest))
		// The package's own files may still be under the staging prefix while
		// fixup runs, so try both — the same pair qualifyRef stats.
		if exists(cand) || exists(staged(cand, opts)) {
			continue
		}
		return fmt.Errorf("%w: %s references %s", ErrMissingRef, exe, r)
	}
	return nil
}

// ErrAbsoluteRef means a Mach-O asks dyld for a library by an absolute path
// that is not part of macOS — so it loads only on a machine that happens to
// have that exact path, which is the build machine and nobody else.
//
// Every guard beside this one reads `@rpath/…` strings and skips anything
// spelled differently, so a reference like
//
//	/opt/homebrew/opt/gettext/lib/libintl.8.dylib   (git-scm.org, 656 files)
//	/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib  (freetype.org)
//
// was invisible to all of them. Homebrew is not a dependency of anything here;
// it is what happened to be installed on the runner, found by a configure
// script that then recorded its path. The consequence is not only a dyld
// failure on the user's machine: freetype's generated `freetype2.pc` inherited
// `Requires.private: … libbrotlidec`, so `fontconfig`'s build now fails at
// `pkg-config` on a package nothing declares.
//
// The rule is stated as an ALLOWLIST on purpose. A denylist of known-bad
// prefixes inherits the blind spot of whoever wrote it — `/Users/runner` was
// listed and `/opt/homebrew` was not, which is why 711 references went out.
// What may legitimately be absolute is small, fixed and owned by Apple:
// `/usr/lib` and `/System`. Everything else absolute names a machine.
//
// Measured over the installed closures: 5642 such references in 63 projects —
// `/Users/runner` 4093, `/opt/qt.io` 834, `/opt/homebrew` 711, plus one
// `/Users/builder/actions-runner/_work/pantry/pantry/builds/…` inherited from
// an upstream mirror.
var ErrAbsoluteRef = errors.New("fixup: absolute reference to a path outside the system")

// systemLibDirs are the only absolute prefixes a relocatable Mach-O may name.
// They are part of macOS, present on every machine, and not ours to vendor.
var systemLibDirs = []string{"/usr/lib/", "/System/"}

// tolerate, when non-nil, is asked about each absolute reference before it is
// refused. The build path uses it for the ONE absolute form that is deliberate
// — a path into $ZPKG_DIR, left by rewriteMacho when no rpath reaches the store
// — and the mirror audit passes nil, because in a bottle we only copy there is
// no such decision to respect.
//
// It takes the REFERENCE, not the error text. Deciding on the message was the
// first thing tried and it was always true: the message names the file too, and
// the file is itself under $ZPKG_DIR.
func checkAbsoluteRefs(exe string, tolerate func(ref string) bool) error {
	refs, err := readMachoRefs(exe)
	if err != nil {
		return err
	}
	for _, r := range refs {
		if !strings.HasPrefix(r, "/") {
			continue
		}
		system := false
		for _, d := range systemLibDirs {
			if strings.HasPrefix(r, d) {
				system = true
				break
			}
		}
		if system || (tolerate != nil && tolerate(r)) {
			continue
		}
		return fmt.Errorf("%w: %s references %s", ErrAbsoluteRef, exe, r)
	}
	return nil
}

// ErrStaleSignature means a Mach-O carries a code signature that no longer
// describes its own bytes — the state an in-place edit leaves behind when
// nothing restates the hashes.
//
// On Apple silicon this is not a load error. The kernel checks each page
// against the code directory at first fault and kills the process outright:
//
//	$ gm version
//	$ echo $?
//	137                              ← SIGKILL, nothing on either stream
//
// There is no dyld message to grep for, which is why an audit that classified
// on the output text recorded 34 dead packages as healthy. The crash report is
// the only thing that says so: termination namespace CODESIGNING, "Invalid
// Page".
//
// `codesign -v` on the EXECUTABLE is no help either — it is usually not the
// file that was edited. `graphicsmagick.org` 1.3.48 is Developer ID signed and
// verifies clean while dying on `gnu.org/libtool`'s `libltdl.7.dylib`.
//
// 2123 files across 56 published project@versions reached the catalogue this
// way before `fixup` learned to re-sign (#96), and every guard here missed
// them: they all read Mach-O *references* and none asked whether the bytes
// still hash to what the signature claims. `MachoSignatureStale` could answer
// it from #101 onwards and nothing ever called it. A guard that is written,
// tested and unwired guards nothing.
var ErrStaleSignature = errors.New("fixup: code signature no longer describes the file")

// checkMachoSignature reports a Mach-O whose signature has gone stale, naming
// it — the operator's next move is to rebuild that package, and "something in
// this prefix" does not say which.
func checkMachoSignature(exe string) error {
	stale, err := MachoSignatureStale(exe)
	if err != nil {
		return err
	}
	if stale {
		return fmt.Errorf("%w: %s", ErrStaleSignature, exe)
	}
	return nil
}

// ErrMachoMagicMismatch means a Mach-O header's word size contradicts its own
// cputype: a 32-bit magic (0xfeedface) over a cputype carrying CPU_ARCH_ABI64,
// or the reverse. No linker produces that. GNU strip does, on a file it was
// never meant to touch:
//
//	cffa edfe 0c00 0001   before: magic 0xfeedfacf, cputype ARM64
//	cefa edfe 0c00 0001   after:  magic 0xfeedface, cputype ARM64
//
// and it exits 0. `pkgx +<deps>` can put gnu.org/binutils ahead of /usr/bin on
// darwin — gnu.org/gcc pulls it in at runtime — so a recipe's bare `strip` is
// GNU's, and github.com/rcedgar/muscle 5.3 was built, signed, indexed and
// published as a binary the kernel kills on sight (exit 137, no output).
//
// It was found by the LC_RPATH guard rather than by anything looking at the
// header, and only because strip had taken the load commands with it. That is
// a side effect: the malformation is four bytes wide and worth naming on its
// own, because debug/macho parses such a file happily AS 32-bit and everything
// downstream then reads the wrong offsets.
var ErrMachoMagicMismatch = errors.New("fixup: Mach-O magic contradicts its cputype")

// cpuArchABI64 is the bit a cputype sets to mean "64-bit variant".
const cpuArchABI64 = 0x01000000

// checkMachoMagic reports a slice whose header word size and cputype disagree.
// machoInfo has already established that the file parses; thinSlice records the
// header size, which is 32 for a 64-bit magic and 28 for a 32-bit one.
func checkMachoMagic(exe string) error {
	raw, slices, err := machoInfo(exe)
	if err != nil {
		return err
	}
	for _, sl := range slices {
		// thinSlice has already refused an out-of-bounds offset, so the header
		// bytes are there to read: no short-buffer case to guard, and a branch
		// no test can reach is a line the coverage gate is right to refuse.
		cpu := sl.bo.Uint32(raw[sl.off+4:])
		bits := 32
		if sl.hdr == 32 {
			bits = 64
		}
		if (bits == 64) != (cpu&cpuArchABI64 != 0) {
			return fmt.Errorf("%w: %s: %d-bit header, cputype %#08x", ErrMachoMagicMismatch, exe, bits, cpu)
		}
	}
	return nil
}

// ErrDuplicateRpath means a Mach-O carries the same LC_RPATH twice. ld refuses
// to link against such a library, so it breaks every dependent rather than the
// bottle itself — which is why nothing noticed until a dependent's build failed:
//
//	ld: duplicate LC_RPATH '@loader_path/../../../..' in
//	    .../facebook.com/folly/v2026.09.14.00/lib/libfolly.0.58.0-dev.dylib
//	c++: error: linker command failed with exit code 1
//
// It was this factory that wrote the second one: relativising an absolute rpath
// can produce a string bk had already linked in. That is fixed where it is
// made, but a defect invisible to every check we had is exactly what a guard is
// for — the bottle carrying it was built, signed, published and inspected
// without complaint.
var ErrDuplicateRpath = errors.New("fixup: duplicate LC_RPATH")

// ErrBuilderRpath means a shipped Mach-O still carries an absolute LC_RPATH
// into the builder's store. Linux is clean because fixup rewrites RUNPATH; this
// is the same promise for Mach-O, checked on the FINAL rpath set rather than
// assumed from what the rewrite meant to do (go-zpkg/bk#395).
var ErrBuilderRpath = errors.New("fixup: absolute LC_RPATH into the builder's store")

// checkNoBuilderRpath refuses a Mach-O whose rpaths still name store (derived
// from the build's $ZPKG_DIR, never a literal). Same caller contract as
// checkNoDuplicateRpath: exe has already parsed.
func checkNoBuilderRpath(exe, store string) error {
	rpaths, _ := machoRpaths(exe)
	for _, r := range rpaths {
		if builderRpath(r, store) {
			return fmt.Errorf("%w: %s carries %q, a path on the machine that built it", ErrBuilderRpath, exe, r)
		}
	}
	return nil
}

// checkNoDuplicateRpath reports a Mach-O that names one rpath more than once.
// The caller has already established that exe parses: isMachO IS "machoInfo
// succeeds", and machoRpaths fails nowhere else — so the read cannot fail here,
// and a branch no test can reach is a line the coverage gate is right to refuse.
func checkNoDuplicateRpath(exe string) error {
	rpaths, _ := machoRpaths(exe)
	seen := map[string]bool{}
	for _, r := range rpaths {
		if seen[r] {
			return fmt.Errorf("%w: %s names %q more than once; ld refuses to link against it", ErrDuplicateRpath, exe, r)
		}
		seen[r] = true
	}
	return nil
}
