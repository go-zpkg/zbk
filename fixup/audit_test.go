package fixup

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditRelocatableFindsTheBuilderOnlyRpath: a mirrored bottle is never
// unpacked, so FixUp's guards never see it. The audit is the same guards run
// read-only over a laid-out prefix, which is what a mirror can afford.
//
// The shape is git-scm.org 2.55.0's: a correctly QUALIFIED @rpath reference to
// a sibling package, and one rpath — the build machine's own absolute path.
func TestAuditRelocatableFindsTheBuilderOnlyRpath(t *testing.T) {
	zpkgDir := t.TempDir()
	prefix := filepath.Join(zpkgDir, "git-scm.org", "v2.55.0")
	ref := machoCmd{lcLoadDylib, "@rpath/zlib.net/v1.3.2/lib/libz.1.dylib"}

	// libexec/git: reaches the sibling only through the builder's path.
	// walkExes looks in bin, lib and libexec — an audit that read only bin/
	// would have missed git-scm.org, whose broken files are under libexec/.
	bad := filepath.Join(prefix, "libexec", "git")
	place(t, bad, ref, machoCmd{lcRpath, "/Users/runner/.pkgx"})
	// lib/libok.dylib: a relative rpath that reaches $ZPKG_DIR from lib/.
	place(t, filepath.Join(prefix, "lib", "libok.dylib"), ref, machoCmd{lcRpath, "@loader_path/../../.."})

	checked, problems := AuditRelocatable(prefix, zpkgDir)
	if checked != 2 {
		t.Fatalf("checked %d Mach-O, want 2", checked)
	}
	if len(problems) != 1 {
		t.Fatalf("reported %d problem(s), want 1: %v", len(problems), problems)
	}
	if !errors.Is(problems[0], ErrBuilderOnlyRpath) {
		t.Errorf("problem is %v, want ErrBuilderOnlyRpath", problems[0])
	}
	if !strings.Contains(problems[0].Error(), bad) {
		t.Errorf("problem does not name %s: %v", bad, problems[0])
	}
}

// TestAuditRelocatableIsQuietOnAHealthyPrefix: the negative control. Without
// it the audit could report every bottle and still look like it works.
func TestAuditRelocatableIsQuietOnAHealthyPrefix(t *testing.T) {
	zpkgDir := t.TempDir()
	prefix := filepath.Join(zpkgDir, "lloyd.github.io", "yajl", "v2.1.0")
	place(t, filepath.Join(prefix, "lib", "libyajl.2.dylib"),
		machoCmd{lcLoadDylib, "@rpath/zlib.net/v1.3.2/lib/libz.1.dylib"},
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcRpath, "/Users/runner/.pkgx"})

	checked, problems := AuditRelocatable(prefix, zpkgDir)
	if checked != 1 {
		t.Fatalf("checked %d Mach-O, want 1", checked)
	}
	if len(problems) != 0 {
		t.Errorf("reported %v on a prefix whose relative rpath reaches $ZPKG_DIR", problems)
	}
}

// TestAuditRelocatableReadsNothingItCannotParse: a prefix with no Mach-O at all
// is not an error — a mirrored bottle can be pure scripts or data.
func TestAuditRelocatableSkipsNonMachO(t *testing.T) {
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "bin", "git"), []byte("#!/bin/sh\nexec true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	checked, problems := AuditRelocatable(prefix, prefix)
	if checked != 0 || len(problems) != 0 {
		t.Errorf("checked=%d problems=%v, want 0 and none", checked, problems)
	}
}

// The audit refuses a Mach-O that names one rpath twice. ld will not link
// against such a library, so the damage lands on every dependent rather than on
// the bottle carrying it — which is why a duplicate survived a build, a
// signature, a publish and an inspection without anything complaining, until
// github.com/facebookincubator/fizz failed to link against folly.
func TestAuditRefusesADuplicateRpath(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.0.0")
	exe := filepath.Join(prefix, "lib", "libfoo.dylib")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcLoadDylib, "@rpath/other.org/bar/v1/lib/libbar.dylib"},
	)
	checked, problems := AuditRelocatable(prefix, pkgx)
	if checked != 1 {
		t.Fatalf("checked %d files, want 1", checked)
	}
	var found error
	for _, p := range problems {
		if errors.Is(p, ErrDuplicateRpath) {
			found = p
		}
	}
	if found == nil {
		t.Fatalf("no duplicate reported; problems = %v", problems)
	}
	// The message has to name the file AND the repeated entry, or the reader
	// has to go looking for which of them it is.
	if !strings.Contains(found.Error(), "libfoo.dylib") ||
		!strings.Contains(found.Error(), "@loader_path/../../../..") {
		t.Errorf("message hides half the problem: %v", found)
	}
}

// One rpath named once is not a duplicate, however many other rpaths there are.
func TestAuditAcceptsDistinctRpaths(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.0.0")
	exe := filepath.Join(prefix, "lib", "libfoo.dylib")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcRpath, "@loader_path/../../../../.."},
		machoCmd{lcLoadDylib, "@rpath/other.org/bar/v1/lib/libbar.dylib"},
	)
	_, problems := AuditRelocatable(prefix, pkgx)
	for _, p := range problems {
		if errors.Is(p, ErrDuplicateRpath) {
			t.Errorf("distinct rpaths reported as duplicate: %v", p)
		}
	}
}

// A 32-bit magic over a 64-bit cputype is what GNU strip leaves behind, and no
// linker produces it. github.com/rcedgar/muscle 5.3 shipped that way for
// darwin/aarch64 and the kernel kills it on sight — exit 137, no output.
//
// The existing guards caught that file only sideways, through the LC_RPATH it
// no longer had, because strip took the load commands too. The malformation
// itself is four bytes wide and needs naming: debug/macho parses such a file
// happily AS 32-bit, so every offset read afterwards is wrong.
func TestAuditRelocatableFindsAMagicThatContradictsTheCPU(t *testing.T) {
	p := buildThin32WithA64BitCPU(t)
	if err := checkMachoMagic(p); !errors.Is(err, ErrMachoMagicMismatch) {
		t.Fatalf("err = %v, want ErrMachoMagicMismatch", err)
	}
	// and the audit reports it over a laid-out prefix, which is the only way a
	// MIRRORED bottle is ever looked at — walkExes visits bin/, lib/ and
	// libexec/, so the file has to be in one of them
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "lib", "libbad.dylib"), raw, 0o755); err != nil {
		t.Fatal(err)
	}
	_, problems := AuditRelocatable(prefix, t.TempDir())
	found := false
	for _, e := range problems {
		if errors.Is(e, ErrMachoMagicMismatch) {
			found = true
		}
	}
	if !found {
		t.Errorf("AuditRelocatable problems = %v, want the magic mismatch among them", problems)
	}
}

// buildThin32WithA64BitCPU writes a file that is structurally a 32-bit Mach-O —
// 28-byte header, one LC_RPATH — whose cputype carries CPU_ARCH_ABI64.
//
// Flipping the magic byte of a 64-bit fixture is NOT the same thing and does
// not reproduce it: the load commands then start four bytes past where a
// 32-bit reader looks, and the parse fails before the header can be judged.
// The published muscle binary parses cleanly as 32-bit, which is exactly why
// nothing downstream noticed.
func buildThin32WithA64BitCPU(t *testing.T) string {
	t.Helper()
	le := binary.LittleEndian
	const path = "@loader_path/../lib"
	cmdSize := 12 + len(path) + 1
	for cmdSize%4 != 0 {
		cmdSize++
	}
	cmd := make([]byte, cmdSize)
	le.PutUint32(cmd[0:], lcRpath)
	le.PutUint32(cmd[4:], uint32(cmdSize))
	le.PutUint32(cmd[8:], 12)
	copy(cmd[12:], path)

	buf := make([]byte, 28+len(cmd))
	le.PutUint32(buf[0:], 0xfeedface) // MH_MAGIC — 32-bit
	le.PutUint32(buf[4:], 0x0100000c) // CPU_TYPE_ARM64 — 64-bit
	le.PutUint32(buf[12:], 6)         // MH_DYLIB
	le.PutUint32(buf[16:], 1)         // ncmds
	le.PutUint32(buf[20:], uint32(len(cmd)))
	copy(buf[28:], cmd)

	q := filepath.Join(t.TempDir(), "thin32-over-64.dylib")
	if err := os.WriteFile(q, buf, 0o755); err != nil {
		t.Fatal(err)
	}
	return q
}

// And it must stay quiet on a healthy file, including a genuine 32-bit one:
// the check is about DISAGREEMENT between the header and the cputype, not
// about the word size.
func TestCheckMachoMagicAcceptsAgreementBothWays(t *testing.T) {
	p := buildMachO(t, machoCmd{lcRpath, "@loader_path/../lib"})
	if err := checkMachoMagic(p); err != nil {
		t.Errorf("64-bit magic + 64-bit cputype: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 0xce // 32-bit magic
	raw[7] = 0x00 // cputype 0x0000000c — CPU_TYPE_ARM, the 32-bit one
	q := filepath.Join(t.TempDir(), "thin32.dylib")
	if err := os.WriteFile(q, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkMachoMagic(q); err != nil && errors.Is(err, ErrMachoMagicMismatch) {
		t.Errorf("32-bit magic + 32-bit cputype must be accepted: %v", err)
	}
}

// A file that is not a Mach-O at all is the reader's problem, not this check's:
// the error is returned rather than mistaken for a malformation.
func TestCheckMachoMagicOnSomethingElse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-macho")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkMachoMagic(p); err == nil || errors.Is(err, ErrMachoMagicMismatch) {
		t.Errorf("err = %v, want a parse error and not a magic mismatch", err)
	}
}

// placeSigned writes a signed image at path, so an audit test can put one
// inside a prefix rather than in a bare temp dir.
func placeSigned(t *testing.T, path string, img signedImage) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, img.raw, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestAuditRelocatableFindsTheStaleSignature: the check that existed, was
// tested, and was wired to nothing.
//
// Every other guard here reads a Mach-O *reference*. None of them asks whether
// the bytes still hash to what the signature claims, so 2123 files across 56
// published project@versions went out in a state where Apple silicon SIGKILLs
// them at the first page fault — with no dyld error and no output at all.
func TestAuditRelocatableFindsTheStaleSignature(t *testing.T) {
	zpkgDir := t.TempDir()
	prefix := filepath.Join(zpkgDir, "gnu.org", "libtool", "v2.6.2")

	bad := filepath.Join(prefix, "lib", "libltdl.7.dylib")
	placeSigned(t, bad, buildSignedMachO(t, "@loader_path/../../../..", sigOpts{badHashes: true}))
	placeSigned(t, filepath.Join(prefix, "lib", "libok.dylib"),
		buildSignedMachO(t, "@loader_path/../../../..", sigOpts{}))

	checked, problems := AuditRelocatable(prefix, zpkgDir)
	if checked != 2 {
		t.Fatalf("checked %d Mach-O, want 2", checked)
	}
	if len(problems) != 1 {
		t.Fatalf("reported %d problem(s), want 1: %v", len(problems), problems)
	}
	if !errors.Is(problems[0], ErrStaleSignature) {
		t.Errorf("problem is %v, want ErrStaleSignature", problems[0])
	}
	// Naming the file is the point: the operator's next move is to rebuild
	// THAT package, and a prefix-wide complaint does not say which.
	if !strings.Contains(problems[0].Error(), bad) {
		t.Errorf("problem does not name %s: %v", bad, problems[0])
	}
}

// TestAuditRelocatableSurfacesAnUnreadableSignature: a signature bk cannot
// compute is reported, not silently passed. Reading "no verdict" as "sound" is
// how an unrunnable bottle gets published.
func TestAuditRelocatableSurfacesAnUnreadableSignature(t *testing.T) {
	zpkgDir := t.TempDir()
	prefix := filepath.Join(zpkgDir, "x", "v1")

	img := buildSignedMachO(t, "@loader_path/../../..", sigOpts{})
	img.raw[img.cdOff+37] = 99 // a hash algorithm we cannot compute
	placeSigned(t, filepath.Join(prefix, "lib", "libx.dylib"), img)

	_, problems := AuditRelocatable(prefix, zpkgDir)
	if len(problems) != 1 {
		t.Fatalf("reported %d problem(s), want 1: %v", len(problems), problems)
	}
	if errors.Is(problems[0], ErrStaleSignature) {
		t.Errorf("called an unreadable signature stale: %v", problems[0])
	}
}

// TestAuditRelocatableFindsTheHomebrewReference: the class every other guard
// skips, because they all start by matching "@rpath/" and this does not.
//
// `git-scm.org` ships 656 files asking for
// `/opt/homebrew/opt/gettext/lib/libintl.8.dylib` — a path that exists on the
// runner that built it and on no user's machine.
func TestAuditRelocatableFindsTheHomebrewReference(t *testing.T) {
	zpkgDir := t.TempDir()
	prefix := filepath.Join(zpkgDir, "git-scm.org", "v2.55.0")

	bad := filepath.Join(prefix, "libexec", "git-receive-pack")
	place(t, bad,
		machoCmd{lcLoadDylib, "/opt/homebrew/opt/gettext/lib/libintl.8.dylib"},
		machoCmd{lcRpath, "@loader_path/../../.."})

	_, problems := AuditRelocatable(prefix, zpkgDir)
	if len(problems) != 1 {
		t.Fatalf("reported %d problem(s), want 1: %v", len(problems), problems)
	}
	if !errors.Is(problems[0], ErrAbsoluteRef) {
		t.Errorf("problem is %v, want ErrAbsoluteRef", problems[0])
	}
	if !strings.Contains(problems[0].Error(), "/opt/homebrew/opt/gettext/lib/libintl.8.dylib") {
		t.Errorf("problem does not name the path: %v", problems[0])
	}
}

// TestAuditRelocatableAllowsTheSystemLibraries: the negative control that
// stops the rule from condemning every binary on the machine. Linking
// libSystem and a system framework by absolute path is how macOS works.
func TestAuditRelocatableAllowsTheSystemLibraries(t *testing.T) {
	zpkgDir := t.TempDir()
	prefix := filepath.Join(zpkgDir, "lloyd.github.io", "yajl", "v2.1.0")
	place(t, filepath.Join(prefix, "lib", "libyajl.2.dylib"),
		machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
		machoCmd{lcLoadDylib, "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"},
		machoCmd{lcRpath, "@loader_path/../../../.."})

	_, problems := AuditRelocatable(prefix, zpkgDir)
	if len(problems) != 0 {
		t.Errorf("reported %v for the system libraries every Mach-O links", problems)
	}
}

// TestAuditRelocatableIgnoresItsOwnInstallName: LC_ID_DYLIB is not a
// reference. A package installed under an absolute prefix names itself that
// way and asks dyld for nothing.
func TestAuditRelocatableIgnoresItsOwnInstallName(t *testing.T) {
	zpkgDir := t.TempDir()
	prefix := filepath.Join(zpkgDir, "x", "v1")
	place(t, filepath.Join(prefix, "lib", "libx.dylib"),
		machoCmd{lcIDDylib, "/opt/x/v1/lib/libx.dylib"},
		machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})

	_, problems := AuditRelocatable(prefix, zpkgDir)
	if len(problems) != 0 {
		t.Errorf("condemned a package for what it calls itself: %v", problems)
	}
}

// TestCheckAbsoluteRefsReportsAnUnreadableFile: reached directly, because
// AuditRelocatable gates on isMachO and so cannot hand this one a file it
// cannot parse. The branch still has to return the error rather than call the
// file clean — "could not read" is not "has no absolute references".
func TestCheckAbsoluteRefsReportsAnUnreadableFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkAbsoluteRefs(p, nil); err == nil {
		t.Error("want an error for a file that is not a Mach-O")
	}
}

// TestFixUpGuardsWhatWeBuild: the guards existed and ran on the bottles we
// COPY, not the ones we MAKE.
//
// AuditRelocatable has exactly one caller — the factory's mirror path, whose
// comment reads "a mirror is never unpacked, so fixup's relocatability guards
// never run on it". True, and it left the inverse unsaid: the build path ran
// only checkRpathResolvable, so a stale signature, a bad magic, a duplicate
// LC_RPATH and an /opt/homebrew reference all went unchecked on everything the
// factory produced.
func TestFixUpGuardsWhatWeBuild(t *testing.T) {
	t.Run("a stale signature is refused", func(t *testing.T) {
		pkgx := t.TempDir()
		prefix := filepath.Join(pkgx, "acme.org", "v1.0.0")
		placeSigned(t, filepath.Join(prefix, "lib", "libacme.dylib"),
			buildSignedMachO(t, "@loader_path/../../..", sigOpts{badHashes: true}))
		err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx})
		if !errors.Is(err, ErrStaleSignature) {
			t.Errorf("FixUp = %v, want ErrStaleSignature", err)
		}
	})
	t.Run("a reference to another machine is refused", func(t *testing.T) {
		pkgx := t.TempDir()
		prefix := filepath.Join(pkgx, "acme.org", "v1.0.0")
		place(t, filepath.Join(prefix, "bin", "acme"),
			machoCmd{lcLoadDylib, "/opt/homebrew/opt/gettext/lib/libintl.8.dylib"},
			machoCmd{lcRpath, "@loader_path/../../.."})
		err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx})
		if !errors.Is(err, ErrAbsoluteRef) {
			t.Errorf("FixUp = %v, want ErrAbsoluteRef", err)
		}
	})
	t.Run("an absolute path INTO the store is the deliberate fallback", func(t *testing.T) {
		// rewriteMacho leaves a name absolute when no rpath reaches the store,
		// because "@rpath would resolve to nothing, which is worse than a path
		// that at least works on one machine". Refusing it would fail a build
		// that today produces something usable.
		pkgx := t.TempDir()
		prefix := filepath.Join(pkgx, "other.org", "v2.0.0")
		dep := filepath.Join(pkgx, "acme.org", "v1.2.3", "lib", "libfoo.dylib")
		place(t, filepath.Join(prefix, "bin", "bar"),
			machoCmd{lcRpath, "@loader_path/.."}, // stops short of the store
			machoCmd{lcLoadDylib, dep})
		var logged []string
		if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx,
			Log: func(s string) { logged = append(logged, s) }}); err != nil {
			t.Fatalf("FixUp refused the fallback: %v", err)
		}
		if !strings.Contains(strings.Join(logged, "\n"), "absolute reference") {
			t.Errorf("the fallback was not reported: %v", logged)
		}
	})
	t.Run("a dangling @rpath target is reported, not refused", func(t *testing.T) {
		// 51 of 272 installed closures carry one, and qt.io is among them and
		// runs: a dangling reference in a module nothing loads never faults.
		pkgx := t.TempDir()
		prefix := filepath.Join(pkgx, "acme.org", "v1.0.0")
		place(t, filepath.Join(prefix, "bin", "acme"),
			machoCmd{lcLoadDylib, "@rpath/gnome.org/libxml2/v2/lib/libxml2.2.dylib"},
			machoCmd{lcRpath, "@loader_path/../../.."})
		var logged []string
		if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx,
			Log: func(s string) { logged = append(logged, s) }}); err != nil {
			t.Fatalf("FixUp = %v, want it reported and tolerated", err)
		}
		if !strings.Contains(strings.Join(logged, "\n"), "libxml2.2.dylib") {
			t.Errorf("the missing target was not reported: %v", logged)
		}
	})
}

// TestCheckRefExistsReportsAnUnreadableFile: reached directly, because
// auditBuilt gates on isMachO and so never hands this one a file it cannot
// parse. "Could not read" is not "has no missing references".
func TestCheckRefExistsReportsAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "script")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkRefExists(p, Options{ZpkgDir: dir}); err == nil {
		t.Error("want an error for a file that is not a Mach-O")
	}
}

// TestCheckRefExistsAcceptsAReferenceThatResolves covers the loop's `continue`
// for a reference whose target IS in the store.
//
// It was reached only through a darwin-gated path, so on the linux runner that
// judges coverage the line was never executed -- and the gate did not say so,
// because the TOTAL still rounded to 100.0%. Reaching checkRefExists directly
// makes the case host-independent, which is what a line that has nothing to do
// with the host deserves.
func TestCheckRefExistsAcceptsAReferenceThatResolves(t *testing.T) {
	pkgx := t.TempDir()
	dep := "acme.org/v1.2.3/lib/libfoo.dylib"
	write(t, filepath.Join(pkgx, filepath.FromSlash(dep)), "x")
	p := filepath.Join(pkgx, "other.org", "v2.0.0", "bin", "bar")
	place(t, p, machoCmd{lcLoadDylib, "@rpath/" + dep})
	if err := checkRefExists(p, Options{ZpkgDir: pkgx}); err != nil {
		t.Errorf("checkRefExists = %v, want nil for a reference the store answers", err)
	}
}

// And the staging half of the same condition: during a build the package's own
// files are still under <prefix>+brewing, so a reference into its own tree
// resolves only through staged().
func TestCheckRefExistsAcceptsAReferenceUnderTheStagingPrefix(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "acme.org", "v1.0.0")
	dep := "acme.org/v1.0.0/lib/libself.dylib"
	write(t, staged(filepath.Join(pkgx, filepath.FromSlash(dep)), Options{Prefix: prefix, ZpkgDir: pkgx}), "x")
	p := filepath.Join(prefix, "bin", "acme")
	place(t, p, machoCmd{lcLoadDylib, "@rpath/" + dep})
	if err := checkRefExists(p, Options{ZpkgDir: pkgx, Prefix: prefix}); err != nil {
		t.Errorf("checkRefExists = %v, want nil while the file is still staged", err)
	}
}
