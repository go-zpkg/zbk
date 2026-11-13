package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shimDir stages a fake shim directory and a PATH holding dir plus the given
// executables, returning the path the shim would be invoked as.
func shimDir(t *testing.T, shim string, onPath ...string) (self string) {
	t.Helper()
	libexec := t.TempDir()
	bin := t.TempDir()
	self = filepath.Join(libexec, shim)
	if err := os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range onPath {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", libexec+string(os.PathListSeparator)+bin)
	return self
}

// ⛔⛔ A SHIM DRIVES THE NAME IT WAS INVOKED AS.
//
// bk sets no $ZPKB_CC for a windows cross build — the compiler comes from the
// recipe's llvm-mingw dep — and compilerShimsFor shims the triple-prefixed
// spellings, which go FIRST on PATH. shimBase reduced
// `x86_64-w64-mingw32-gcc` to `gcc`, so the shim shadowed llvm-mingw's real
// compiler and then delegated to a name that bottle does not ship:
//
//	bk gcc: gcc is not on PATH outside …/build.libexec
//
// Measured on go-zpkg/packages' windows-c lane building zlib.net 1.3.2.
func TestAWindowsCrossShimDrivesTheTriplePrefixedCompiler(t *testing.T) {
	t.Setenv("ZPKB_CC", "")
	const shim = "x86_64-w64-mingw32-gcc"
	self := shimDir(t, shim, shim) // llvm-mingw ships exactly this name
	if got := fallbackDriver(shim, self); got != shim {
		t.Errorf("fallbackDriver(%q) = %q, want the name it was invoked as", shim, got)
	}
}

// ⛔ AND STRIPPING THE TRIPLE IS STILL RIGHT WHEN NOTHING SHIPS THAT NAME.
//
// The control, without which the fix could be "always use the exact name",
// which would break the case compilerShimsFor was written for: autoconf probes
// `x86_64-pc-linux-gnu-gcc`, nothing installs it, and reducing to `gcc` is
// what makes libisl's configure find a compiler at all.
func TestATripleNobodyShipsStillFallsBackToTheBareCompiler(t *testing.T) {
	t.Setenv("ZPKB_CC", "")
	const shim = "x86_64-pc-linux-gnu-gcc"
	self := shimDir(t, shim, "gcc") // only the bare compiler exists
	if got := fallbackDriver(shim, self); got != "gcc" {
		t.Errorf("fallbackDriver(%q) = %q, want the bare gcc", shim, got)
	}
}

// An unprefixed shim is unaffected either way: it already named its own
// compiler, and both candidates are the same string.
func TestABareShimIsUnchanged(t *testing.T) {
	t.Setenv("ZPKB_CC", "")
	self := shimDir(t, "cc", "cc")
	if got := fallbackDriver("cc", self); got != "cc" {
		t.Errorf("fallbackDriver(cc) = %q", got)
	}
}

// When NEITHER name is installed the fallback still names the base, so the
// error the caller prints is about a real lookup rather than a half-choice.
func TestNeitherNameInstalledFallsBackToTheBase(t *testing.T) {
	t.Setenv("ZPKB_CC", "")
	const shim = "x86_64-w64-mingw32-gcc"
	self := shimDir(t, shim) // nothing but the shim itself
	if got := fallbackDriver(shim, self); got != "gcc" {
		t.Errorf("fallbackDriver(%q) = %q, want %q", shim, got, "gcc")
	}
}

// ⛔ AND THE MESSAGE NAMES BOTH CANDIDATES, because with a prefixed shim the
// two are different and reporting only one hides half the lookup.
//
// The old wording blamed $ZPKB_CC for a build where $ZPKB_CC was UNSET, which is
// what sent a Windows cross build looking at the wrong thing. A prefixed name
// with nothing installed is the case that wording was rewritten for, so it is
// the case asserted: TestCCShimFailures drives the BARE `cc`, where both
// candidates are one string and this branch never runs.
func TestTheNoStencilFailureNamesBothCandidates(t *testing.T) {
	t.Setenv("ZPKB_CC", "")
	const shim = "x86_64-w64-mingw32-gcc"
	self := shimDir(t, shim) // neither the triple nor the bare gcc exists
	old := os.Args
	os.Args = []string{self}
	defer func() { os.Args = old }()

	var errb bytes.Buffer
	if code := ccShim(shim, nil, &errb); code != 127 {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}
	for _, want := range []string{"neither " + shim, "nor gcc", "$ZPKB_CC is unset"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr = %q, want it to contain %q", errb.String(), want)
		}
	}
	// And it must NOT say what the old message said, which is the defect.
	if strings.Contains(errb.String(), "names a compiler that is not installed") {
		t.Error("the message still blames $ZPKB_CC, which is unset here")
	}
}
