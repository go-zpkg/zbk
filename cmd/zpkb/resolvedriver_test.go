package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// THE INVARIANT THAT MAKES SHIMMING `clang` SAFE.
//
// $ZPKB_CC's driver is `clang` and the shim directory is FIRST on PATH, so a
// shim named clang that looked its driver up normally would find itself and
// re-exec forever. This is the test that says it does not.
func TestAShimDoesNotResolveToItself(t *testing.T) {
	shimDir := t.TempDir()
	realDir := t.TempDir()
	for _, d := range []string{shimDir, realDir} {
		if err := os.WriteFile(filepath.Join(d, "clang"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)

	got, err := resolveDriver("clang", filepath.Join(shimDir, "clang"))
	if err != nil {
		t.Fatal(err)
	}
	if got == filepath.Join(shimDir, "clang") {
		t.Fatal("the shim resolved to ITSELF — this is the infinite exec")
	}
	if got != filepath.Join(realDir, "clang") {
		t.Errorf("resolved to %q, want the one outside the shim dir", got)
	}

	// And with the shim dir LAST, the answer is the same: the rule is "not
	// my directory", not "not the first one".
	t.Setenv("PATH", realDir+string(os.PathListSeparator)+shimDir)
	if got, _ := resolveDriver("clang", filepath.Join(shimDir, "clang")); got != filepath.Join(realDir, "clang") {
		t.Errorf("with the shim dir last, resolved to %q", got)
	}
}

// THE WIRING, not just the function. The first version of this file tested
// resolveDriver directly, and replacing the caller's `os.Args[0]` with a
// path in no directory at all — which switches the guard off completely —
// did not fail a single test. A guard whose ARGUMENT is untested is a guard
// nobody is holding.
func TestTheShimPassesItsOwnPathToTheResolver(t *testing.T) {
	shimDir := t.TempDir()
	realDir := t.TempDir()
	for _, d := range []string{shimDir, realDir} {
		if err := os.WriteFile(filepath.Join(d, "clang"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)
	t.Setenv("ZPKB_CC", "clang --sysroot=/somewhere")

	// argv[0] as the kernel gives it to a shim: the symlink's own path.
	argv := os.Args
	os.Args = []string{filepath.Join(shimDir, "clang")}
	t.Cleanup(func() { os.Args = argv })

	// A no-op by ABSOLUTE path: PATH is two temp dirs here, so anything
	// looked up by name would not be found and the test would fail for a
	// reason that has nothing to do with what it asserts.
	noop := filepath.Join(t.TempDir(), "noop")
	if err := os.WriteFile(noop, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var ranBin string
	prev := execCommand
	execCommand = func(bin string, args ...string) *exec.Cmd {
		ranBin = bin
		return exec.Command(noop)
	}
	t.Cleanup(func() { execCommand = prev })

	var errb bytes.Buffer
	if code := ccShim("clang", []string{"-c", "x.c"}, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	if ranBin == filepath.Join(shimDir, "clang") {
		t.Fatal("the shim exec'd ITSELF — os.Args[0] is not reaching resolveDriver")
	}
	if ranBin != filepath.Join(realDir, "clang") {
		t.Errorf("exec'd %q, want the compiler outside the shim dir", ranBin)
	}
}

// A driver that cannot be found is 127 and a message, not a crash and not
// a silent success. 127 is what a shell reports for "command not found",
// which is what this is.
func TestTheShimReportsACompilerItCannotFind(t *testing.T) {
	shimDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shimDir, "clang"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir) // the ONLY clang is the shim
	t.Setenv("ZPKB_CC", "clang --sysroot=/somewhere")
	argv := os.Args
	os.Args = []string{filepath.Join(shimDir, "clang")}
	t.Cleanup(func() { os.Args = argv })

	var errb bytes.Buffer
	if code := ccShim("clang", []string{"-c", "x.c"}, &errb); code != 127 {
		t.Fatalf("code=%d, want 127", code)
	}
	if !strings.Contains(errb.String(), "not on PATH outside") {
		t.Errorf("the message does not say what happened: %q", errb.String())
	}
}

// A path is taken as given. Only a bare name can resolve back to the shim,
// so only a bare name is looked up.
func TestResolveDriverPassesAPathThrough(t *testing.T) {
	for _, in := range []string{"/usr/bin/clang", "./clang", "../bin/clang"} {
		got, err := resolveDriver(in, "/shims/clang")
		if err != nil || got != in {
			t.Errorf("resolveDriver(%q) = %q, %v", in, got, err)
		}
	}
}

// A driver that is nowhere is a diagnosable failure, not a silent one — and
// the message says WHERE it looked, because "clang: not found" on a machine
// with clang installed is a confusing thing to read.
func TestResolveDriverSaysWhenThereIsNoCompiler(t *testing.T) {
	shimDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shimDir, "clang"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir)
	_, err := resolveDriver("clang", filepath.Join(shimDir, "clang"))
	if err == nil {
		t.Fatal("the only clang on PATH was the shim and it was accepted")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Errorf("the message does not say where it looked: %v", err)
	}
}

// Non-executable and directory entries are not compilers. A directory named
// `clang` on PATH would otherwise be exec'd.
func TestResolveDriverSkipsWhatCannotBeRun(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(a, "clang"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, "clang"), []byte("#!/bin/sh\n"), 0o644); err != nil { // not executable
		t.Fatal(err)
	}
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "clang"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sep := string(os.PathListSeparator)
	t.Setenv("PATH", a+sep+b+sep+real)
	got, err := resolveDriver("clang", "/elsewhere/clang")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(real, "clang") {
		t.Errorf("resolved to %q", got)
	}

	// An empty PATH entry is skipped rather than meaning the working
	// directory, which is how a PATH with a stray colon becomes a way to
	// run whatever is in the build tree.
	t.Setenv("PATH", sep+real)
	if got, _ := resolveDriver("clang", "/elsewhere/clang"); got != filepath.Join(real, "clang") {
		t.Errorf("with an empty PATH entry, resolved to %q", got)
	}
}

// The C++ names must reach the C++ driver, bare and triple-prefixed alike.
// A C++ build handed $ZPKB_CC gets no libc++ headers.
func TestTheCXXNamesRouteToTheCXXDriver(t *testing.T) {
	for _, n := range []string{"c++", "g++", "clang++", "s390x-ibm-linux-gnu-g++", "x86_64-pc-linux-gnu-clang++"} {
		if !isCXXShim(n) {
			t.Errorf("%q is a C++ compiler and routes to ZPKB_CC", n)
		}
	}
	for _, n := range []string{"cc", "gcc", "clang", "s390x-ibm-linux-gnu-gcc"} {
		if isCXXShim(n) {
			t.Errorf("%q is a C compiler and routes to ZPKB_CXX", n)
		}
	}
}

// Every name the dispatcher recognises, including the two just added.
func TestIsCompilerShimKnowsClang(t *testing.T) {
	for _, n := range []string{"cc", "gcc", "c++", "g++", "clang", "clang++",
		"x86_64-pc-linux-gnu-gcc", "s390x-ibm-linux-gnu-clang++"} {
		if !isCompilerShim(n) {
			t.Errorf("%q is materialised as a shim and the dispatcher does not know it", n)
		}
	}
	for _, n := range []string{"bk", "make", "clanger", "ccache"} {
		if isCompilerShim(n) {
			t.Errorf("%q is not a compiler shim", n)
		}
	}
}
