package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubLibtoolPath puts a plausible GNU libtool on PATH — a real file, because
// nextOnPath stats it — and records which binary the shim then chose.
//
// The choice is recorded through the execCommand seam rather than by running
// anything: what is under test is the ROUTING, and a test that execs a shell
// script measures the kernel's willingness to exec it as well (the first
// version of this file did, and only the OpenBSD lane disagreed).
func stubLibtoolPath(t *testing.T) *string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "libtool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	oldCmd, oldApple := execCommand, appleLibtool
	t.Cleanup(func() { execCommand, appleLibtool = oldCmd, oldApple })
	appleLibtool = filepath.Join(dir, "apple-libtool")
	if err := os.WriteFile(appleLibtool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ran := new(string)
	execCommand = func(name string, args ...string) *exec.Cmd {
		*ran = name
		// absolute: PATH has been replaced with the fixture dir, so a bare
		// "true" would not be found — which is exactly how the first version of
		// this file failed, and only on the lane whose PATH differed.
		return exec.Command("/usr/bin/true")
	}
	return ran
}

// The two invocations that actually broke, both from this factory's own darwin
// runs: videolan.org/x265's recipe line and the one V8's gyp generates inside
// nodejs.org. GNU libtool answers `unrecognised option` to each, after the
// build has compiled everything.
func TestLibtoolShimRoutesAppleInvocationsToApple(t *testing.T) {
	for _, args := range [][]string{
		{"-static", "-o", "libx265.a", "libx265_main.a"},
		{"-framework", "CoreFoundation", "-static", "-o", "libv8_libbase.a"},
		{"-dynamic", "-o", "libfoo.dylib"},
	} {
		ran := stubLibtoolPath(t)
		var out bytes.Buffer
		if code := libtoolShim(args, &out); code != 0 {
			t.Fatalf("args %v: exit %d (%s)", args, code, out.String())
		}
		if filepath.Base(*ran) != "apple-libtool" {
			t.Errorf("args %v ran %q, want Apple's", args, *ran)
		}
	}
}

// Everything else falls through to whatever PATH would have found. The rule is
// one-directional on purpose: the shim can turn an error into a build, and must
// not be able to send a working GNU call somewhere else.
func TestLibtoolShimLeavesGnuInvocationsAlone(t *testing.T) {
	for _, args := range [][]string{
		{"--mode=link", "cc", "-o", "libfoo.la"},
		{"--version"},
		{"--mode=compile", "cc", "-c", "foo.c"},
	} {
		ran := stubLibtoolPath(t)
		var out bytes.Buffer
		if code := libtoolShim(args, &out); code != 0 {
			t.Fatalf("args %v: exit %d (%s)", args, code, out.String())
		}
		if filepath.Base(*ran) != "libtool" {
			t.Errorf("args %v ran %q, want the one on PATH", args, *ran)
		}
	}
}

// An Apple invocation on a machine with no cctools libtool still has to run
// something: the shim falls through rather than failing on a missing file.
func TestLibtoolShimFallsThroughWhenAppleIsAbsent(t *testing.T) {
	ran := stubLibtoolPath(t)
	appleLibtool = filepath.Join(t.TempDir(), "definitely-absent")
	var out bytes.Buffer
	if code := libtoolShim([]string{"-static", "-o", "x.a"}, &out); code != 0 {
		t.Fatalf("exit %d (%s)", code, out.String())
	}
	if filepath.Base(*ran) != "libtool" {
		t.Errorf("ran %q, want the one on PATH", *ran)
	}
}

// With no other libtool on PATH the shim must say so rather than recurse into
// itself: every shim in the libexec dir is a symlink to the bk binary, so a
// self-exec would loop.
func TestLibtoolShimRefusesToFindOnlyItself(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(self))
	var out bytes.Buffer
	if code := libtoolShim([]string{"--version"}, &out); code != 127 {
		t.Errorf("exit = %d, want 127", code)
	}
	if !strings.Contains(out.String(), "besides this shim") {
		t.Errorf("stderr = %q, want it to name the problem", out.String())
	}
}

// Without a path to itself the shim cannot tell which PATH entry is its own, so
// it declines rather than risk exec'ing itself in a loop.
func TestLibtoolShimWithoutAPathToItself(t *testing.T) {
	old := osExecutable
	osExecutable = func() (string, error) { return "", errInjectedLibtool }
	t.Cleanup(func() { osExecutable = old })
	var out bytes.Buffer
	if code := libtoolShim([]string{"--version"}, &out); code != 127 {
		t.Errorf("exit = %d, want 127", code)
	}
}

var errInjectedLibtool = errors.New("injected")

// The child's exit status is the shim's: a build system reads it to decide
// whether the archive was made.
func TestLibtoolShimPassesTheExitStatusThrough(t *testing.T) {
	stubLibtoolPath(t)
	execCommand = func(name string, args ...string) *exec.Cmd { return exec.Command("/usr/bin/false") }
	var out bytes.Buffer
	if code := libtoolShim([]string{"--version"}, &out); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

// A libtool that cannot be executed at all is not an exit status, and must be
// reported rather than swallowed into a zero.
func TestLibtoolShimReportsAnUnrunnableTool(t *testing.T) {
	stubLibtoolPath(t)
	execCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command(filepath.Join(t.TempDir(), "not-a-program"))
	}
	var out bytes.Buffer
	if code := libtoolShim([]string{"--version"}, &out); code != 127 {
		t.Errorf("exit = %d, want 127", code)
	}
	if !strings.Contains(out.String(), "zbk libtool:") {
		t.Errorf("stderr = %q, want it to name the shim", out.String())
	}
}

// main() routes the shim name to the shim.
func TestLibtoolMultiCallDispatch(t *testing.T) {
	oldExit, oldArgs := osExit, os.Args
	defer func() { osExit, os.Args = oldExit, oldArgs }()
	got := -1
	osExit = func(c int) { got = c }
	ran := stubLibtoolPath(t)
	os.Args = []string{"/build/libexec/libtool", "-static", "-o", "x.a"}
	main()
	if got != 0 {
		t.Fatalf("libtool dispatch exit = %d, want 0", got)
	}
	if filepath.Base(*ran) != "apple-libtool" {
		t.Errorf("dispatch ran %q, want Apple's", *ran)
	}
}
