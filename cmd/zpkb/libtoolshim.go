package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// appleLibtoolFlags are the options only cctools' libtool understands. GNU
// libtool refuses every one of them outright:
//
//	libtool:   error: unrecognised option: '-static'
//	libtool:   error: unrecognised option: '-framework'
//
// Both of those are real, from this factory, on two different packages —
// videolan.org/x265's own recipe line and V8's gyp inside nodejs.org.
var appleLibtoolFlags = map[string]bool{
	"-static":     true,
	"-dynamic":    true,
	"-framework":  true,
	"-arch_only":  true,
	"-filelist":   true,
	"-syslibroot": true,
}

// libtoolShim picks which `libtool` a darwin build meant.
//
// Two unrelated programs answer to that name. cctools' libtool merges static
// libraries; GNU libtool drives compilation and linking. On a plain macOS only
// the first is installed, so a build system that wants it just writes
// `libtool`. In this factory `pkgx +<deps>` prepends the dependency bin dirs to
// PATH, and any dependency shipping gnu.org/libtool puts the OTHER program in
// front of /usr/bin — after a build has already compiled everything:
//
//	[148/2639] LIBTOOL-STATIC libv8_libbase.a
//	libtool:   error: unrecognised option: '-framework'
//
// x265 could be fixed in its recipe by naming /usr/bin/libtool. nodejs cannot:
// the call is generated inside V8's gyp, and there is no recipe line to change.
//
// The rule is deliberately one-directional. An invocation is routed to Apple's
// libtool only when it carries a flag GNU libtool would REFUSE — so the shim
// can only turn an error into a build, never a working GNU call into something
// else. Anything else falls through to whatever `libtool` PATH would have
// found without us.
func libtoolShim(args []string, stderr io.Writer) int {
	if wantsAppleLibtool(args) {
		if _, err := os.Stat(appleLibtool); err == nil {
			return runLibtool(appleLibtool, args, stderr)
		}
	}
	next, err := nextOnPath("libtool")
	if err != nil {
		fmt.Fprintf(stderr, "zpkb libtool: %v\n", err)
		return 127
	}
	return runLibtool(next, args, stderr)
}

// appleLibtool is where cctools' libtool lives on macOS. A var so a test can
// point it at something it can run.
var appleLibtool = "/usr/bin/libtool"

// osExecutable is a seam: the error branch of os.Executable is not reachable
// with a real process.
var osExecutable = os.Executable

func wantsAppleLibtool(args []string) bool {
	for _, a := range args {
		if appleLibtoolFlags[a] {
			return true
		}
	}
	return false
}

// nextOnPath finds the first name on $PATH that is not this shim itself.
//
// "Not itself" is decided by DIRECTORY, not by resolving the symlink: every
// shim in the libexec dir points at the bk binary, so comparing targets would
// match nothing useful, and comparing paths would miss the case where PATH
// names the same directory twice.
func nextOnPath(name string) (string, error) {
	self, err := osExecutable()
	if err != nil {
		return "", err
	}
	selfDir := filepath.Dir(self)
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || dir == selfDir {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("no %s on PATH besides this shim (PATH=%s)", name, os.Getenv("PATH"))
}

func runLibtool(bin string, args []string, stderr io.Writer) int {
	cmd := execCommand(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errorsAs(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(stderr, "zpkb libtool: %s: %v\n", strings.TrimSpace(bin), err)
		return 127
	}
	return 0
}
