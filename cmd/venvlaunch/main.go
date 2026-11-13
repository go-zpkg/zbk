// venvlaunch is the entry point `zpkb bkpyvenv seal` installs as
// $PREFIX/bin/<cmd> for a Python application packaged into a virtualenv.
//
// ⛔⛔ IT IS A BINARY BECAUSE A SCRIPT HAS NO $ORIGIN. The kernel resolves a
// shebang by handing the interpreter name to ordinary path lookup
// (fs/binfmt_script.c), so a script cannot find anything relative to itself —
// in any kernel, for any language. A binary can: /proc/self/exe on Linux,
// _NSGetExecutablePath on darwin, KERN_PROC_PATHNAME on the BSDs, all of which
// os.Executable wraps.
//
// That one difference settles four defects this repository paid for
// separately, each measured rather than assumed (go-zpkg/zpkgx#151):
//
//	no /usr/bin/env, no /bin/sh   1513 of 1870 scripts in a real installed
//	                              tree need one or the other, so they cannot
//	                              start in a FROM-scratch image at all
//	no `env -S`                   busybox's env has no -S (coreutils/env.c
//	                              parses "+i0u:*"), so the shebang this
//	                              replaces does not run on Alpine (zpkb#435)
//	no 127-character limit        execve(2) truncates a shebang at 127 bytes
//	                              before Linux 5.1, 255 after, SILENTLY
//	no interpreter at all         a CGO_ENABLED=0 Go binary has no PT_INTERP
//	                              and no DT_NEEDED: measured on linux/amd64,
//	                              s390x and loong64. A C launcher would need
//	                              ld-linux and libc.so.6, which is the same
//	                              missing-interpreter failure one layer down
//
// ⛔ AND IT EXECS THE INTERPRETER WITH THE SCRIPT AS AN ARGUMENT, so the venv's
// own console-script shebangs are never consulted by the kernel. The shebang
// rewriting the previous launcher existed to do therefore disappears — with it
// the lock, the race it needed, the NFS restriction that lock turned out to
// have, and the planted-symlink hazard its temporary file carried.
//
// ⛔⛔ IT WRITES NOTHING. NOT "LITTLE" — NOTHING.
//
// The first version of this file repaired venv/bin/python when an environment
// variable said it was wrong. That was a smaller version of the same mistake:
// a launcher that writes needs a lock, and a lock over NFS needs a file opened
// for writing, and a shared home needs the write not to fight another host.
// The repair is unnecessary because `seal` can make venv/bin/python a RELATIVE
// symlink into the store — `../../../../python.org/<ver>/bin/python3` — and a
// relative link survives the store moving, which is the same property
// `@loader_path/../../..` already gives our rpaths (go-zpkg/pantry-overlay#28).
//
// So there is no ZPKG_PYTHON, no temporary file, no rename and no lock. A
// read-only store works, an NFS home works, two hosts sharing one home work,
// and every signature stays valid because nothing is rewritten. The repair
// mechanism was removed rather than kept "just in case": a bottle built before
// this carries the old SCRIPT launcher, not this binary, so there is no
// deployment in which the repair could ever run.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Seams, so every error branch is reachable from a test without a real venv.
var (
	osExecutable = os.Executable
	evalSymlinks = filepath.EvalSymlinks
	osStat       = os.Stat
	execFn       = syscall.Exec
	exitFn       = os.Exit
)

func main() {
	if code := run(os.Args, os.Stderr); code != 0 {
		exitFn(code)
	}
}

// run is main with its edges injected. It returns a code only on failure: the
// success path ends in exec and never comes back.
func run(args []string, stderr io.Writer) int {
	self, err := osExecutable()
	if err != nil {
		fmt.Fprintf(stderr, "venvlaunch: cannot locate myself: %v\n", err)
		return 127
	}
	// Resolved, because the store exposes a `v<version>` symlink beside the
	// hashed directory and an entry point reached through it would otherwise
	// look for its venv under the alias.
	self, err = evalSymlinks(self)
	if err != nil {
		fmt.Fprintf(stderr, "venvlaunch: %v\n", err)
		return 127
	}

	name := filepath.Base(self)
	prefix := filepath.Dir(filepath.Dir(self)) // <prefix>/bin/<name> -> <prefix>
	venv := filepath.Join(prefix, "venv")
	python := filepath.Join(venv, "bin", "python")
	entry := filepath.Join(venv, "bin", name)

	// Both are checked before the exec so that the message names which one is
	// missing. `exec: no such file or directory` cannot distinguish "this venv
	// has no such program" from "this venv has no interpreter", and those have
	// different causes and different fixes.
	if _, err := osStat(entry); err != nil {
		fmt.Fprintf(stderr, "venvlaunch: %s has no entry point named %s\n", venv, name)
		return 127
	}
	if _, err := osStat(python); err != nil {
		fmt.Fprintf(stderr, "venvlaunch: %s has no interpreter at bin/python: %v\n", venv, err)
		return 127
	}

	argv := append([]string{python, entry}, args[1:]...)
	if err := execFn(python, argv, os.Environ()); err != nil {
		fmt.Fprintf(stderr, "venvlaunch: exec %s: %v\n", python, err)
		return 127
	}
	return 0 // unreachable: a successful exec does not return
}
