// venvlaunch is the entry point `zbk bkpyvenv seal` installs as
// $PREFIX/bin/<cmd> for a Python application packaged into a virtualenv.
//
// ⛔⛔ IT IS A BINARY BECAUSE A SCRIPT HAS NO $ORIGIN. The kernel resolves a
// shebang by handing the interpreter name to ordinary path lookup
// (fs/binfmt_script.c), so a script cannot find anything relative to itself —
// in any kernel, for any language. A binary can: /proc/self/exe on Linux,
// _NSGetExecutablePath on darwin, KERN_PROC_PATHNAME on the BSDs, all of which
// os.Executable wraps.
//
// That one difference settles four separate defects this repository has paid
// for, each measured rather than assumed (go-zpkg/zpkgx#151):
//
//	no /usr/bin/env, no /bin/sh   1513 of 1870 scripts in a real installed
//	                              tree need one or the other, so they cannot
//	                              start in a FROM-scratch image at all
//	no `env -S`                   busybox's env has no -S (coreutils/env.c
//	                              parses "+i0u:*"), so the shebang this
//	                              replaces does not run on Alpine (zbk#435)
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
// rewriting that the previous launcher existed to do therefore disappears —
// with it the lock, the race it needed, the NFS restriction that lock turned
// out to have, and the symlink hazard the temporary file carried.
//
// What it still has to repair is ONE thing, and only when it is wrong:
// venv/bin/python. Measured: a venv whose pyvenv.cfg says `home = /gone/bin`
// still resolves to the venv, because python takes sys.prefix from where
// sys.executable is; deleting pyvenv.cfg does break it. So the file's presence
// is load-bearing and its contents are not, and this launcher never writes it.
// The symlink is replaced by rename, which is atomic, so two launchers doing
// it at once is harmless and NO LOCK IS NEEDED.
package main

import (
	"errors"
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
	osReadlink   = os.Readlink
	osSymlink    = os.Symlink
	osRename     = os.Rename
	osRemove     = os.Remove
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
	venvBin := filepath.Join(prefix, "venv", "bin")
	python := filepath.Join(venvBin, "python")
	entry := filepath.Join(venvBin, name)

	// ⛔ THE ENTRY POINT IS CHECKED BEFORE THE SYMLINK IS TOUCHED. Repairing a
	// venv that has no such entry point writes to a tree to no purpose, and
	// the error a caller needs is "there is no such program", not a failure
	// from the repair of something unrelated.
	if _, err := osStat(entry); err != nil {
		fmt.Fprintf(stderr, "venvlaunch: %s has no entry point named %s\n",
			filepath.Join(prefix, "venv"), name)
		return 127
	}

	if want := os.Getenv("ZPKG_PYTHON"); want != "" {
		if err := ensureSymlink(python, want); err != nil {
			// A venv that cannot be repaired may still run: the existing
			// symlink might be correct for this host even though the
			// environment named another interpreter. The exec below decides,
			// and its error is the one worth reporting.
			fmt.Fprintf(stderr, "venvlaunch: could not point %s at %s: %v\n", python, want, err)
		}
	}

	argv := append([]string{python, entry}, args[1:]...)
	if err := execFn(python, argv, os.Environ()); err != nil {
		fmt.Fprintf(stderr, "venvlaunch: exec %s: %v\n", python, err)
		return 127
	}
	return 0 // unreachable: a successful exec does not return
}

// ensureSymlink points path at want, and writes nothing if it already does.
//
// The replacement goes through a temporary name and a rename rather than
// remove-then-create, because remove-then-create leaves a window with NO
// interpreter — which is exactly how the previous launcher failed under
// contention: six of them against one stale venv produced
// `FileNotFoundError: [Errno 2]` on execv, 8 times in 5 runs. rename is
// atomic, so an observer sees either the old link or the new one.
func ensureSymlink(path, want string) error {
	if got, err := osReadlink(path); err == nil && got == want {
		return nil
	}
	// The temporary name is in the same directory, so the rename cannot cross
	// a filesystem; and it is exclusive, so a planted name is not followed.
	tmp := path + ".venvlaunch"
	if err := osRemove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := osSymlink(want, tmp); err != nil {
		return err
	}
	if err := osRename(tmp, path); err != nil {
		if rmErr := osRemove(tmp); rmErr != nil {
			return fmt.Errorf("%w (and the temporary survived: %v)", err, rmErr)
		}
		return err
	}
	return nil
}
