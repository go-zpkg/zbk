package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Installing the venvlaunch entry point, which is what replaces the three
// embedded launcher SCRIPTS this repository used to ship (go-zpkg/zpkb#431,
// go-zpkg/zpkb#435, go-zpkg/zpkgx#151).
//
// There were three of them — bkpyvenv's python stub, python-venv-stubber's
// python stub and python-venv.py's POSIX-sh stub — written by three different
// upstream files, two of them still VERBATIM copies of pkgxdev/brewkit, which
// declares no licence. They are deleted here rather than ported, because a
// script cannot do this job in the images we target at all:
//
//	a shebang has no $ORIGIN      fs/binfmt_script.c hands the interpreter
//	                             name to ordinary path lookup, so no script
//	                             can find its own venv — in any kernel
//	no /usr/bin/env, no /bin/sh   1513 of 1870 scripts in a real installed
//	                             tree need one or the other, so they cannot
//	                             start in a FROM-scratch image
//	no `env -S` on busybox        coreutils/env.c parses "+i0u:*", so the
//	                             `env -S zpkgx python@X.Y` shebang these
//	                             stubs carried does not run on Alpine
//
// cmd/venvlaunch answers all three because a binary can read /proc/self/exe.
// This file is the other half: getting that binary into the bottle, and
// leaving the venv in a state it can use WITHOUT writing anything at run time.

// Seams. pyLookPath and pyRelink are indirected so that the two error branches
// no temp directory can produce — a PATH entry that disappears between lookup
// and read, and a failed relink — stay reachable from a test.
// pyGOOS lives in bkpyvenv.go, where it already selects the venv-creation
// flags; it is the same question here and a second copy of it could disagree.
// ⛔⛔ pyReadlink IS A SEAM BECAUSE THE CLEVER ALTERNATIVE FAILED ON THREE
// KERNELS. Reaching os.Readlink's error without one means making <venv>/bin
// readable but not searchable (mode 0444), so that os.ReadDir lists it and
// resolving a name inside it fails. That works on linux and darwin, and
// FreeBSD, NetBSD and OpenBSD all answered the readlink anyway: 21 green, 3
// red, on a run whose other 23 checks said the change was fine. A test that
// depends on where a kernel places a permission check is testing the kernel.
var (
	pyLookPath   = exec.LookPath
	pyRelink     = defaultRelink
	pyExecutable = os.Executable
	pyReadlink   = os.Readlink
	pyGOARCH     = runtime.GOARCH
)

// venvLaunchName is the program `seal` looks for on PATH. It is a build
// dependency of every python-venv recipe (go-zpkg.github.io/venvlaunch, see
// the error below for why that domain), published as a STORED release asset
// (go-zpkg/zpkb's release workflow) so the recipe can pin it by digest —
// 1111 of 1932 upstream recipes fetch a GitHub-GENERATED archive, whose bytes
// have changed before, and cannot be pinned at all (go-zpkg/packages#420).
const venvLaunchName = "venvlaunch"

// findVenvLaunch locates the launcher to install: PATH first, then beside the
// running zpkb.
//
// ⛔⛔ PATH FIRST, AND THE ORDER IS THE WHOLE CORRECTNESS ARGUMENT. The binary
// that goes into the bottle must be for the bottle's TARGET, and the two
// candidates answer for different platforms:
//
//	on PATH             resolved from the recipe's build dependencies, so it
//	                    is the TARGET's. Correct for a cross build, and the
//	                    only candidate that can be.
//	beside this zpkb     the HOST's, because it came out of the same release
//	                    matrix as the zpkb now running. Correct whenever host
//	                    and target are the same, which every python-venv build
//	                    is — a venv is built by running the packaged python.
//
// So PATH wins when a recipe declares the dependency, and the fallback saves
// every recipe that does not from failing. Without the fallback this change
// would have required editing every python-venv recipe in the pantry before it
// could land; with it, the behaviour improves for all of them at once and a
// recipe can still override it explicitly.
//
// Both spellings are tried beside zpkb because the release publishes the assets
// under their platform names (`venvlaunch-linux-amd64`) and an installer may
// or may not have renamed them.
func findVenvLaunch() (string, error) {
	if src, err := pyLookPath(venvLaunchName); err == nil {
		return src, nil
	}
	self, err := pyExecutable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(self)
	tried := []string{venvLaunchName + " (PATH)"}
	for _, name := range []string{
		venvLaunchName,
		venvLaunchName + "-" + pyGOOS + "-" + pyGOARCH,
	} {
		cand := filepath.Join(dir, name)
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
		tried = append(tried, cand)
	}
	// ⛔ go-zpkg.github.io, NOT go-zpkg.org. A pantry project name is a DOMAIN,
	// and it is the thing a consumer trusts to say where a package came from;
	// go-zpkg.org is not a domain this organisation holds, so naming it here
	// would tell every recipe author to pin provenance to an address somebody
	// else could register. go-zpkg.github.io is the one we actually serve, and
	// the convention the pantry already uses for projects published that way
	// (aria2.github.io, openprinting.github.io).
	return "", fmt.Errorf("cannot find %s — looked at %v; install it beside zpkb from the same release, or declare go-zpkg.github.io/venvlaunch among the recipe's build dependencies", venvLaunchName, tried)
}

// installVenvLaunch copies the venvlaunch binary to <prefix>/bin/<name> for
// every name, and relativises the venv's absolute symlinks.
//
// ⛔ IT COPIES, ONCE PER NAME, AND THAT IS DELIBERATE. A symlink would not
// work: venvlaunch derives the entry point it runs from filepath.Base of its
// own RESOLVED path, so bin/foo -> bin/bar would run bar. A hard link keeps the
// name on Linux (/proc/self/exe reports the path execve used) and is not
// specified to on darwin, where _NSGetExecutablePath reports what the caller
// passed. A copy is the only form that means the same thing on every platform
// we publish for, and it costs ~1.5 MB per entry point (measured: 1 769 632
// bytes for linux/s390x, 1 610 011 for openbsd/amd64, stripped). Almost every
// python-venv recipe declares exactly one command.
func installVenvLaunch(prefix, venv string, names []string) error {
	src, err := findVenvLaunch()
	if err != nil {
		return err
	}
	launcher, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	binDir := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	for _, name := range names {
		dst := filepath.Join(binDir, name)
		// Removed first: os.WriteFile does not change the mode of a file that
		// already exists, so a rebuild over a 0o644 leftover would install an
		// entry point nobody can execute.
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(dst, launcher, 0o755); err != nil {
			return err
		}
	}
	return relativiseVenvLinks(venv)
}

// relativiseVenvLinks rewrites every ABSOLUTE symlink in <venv>/bin as a path
// relative to that directory.
//
// ⛔⛔ THIS IS WHAT LETS THE LAUNCHER WRITE NOTHING. `python -m venv` makes
// bin/python, bin/python3 and bin/pythonX.Y symlinks to the interpreter it was
// run with, by ABSOLUTE path. That path is the build store's, so a bottle
// unpacked anywhere else has a venv whose interpreter does not exist — which is
// the single fact the three deleted stubs existed to repair, at run time, on
// every invocation of every packaged tool. A relative link survives the store
// moving as a unit, exactly as `@loader_path/../../..` already does for our
// rpaths (go-zpkg/pantry-overlay#28), and it is written once, here, in the
// build sandbox: no lock, no race, no NFS restriction, no rewritten file inside
// a signed bottle.
//
// Only <venv>/bin is walked. The console scripts in it are regular files, not
// symlinks, so their absolute shebangs are untouched — and unread: venvlaunch
// execs `python <entry>`, passing the script as an ARGUMENT, so the kernel
// never looks at their first line. pyvenv.cfg's `home` is left alone too; it is
// measured to be load-bearing by its PRESENCE and not by its contents.
func relativiseVenvLinks(venv string) error {
	binDir := filepath.Join(venv, "bin")
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		link := filepath.Join(binDir, e.Name())
		target, err := pyReadlink(link)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			continue // already relative: a rebuild must not double-prefix it
		}
		// ⛔ NO filepath.Abs HERE, AND THE ERROR IS THE POINT. filepath.Rel
		// refuses to relate an absolute target to a relative base, so a caller
		// that passed a relative $PREFIX lands in this branch instead of
		// silently getting a link computed against whatever the build step's
		// working directory happened to be. Absolutising it would have hidden
		// that, and filepath.Abs's own error — os.Getwd failing — is a branch
		// nothing can reach, so it would have cost coverage to buy a defect.
		rel, err := filepath.Rel(binDir, target)
		if err != nil {
			return fmt.Errorf("%s -> %s: cannot be made relative to %s (an absolute prefix is required): %w", link, target, binDir, err)
		}
		if err := pyRelink(link, rel); err != nil {
			return err
		}
		// ⛔ AND IT IS CHECKED, because filepath.Rel is pure arithmetic on two
		// strings: it answers for any pair of absolute paths, including a pair
		// with no useful relationship, and a wrong answer here would ship a
		// venv with no interpreter. os.Stat follows the link.
		if _, err := os.Stat(link); err != nil {
			return fmt.Errorf("%s: %s resolved, %s does not: %w", link, target, rel, err)
		}
	}
	return nil
}

// defaultRelink replaces the symlink at path with one pointing at target.
//
// It creates the new link under a temporary name and renames it over the old
// one, so there is no instant in which bin/python is absent — a concurrent
// build step reading the venv sees the old link or the new one.
//
// ⛔ A PREDICTABLE TEMPORARY NAME IS SAFE HERE, AND IT IS NOT SAFE IN GENERAL.
// The hazard a predictable name carries is that OPENING it follows whatever
// somebody planted there; this repository shipped exactly that defect in the
// stub this file deletes. symlink(2) does not open anything and fails with
// EEXIST if the name is taken, so a planted file makes this return an error
// naming it rather than write through it.
func defaultRelink(path, target string) error {
	tmp := path + ".zpkg-relink"
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
