package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// tree builds what `bkpyvenv seal` leaves behind: the launcher at
// <prefix>/bin/<name>, and a venv beside it.
func tree(t *testing.T, name string) (prefix, venvBin string) {
	t.Helper()
	prefix = t.TempDir()
	venvBin = filepath.Join(prefix, "venv", "bin")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(venvBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venvBin, name), []byte("#!/gone/python\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The launcher itself has to exist on disk: it locates the venv by
	// RESOLVING its own path, so a test that only pretends os.Executable
	// returns a path exercises nothing.
	if err := os.WriteFile(filepath.Join(prefix, "bin", name), []byte("binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return prefix, venvBin
}

// at points osExecutable at <prefix>/bin/<name> for the duration of a test.
func at(t *testing.T, prefix, name string) {
	t.Helper()
	was := osExecutable
	osExecutable = func() (string, error) { return filepath.Join(prefix, "bin", name), nil }
	t.Cleanup(func() { osExecutable = was })
}

// captureExec records what would have been exec'd instead of replacing the
// test process.
func captureExec(t *testing.T) *[]string {
	t.Helper()
	var got []string
	was := execFn
	execFn = func(argv0 string, argv []string, env []string) error {
		got = append([]string{argv0}, argv...)
		return nil
	}
	t.Cleanup(func() { execFn = was })
	return &got
}

// ⛔⛔ THE WHOLE POINT: THE INTERPRETER IS EXEC'D WITH THE SCRIPT AS AN
// ARGUMENT. The venv's own shebang is therefore never resolved by the kernel,
// which is what removes the need for /usr/bin/env, for env -S, for a shell,
// and for rewriting every console script in the tree.
func TestItExecsTheInterpreterWithTheEntryPointAsAnArgument(t *testing.T) {
	prefix, venvBin := tree(t, "acme")
	at(t, prefix, "acme")
	got := captureExec(t)

	var errb bytes.Buffer
	if code := run([]string{filepath.Join(prefix, "bin", "acme"), "--flag", "x"}, &errb); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}

	real, err := filepath.EvalSymlinks(venvBin)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(real, "python"),
		filepath.Join(real, "python"),
		filepath.Join(real, "acme"),
		"--flag", "x",
	}
	if strings.Join(*got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("exec\n got %v\nwant %v", *got, want)
	}
}

// ⛔ NOTHING IS WRITTEN WHEN ZPKG_PYTHON IS NOT SET, and nothing is written
// when the symlink is already right. Every write the previous launcher made is
// the origin of the lock, the race, the NFS restriction and the multi-host
// ping-pong, so "writes nothing" is the property under test, not an
// optimisation.
func TestItWritesNothingWhenThereIsNothingToFix(t *testing.T) {
	prefix, venvBin := tree(t, "acme")
	at(t, prefix, "acme")
	captureExec(t)

	python := filepath.Join(venvBin, "python")
	if err := os.Symlink("/usr/bin/python3", python); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZPKG_PYTHON", "/usr/bin/python3")

	// Any write at all would be visible: the seams refuse to be called.
	wasSym, wasRen, wasRm := osSymlink, osRename, osRemove
	osSymlink = func(string, string) error { t.Error("symlink was written"); return nil }
	osRename = func(string, string) error { t.Error("rename was performed"); return nil }
	osRemove = func(string) error { t.Error("remove was performed"); return nil }
	t.Cleanup(func() { osSymlink, osRename, osRemove = wasSym, wasRen, wasRm })

	var errb bytes.Buffer
	if code := run([]string{filepath.Join(prefix, "bin", "acme")}, &errb); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}
}

// And when the symlink IS wrong it is replaced — by rename, never by
// remove-then-create, because that leaves a window with no interpreter. Six
// concurrent copies of the previous launcher produced `FileNotFoundError` on
// execv 8 times in 5 runs through exactly that window.
func TestItReplacesAWrongSymlinkByRenamingOverIt(t *testing.T) {
	prefix, venvBin := tree(t, "acme")
	at(t, prefix, "acme")
	captureExec(t)
	python := filepath.Join(venvBin, "python")
	if err := os.Symlink("/gone/bin/python3", python); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZPKG_PYTHON", "/usr/bin/python3")

	// The removal of the target is the shape that must NOT happen.
	wasRm := osRemove
	osRemove = func(p string) error {
		if p == python {
			t.Errorf("the live symlink was removed; the replacement must be a rename")
		}
		return wasRm(p)
	}
	t.Cleanup(func() { osRemove = wasRm })

	var errb bytes.Buffer
	if code := run([]string{filepath.Join(prefix, "bin", "acme")}, &errb); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}
	got, err := os.Readlink(python)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/usr/bin/python3" {
		t.Errorf("symlink = %q", got)
	}
	// And no temporary may survive in a packaged tree.
	leftover, err := filepath.Glob(filepath.Join(venvBin, "python.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftover) > 0 {
		t.Errorf("temporary left behind: %v", leftover)
	}
}

// A missing entry point is a stated error, and it is checked BEFORE anything
// is written: repairing a venv that cannot run the requested program writes to
// a packaged tree to no purpose.
func TestItRefusesAMissingEntryPointWithoutWriting(t *testing.T) {
	prefix, venvBin := tree(t, "acme")
	if err := os.Remove(filepath.Join(venvBin, "acme")); err != nil {
		t.Fatal(err)
	}
	at(t, prefix, "acme")
	captureExec(t)
	t.Setenv("ZPKG_PYTHON", "/usr/bin/python3")

	wasSym := osSymlink
	osSymlink = func(string, string) error { t.Error("wrote before checking the entry point"); return nil }
	t.Cleanup(func() { osSymlink = wasSym })

	var errb bytes.Buffer
	code := run([]string{filepath.Join(prefix, "bin", "acme")}, &errb)
	if code != 127 {
		t.Fatalf("code = %d, want 127", code)
	}
	if !strings.Contains(errb.String(), "no entry point named acme") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestItReportsWhenItCannotLocateItself(t *testing.T) {
	was := osExecutable
	osExecutable = func() (string, error) { return "", errors.New("no /proc") }
	t.Cleanup(func() { osExecutable = was })
	var errb bytes.Buffer
	if code := run([]string{"x"}, &errb); code != 127 || !strings.Contains(errb.String(), "locate myself") {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
}

func TestItReportsWhenItsPathCannotBeResolved(t *testing.T) {
	at(t, t.TempDir(), "acme") // bin/acme does not exist, so EvalSymlinks fails
	var errb bytes.Buffer
	if code := run([]string{"x"}, &errb); code != 127 {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
}

// A failed repair is reported and then the exec is still attempted: the
// existing symlink may be right for this host even though the environment
// named another interpreter, and only the exec can tell.
func TestAFailedRepairStillTriesToRun(t *testing.T) {
	prefix, venvBin := tree(t, "acme")
	at(t, prefix, "acme")
	got := captureExec(t)
	if err := os.Symlink("/gone/python3", filepath.Join(venvBin, "python")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZPKG_PYTHON", "/usr/bin/python3")

	wasSym := osSymlink
	osSymlink = func(string, string) error {
		return &fs.PathError{Op: "symlink", Err: errors.New("read-only file system")}
	}
	t.Cleanup(func() { osSymlink = wasSym })

	var errb bytes.Buffer
	if code := run([]string{filepath.Join(prefix, "bin", "acme")}, &errb); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "could not point") {
		t.Errorf("the failure must be said out loud: %q", errb.String())
	}
	if len(*got) == 0 {
		t.Error("the exec must still be attempted")
	}
}

func TestAFailedExecIsReported(t *testing.T) {
	prefix, _ := tree(t, "acme")
	at(t, prefix, "acme")
	was := execFn
	execFn = func(string, []string, []string) error { return syscall.ENOENT }
	t.Cleanup(func() { execFn = was })

	var errb bytes.Buffer
	if code := run([]string{filepath.Join(prefix, "bin", "acme")}, &errb); code != 127 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(errb.String(), "exec") {
		t.Errorf("stderr = %q", errb.String())
	}
}

// The remaining arms of ensureSymlink, each unreachable through run() with
// real files and each a different failure a packaged tree can present.
func TestEnsureSymlinkFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "python")

	wasRm, wasSym, wasRen := osRemove, osSymlink, osRename
	t.Cleanup(func() { osRemove, osSymlink, osRename = wasRm, wasSym, wasRen })

	osRemove = func(string) error { return errors.New("stale temporary cannot be removed") }
	if err := ensureSymlink(path, "/usr/bin/python3"); err == nil {
		t.Error("a temporary that cannot be cleared must stop the replacement")
	}

	osRemove = wasRm
	osRename = func(string, string) error { return errors.New("rename refused") }
	if err := ensureSymlink(path, "/usr/bin/python3"); err == nil {
		t.Error("a failed rename must be reported")
	}
	// …and the temporary must not survive it.
	if _, err := os.Lstat(path + ".venvlaunch"); err == nil {
		t.Error("the temporary survived a failed rename")
	}

	// ⛔ The FIRST removal clears a stale temporary and must succeed, or the
	// function returns before the rename it is meant to fail at. Only the
	// cleanup removal — the second call — fails here. Counting the calls is
	// the difference between testing the cleanup arm and testing the arm
	// above it, which is what the first version of this did.
	calls := 0
	osRemove = func(p string) error {
		calls++
		if calls == 1 {
			return wasRm(p)
		}
		return errors.New("cannot clean up")
	}
	err := ensureSymlink(path, "/usr/bin/python3")
	if err == nil || !strings.Contains(err.Error(), "temporary survived") {
		t.Errorf("a failed cleanup after a failed rename must say both: %v", err)
	}
	if calls != 2 {
		t.Errorf("want the stale-clear then the cleanup, got %d removal(s)", calls)
	}
}

// main() exits with the code run() gives it, and does not exit on success.
func TestMainExitsOnlyOnFailure(t *testing.T) {
	var code int
	wasExit, wasExec := exitFn, osExecutable
	exitFn = func(c int) { code = c }
	osExecutable = func() (string, error) { return "", errors.New("nowhere") }
	t.Cleanup(func() { exitFn, osExecutable = wasExit, wasExec })
	main()
	if code != 127 {
		t.Errorf("exit code = %d, want 127", code)
	}
}

// ⛔⛔ THE PROOF THE DESIGN RESTS ON: the launcher, BUILT, against a venv
// CPython itself created, importing a module really installed into it.
//
// Everything above drives run() with seams. This one answers the question the
// seams cannot: does exec'ing the interpreter with the entry point as an
// argument actually give that script the venv's packages? Measurement said it
// should — a venv resolves from where sys.executable is, so going through
// venv/bin/python keeps sys.prefix pointing at the venv — and a design decided
// from a measurement deserves a test that repeats it.
//
// It also proves the shebang is never consulted: the entry point's first line
// names an interpreter that does not exist, and the program still runs.
func TestTheBuiltLauncherRunsARealVenv(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 on this lane")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go on this lane")
	}

	prefix := t.TempDir()
	venv := filepath.Join(prefix, "venv")
	if out, err := exec.Command(py, "-m", "venv", venv).CombinedOutput(); err != nil {
		t.Fatalf("venv: %v\n%s", err, out)
	}
	sites, err := filepath.Glob(filepath.Join(venv, "lib", "python*", "site-packages"))
	if err != nil || len(sites) == 0 {
		t.Fatalf("no site-packages under %s: %v", venv, err)
	}
	if err := os.WriteFile(filepath.Join(sites[0], "zpkgmarker.py"),
		[]byte("VALUE = 'the venv package was imported'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A shebang naming nothing, on purpose: the kernel never reads it, because
	// the launcher hands this file to python as an argument.
	entry := "#!/this/interpreter/does/not/exist\n" +
		"import sys, zpkgmarker\n" +
		"print(zpkgmarker.VALUE, 'in', sys.prefix != sys.base_prefix)\n"
	if err := os.WriteFile(filepath.Join(venv, "bin", "acme"), []byte(entry), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(prefix, "bin", "acme")
	if out, err := exec.Command(goBin, "build", "-o", installed, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// ⛔ THE INTERPRETER TO RESTORE IS THE ONE THE VENV WAS BUILT WITH, read
	// before the link is broken. The first version of this test passed
	// /usr/bin/python3, which on darwin is an Xcode shim that resolves
	// `python` through `xcodebuild -find` and fails with exit 72 — a correct
	// exec of a wrong interpreter. In production ZPKG_PYTHON is the python
	// bottle's own path, never a shim, and this makes the test say the same.
	link := filepath.Join(venv, "bin", "python")
	real, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(real) {
		real = filepath.Join(filepath.Dir(link), real)
	}

	// And the venv is RELOCATED first: its python symlink is made wrong, which
	// is the case the launcher repairs, so the run exercises the repair too.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/gone/bin/python3", link); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(installed)
	cmd.Env = append(os.Environ(), "ZPKG_PYTHON="+real)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the launcher failed: %v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "the venv package was imported") {
		t.Errorf("the venv's own package was not importable: %q", got)
	}
	if !strings.Contains(got, "in True") {
		t.Errorf("sys.prefix is not the venv, so this is not venv semantics: %q", got)
	}
	if !strings.Contains(got, "in True") || strings.Contains(got, "Traceback") {
		t.Errorf("output = %q", got)
	}

	// pyvenv.cfg is NEVER written: its contents are not load-bearing, and not
	// writing it is what removes the lock, the NFS restriction and the
	// multi-host ping-pong.
	cfg := filepath.Join(venv, "pyvenv.cfg")
	before, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	old := before.ModTime().Add(-time.Hour)
	if err := os.Chtimes(cfg, old, old); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(installed).CombinedOutput(); err != nil {
		t.Fatalf("second run: %v\n%s", err, out)
	}
	after, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if after.ModTime().After(old.Add(time.Minute)) {
		t.Errorf("pyvenv.cfg was rewritten; it must never be")
	}
}
