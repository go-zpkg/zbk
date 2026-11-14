package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// tree builds what `zpkvenv seal` leaves behind: the launcher at
// <prefix>/bin/<name>, and a venv beside it whose bin/python is a RELATIVE
// symlink into a sibling "store" — the shape seal will write, and the reason
// this launcher needs no repair.
func tree(t *testing.T, name string) (prefix, venvBin string) {
	t.Helper()
	root := t.TempDir()
	prefix = filepath.Join(root, "acme.org", "v1.0-habcdef")
	venvBin = filepath.Join(prefix, "venv", "bin")
	pythonBin := filepath.Join(root, "python.org", "v3.12.1-h012345", "bin")

	for _, d := range []string{filepath.Join(prefix, "bin"), venvBin, pythonBin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pythonBin, "python3"), []byte("interpreter\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// ../../../../python.org/<ver>/bin/python3 — bin → venv → v1.0 → acme.org
	// → the store root. The same four levels @loader_path/../../.. climbs for
	// an rpath.
	rel := filepath.Join("..", "..", "..", "..", "python.org", "v3.12.1-h012345", "bin", "python3")
	if err := os.Symlink(rel, filepath.Join(venvBin, "python")); err != nil {
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

func at(t *testing.T, prefix, name string) {
	t.Helper()
	was := osExecutable
	osExecutable = func() (string, error) { return filepath.Join(prefix, "bin", name), nil }
	t.Cleanup(func() { osExecutable = was })
}

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

// ⛔⛔ IT WRITES NOTHING AT ALL, and that is the property the design rests on:
// no write means no lock, which means the NFS restriction, the race and the
// multi-host ping-pong have no place left to occur. Asserted by refusing the
// syscalls rather than by comparing timestamps, because an absence of change
// and an absence of attempt are different claims.
func TestItWritesNothing(t *testing.T) {
	prefix, venvBin := tree(t, "acme")
	at(t, prefix, "acme")
	captureExec(t)

	// ⛔ COMPARED BY CONTENT, NOT BY TIMESTAMP, and that is not fussiness: the
	// first version of this test backdated each entry with os.Chtimes and
	// compared mtimes afterwards. os.Chtimes FOLLOWS a symlink, so it
	// backdated the interpreter the link points at and then compared the
	// link — reporting "python was written" about a launcher that had written
	// nothing. A content comparison is exact and has no granularity.
	snap := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		entries, err := os.ReadDir(venvBin)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			p := filepath.Join(venvBin, e.Name())
			fi, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(p)
				if err != nil {
					t.Fatal(err)
				}
				out[e.Name()] = "-> " + target
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = string(b)
		}
		return out
	}

	before := snap()

	var errb bytes.Buffer
	if code := run([]string{filepath.Join(prefix, "bin", "acme")}, &errb); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}

	after := snap()
	if len(after) != len(before) {
		// A temporary file in a packaged tree is a write by another name.
		t.Errorf("the venv's bin gained or lost entries: %d -> %d", len(before), len(after))
	}
	for name, was := range before {
		if got, ok := after[name]; !ok {
			t.Errorf("%s disappeared", name)
		} else if got != was {
			t.Errorf("%s changed:\n before %q\n after  %q", name, was, got)
		}
	}
}

// A missing entry point and a missing interpreter are DIFFERENT errors with
// different causes, and `exec: no such file or directory` cannot tell them
// apart — so both are checked by name before the exec.
func TestItNamesWhichHalfIsMissing(t *testing.T) {
	t.Run("no entry point", func(t *testing.T) {
		prefix, venvBin := tree(t, "acme")
		if err := os.Remove(filepath.Join(venvBin, "acme")); err != nil {
			t.Fatal(err)
		}
		at(t, prefix, "acme")
		captureExec(t)
		var errb bytes.Buffer
		if code := run([]string{"x"}, &errb); code != 127 ||
			!strings.Contains(errb.String(), "no entry point named acme") {
			t.Errorf("code = %d, stderr = %q", code, errb.String())
		}
	})
	t.Run("no interpreter", func(t *testing.T) {
		prefix, venvBin := tree(t, "acme")
		if err := os.Remove(filepath.Join(venvBin, "python")); err != nil {
			t.Fatal(err)
		}
		at(t, prefix, "acme")
		captureExec(t)
		var errb bytes.Buffer
		if code := run([]string{"x"}, &errb); code != 127 ||
			!strings.Contains(errb.String(), "no interpreter at bin/python") {
			t.Errorf("code = %d, stderr = %q", code, errb.String())
		}
	})
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
// CPython itself created, importing a module really installed into it, with
// bin/python a RELATIVE symlink — and the venv MOVED after it was made, which
// is what an absolute link would not survive and this one does.
//
// Everything above drives run() with seams. This one answers the question the
// seams cannot: does exec'ing the interpreter with the entry point as an
// argument actually give that script the venv's packages? Measurement said it
// should — a venv resolves from where sys.executable is — and a design decided
// from a measurement deserves a test that repeats it.
func TestTheBuiltLauncherRunsARealRelocatedVenv(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 on this lane")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go on this lane")
	}

	root := t.TempDir()
	made := filepath.Join(root, "made")
	venv := filepath.Join(made, "venv")
	if err := os.MkdirAll(made, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(py, "-m", "venv", venv).CombinedOutput(); err != nil {
		t.Fatalf("venv: %v\n%s", err, out)
	}
	sites, err := filepath.Glob(filepath.Join(venv, "lib", "python*", "site-packages"))
	if err != nil || len(sites) == 0 {
		t.Fatalf("no site-packages under %s: %v", venv, err)
	}
	if err := os.WriteFile(filepath.Join(sites[0], "zpkmarker.py"),
		[]byte("VALUE = 'the venv package was imported'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A shebang naming nothing, on purpose: the kernel never reads it, because
	// the launcher hands this file to python as an argument.
	entry := "#!/this/interpreter/does/not/exist\n" +
		"import sys, zpkmarker\n" +
		"print(zpkmarker.VALUE, 'in', sys.prefix != sys.base_prefix)\n"
	if err := os.WriteFile(filepath.Join(venv, "bin", "acme"), []byte(entry), 0o755); err != nil {
		t.Fatal(err)
	}

	// The interpreter the venv was built with, copied into a sibling "store"
	// directory so bin/python can point at it RELATIVELY. Reading it before
	// anything is moved: the first version of this test passed
	// /usr/bin/python3, which on darwin is an Xcode shim that resolves
	// `python` through `xcodebuild -find` and fails with exit 72 — a correct
	// exec of a wrong interpreter.
	link := filepath.Join(venv, "bin", "python")
	real, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}

	// Now lay it out the way the store does, and MOVE it there: <store>/<proj>/<ver>.
	store := filepath.Join(root, "store")
	prefix := filepath.Join(store, "acme.org", "v1.0-habcdef")
	pyPrefix := filepath.Join(store, "python.org", "v3-h012345", "bin")
	if err := os.MkdirAll(filepath.Dir(prefix), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pyPrefix, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(pyPrefix, "python3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(made, prefix); err != nil {
		t.Fatal(err)
	}
	// The relative link seal will write, replacing the absolute one venv made.
	if err := os.Remove(filepath.Join(prefix, "venv", "bin", "python")); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join("..", "..", "..", "..", "python.org", "v3-h012345", "bin", "python3")
	if err := os.Symlink(rel, filepath.Join(prefix, "venv", "bin", "python")); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(prefix, "bin", "acme")
	if out, err := exec.Command(goBin, "build", "-o", installed, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	out, err := exec.Command(installed).CombinedOutput()
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
	if strings.Contains(got, "Traceback") {
		t.Errorf("output = %q", got)
	}

	// ⛔ AND THE WHOLE STORE IS MOVED AGAIN, which is what an absolute symlink
	// cannot survive and a relative one can. No repair runs, because there is
	// no repair: the link is still correct at the new location.
	moved := filepath.Join(root, "moved")
	if err := os.Rename(store, moved); err != nil {
		t.Fatal(err)
	}
	again := filepath.Join(moved, "acme.org", "v1.0-habcdef", "bin", "acme")
	out, err = exec.Command(again).CombinedOutput()
	if err != nil {
		t.Fatalf("after the store moved: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "the venv package was imported") {
		t.Errorf("after the store moved: %q", out)
	}
}
