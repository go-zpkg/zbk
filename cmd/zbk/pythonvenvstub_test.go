package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ⛔⛔ THIS FILE IS THE FIRST TEST THE LAUNCHER HAS EVER HAD, and its absence
// is why the launcher drifted. It was shipped as a verbatim copy of brewkit's,
// upstream rewrote it around a lock and an idempotence check, and nothing here
// noticed for as long as that took (go-zpkg/zbk#431). A file embedded with
// //go:embed is still code; it was simply code nobody ran.
//
// The launcher is exercised by RUNNING it against a venv-shaped tree, because
// every property that matters is a property of what it does to files.

// stubTree builds the shape `bkpyvenv seal` leaves behind: the launcher at
// <root>/bin/<cmd>, and a venv beside it whose pyvenv.cfg, python symlink and
// console-script shebangs all name somewhere this tree is not.
//
// The stale paths are deliberately absurd: a venv that has been RELOCATED is
// the whole case, and one whose recorded interpreter still exists would let a
// launcher that checks nothing pass.
func stubTree(t *testing.T, cmd string) (root string, venv string) {
	t.Helper()
	root = t.TempDir()
	venv = filepath.Join(root, "venv")
	binDir := filepath.Join(venv, "bin")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// `version` and `prompt` are the control for preservation: CPython writes
	// them (Lib/venv/__init__.py:233-235) and the launcher does not own them,
	// so a launcher that rebuilds this file from its own three keys loses them.
	cfg := "home = /gone/bin\n" +
		"include-system-site-packages = false\n" +
		"version = 3.12.1\n" +
		"prompt = 'acme'\n" +
		"executable = /gone/bin/python3\n"
	if err := os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// A console script as pip writes one, with `python3` rather than `python`:
	// the shape the old launcher's `endswith(b"python")` silently skipped.
	script := "#!/gone/bin/python3\nprint('entry point ran')\n"
	if err := os.WriteFile(filepath.Join(binDir, cmd), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/gone/bin/python3", filepath.Join(binDir, "python")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", cmd), pythonVenvStub, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, venv
}

// python3 is the interpreter under test. A lane without one cannot run the
// launcher at all; TestTheLauncherKeepsItsLockAndItsIdempotence covers those.
func python3(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 on this lane")
	}
	return p
}

// runStub invokes the launcher the way the installed shebang does: the packaged
// interpreter, with the launcher's path as the script.
func runStub(t *testing.T, py, root, cmd string) (string, error) {
	t.Helper()
	out, err := exec.Command(py, filepath.Join(root, "bin", cmd)).CombinedOutput()
	return string(out), err
}

func TestTheLauncherRepairsARelocatedVenvAndExecs(t *testing.T) {
	py := python3(t)
	root, venv := stubTree(t, "acme")

	out, err := runStub(t, py, root, "acme")
	if err != nil {
		t.Fatalf("launcher failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "entry point ran") {
		t.Errorf("the real entry point was not exec'd: %q", out)
	}

	cfg, err := os.ReadFile(filepath.Join(venv, "pyvenv.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(cfg)
	if strings.Contains(got, "/gone/bin") {
		t.Errorf("pyvenv.cfg still names the old location:\n%s", got)
	}
	// ⛔ THE KEYS THE LAUNCHER DOES NOT OWN SURVIVE. The copy this replaces
	// rewrote this file from three keys on every single invocation, so
	// `version`, `prompt` and `command` were discarded each time a packaged
	// tool was run.
	for _, want := range []string{"version = 3.12.1", "prompt = 'acme'"} {
		if !strings.Contains(got, want) {
			t.Errorf("pyvenv.cfg lost %q:\n%s", want, got)
		}
	}

	// The shebang pip wrote with `python3` is rewritten — the old launcher
	// matched only a shebang ending exactly in "python" and left this one
	// pointing at a path that does not exist.
	script, err := os.ReadFile(filepath.Join(venv, "bin", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	// Resolved, because the launcher locates the venv from
	// os.path.realpath(__file__) and macOS hands a test /var, which is a
	// symlink to /private/var. Comparing the unresolved path would fail on
	// darwin for a launcher that is behaving correctly.
	realVenv, err := filepath.EvalSymlinks(venv)
	if err != nil {
		t.Fatal(err)
	}
	wantLine := "#!" + filepath.Join(realVenv, "bin", "python") + "\n"
	if !strings.HasPrefix(string(script), wantLine) {
		t.Errorf("shebang = %q, want %q", strings.SplitN(string(script), "\n", 2)[0], wantLine)
	}

	link, err := os.Readlink(filepath.Join(venv, "bin", "python"))
	if err != nil {
		t.Fatalf("python symlink: %v", err)
	}
	if link == "/gone/bin/python3" {
		t.Error("the python symlink still points at the old interpreter")
	}
}

// ⛔⛔ A CORRECT VENV IS NOT WRITTEN AGAIN, and that is not an optimisation.
// The launcher runs on EVERY invocation of every packaged tool, so a launcher
// that rewrites unconditionally holds its repair window open permanently
// rather than once per relocation — which is the race this replaces.
func TestTheLauncherWritesNothingWhenTheVenvIsCurrent(t *testing.T) {
	py := python3(t)
	root, venv := stubTree(t, "acme")
	if out, err := runStub(t, py, root, "acme"); err != nil {
		t.Fatalf("first run failed: %v\n%s", err, out)
	}

	cfgPath := filepath.Join(venv, "pyvenv.cfg")
	scriptPath := filepath.Join(venv, "bin", "acme")
	before := make(map[string]os.FileInfo)
	for _, p := range []string{cfgPath, scriptPath} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		before[p] = st
	}

	if out, err := runStub(t, py, root, "acme"); err != nil {
		t.Fatalf("second run failed: %v\n%s", err, out)
	}
	for p, st := range before {
		now, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !now.ModTime().Equal(st.ModTime()) {
			t.Errorf("%s was rewritten although the venv was already current", filepath.Base(p))
		}
	}
}

// And the consequence of that: once a venv is current, the tree need not be
// writable at all. The old launcher could not run a correct, read-only venv.
func TestTheLauncherRunsACurrentVenvOnAReadOnlyTree(t *testing.T) {
	py := python3(t)
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	root, venv := stubTree(t, "acme")
	if out, err := runStub(t, py, root, "acme"); err != nil {
		t.Fatalf("first run failed: %v\n%s", err, out)
	}

	binDir := filepath.Join(venv, "bin")
	if err := os.Chmod(binDir, 0o555); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.Chmod(binDir, 0o755) })
	if err := os.Chmod(venv, 0o555); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.Chmod(venv, 0o755) })

	out, err := runStub(t, py, root, "acme")
	if err != nil {
		t.Fatalf("a current venv must run with nothing writable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "entry point ran") {
		t.Errorf("the entry point did not run: %q", out)
	}
}

// A venv with no such entry point is a stated error, not a traceback.
func TestTheLauncherSaysWhenThereIsNoSuchEntryPoint(t *testing.T) {
	py := python3(t)
	root, venv := stubTree(t, "acme")
	if err := os.Remove(filepath.Join(venv, "bin", "acme")); err != nil {
		t.Fatal(err)
	}
	out, err := runStub(t, py, root, "acme")
	if err == nil {
		t.Fatal("want a failure")
	}
	if !strings.Contains(out, "no entry point named acme") {
		t.Errorf("want a stated error, got %q", out)
	}
	if strings.Contains(out, "Traceback") {
		t.Errorf("a missing entry point must not be a traceback: %q", out)
	}
}

// ⛔ THE STRUCTURAL WITNESS, so a lane with no python3 still refuses the
// regression this file exists to prevent. The three properties above are each
// one call, and losing any of them is silent: the launcher keeps working and
// stops being safe.
func TestTheLauncherKeepsItsLockAndItsIdempotence(t *testing.T) {
	src := string(pythonVenvStub)
	for what, token := range map[string]string{
		"an exclusive lock while repairing": "fcntl.flock(fd, fcntl.LOCK_EX)",
		"a check before writing anything":   "if not venv_is_current():",
		"an atomic shebang replacement":     "os.replace(tmp, path)",
	} {
		if !strings.Contains(src, token) {
			t.Errorf("the launcher no longer has %s (%q)", what, token)
		}
	}
	// The shape it must never go back to: an unconditional in-place rewrite.
	for _, gone := range []string{"f.truncate()", "f.seek(0)"} {
		if strings.Contains(src, gone) {
			t.Errorf("the launcher rewrites in place again (%q)", gone)
		}
	}
}
