package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultPyRunEnv covers the env-aware exec helper (happy + error).
func TestDefaultPyRunEnv(t *testing.T) {
	if err := defaultPyRunEnv(t.TempDir(), []string{"X=1"}, "/bin/echo", "hi"); err != nil {
		t.Errorf("defaultPyRunEnv echo: %v", err)
	}
	if err := defaultPyRunEnv(t.TempDir(), nil, "/no/such/cmd-xyz"); err == nil {
		t.Error("defaultPyRunEnv missing cmd: want error")
	}
}

// stubOneShotSeams makes venv/git/pip all succeed and returns the recorded
// pip args so a test can assert what would have been installed.
func stubOneShotSeams(t *testing.T) *[]string {
	t.Helper()
	pyGitInitTag = func(string, string) error { return nil }
	pyRun = func(string, string, ...string) error { return nil }
	var pip []string
	pyRunEnv = func(_ string, _ []string, _ string, a ...string) error { pip = a; return nil }
	return &pip
}

// TestPyVenvOneShot exercises the shared builder and each error branch.
func TestPyVenvOneShot(t *testing.T) {
	defer restorePy(t)()
	launcher := fakeVenvLaunch(t)

	// happy: venv flags forwarded, git tagged, pip run, launcher installed.
	stubOneShotSeams(t)
	var venvArgs []string
	pyRun = func(_, _ string, a ...string) error { venvArgs = a; return nil }
	root := t.TempDir()
	prefix := t.TempDir()
	exe := filepath.Join(prefix, "bin", "mycli")
	// pyRun is stubbed, so nothing really ran `python -m venv`; the venv it
	// would have produced is created here, since installVenvLaunch has to find
	// one to relativise.
	makeVenvBin(t, prefix)
	if err := pyVenvOneShot(root, exe, pyOneShotOpts{venvFlags: []string{"--symlinks"}, pipArgs: []string{root}, delEmptyInclude: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(venvArgs, " ") != "-m venv --symlinks "+filepath.Join(prefix, "venv") {
		t.Errorf("venv args = %v", venvArgs)
	}
	if b, _ := os.ReadFile(exe); string(b) != string(launcher) {
		t.Errorf("entry point = %q, want the launcher", b)
	}

	// venv error
	stubOneShotSeams(t)
	pyRun = func(string, string, ...string) error { return errBoomPy }
	if err := pyVenvOneShot(t.TempDir(), exe, pyOneShotOpts{}); !errors.Is(err, errBoomPy) {
		t.Errorf("venv err: %v", err)
	}

	// git error
	stubOneShotSeams(t)
	pyGitInitTag = func(string, string) error { return errBoomPy }
	if err := pyVenvOneShot(t.TempDir(), exe, pyOneShotOpts{}); !errors.Is(err, errBoomPy) {
		t.Errorf("git err: %v", err)
	}

	// pip error
	stubOneShotSeams(t)
	pyRunEnv = func(string, []string, string, ...string) error { return errBoomPy }
	if err := pyVenvOneShot(t.TempDir(), exe, pyOneShotOpts{}); !errors.Is(err, errBoomPy) {
		t.Errorf("pip err: %v", err)
	}

	// MkdirAll(buildDir) error: root is a file → root/dev.pkgx.python.build can't be made.
	stubOneShotSeams(t)
	rf := filepath.Join(t.TempDir(), "file")
	os.WriteFile(rf, []byte("x"), 0o644)
	if err := pyVenvOneShot(rf, exe, pyOneShotOpts{}); err == nil {
		t.Error("expected buildDir mkdir error")
	}

	// installVenvLaunch error: prefix's bin path blocked by a file.
	stubOneShotSeams(t)
	pf := t.TempDir()
	os.WriteFile(filepath.Join(pf, "bin"), []byte("x"), 0o644) // bin is a file → MkdirAll(bin) fails
	if err := pyVenvOneShot(t.TempDir(), filepath.Join(pf, "bin", "c"), pyOneShotOpts{}); err == nil {
		t.Error("expected an install error")
	}
}

// TestPythonVenvSh drives the .sh entry point.
func TestPythonVenvSh(t *testing.T) {
	defer restorePy(t)()
	var sb strings.Builder

	if pythonVenvSh(nil, &sb) != 2 {
		t.Error("no args → 2")
	}

	t.Run("srcroot err", func(t *testing.T) {
		defer restorePy(t)()
		os.Unsetenv("SRCROOT")
		pyGetwd = func() (string, error) { return "", errBoomPy }
		if pythonVenvSh([]string{"/p/bin/c"}, &sb) != 1 {
			t.Error("srcRoot err → 1")
		}
	})

	t.Setenv("SRCROOT", t.TempDir())
	launcher := fakeVenvLaunch(t)
	pip := stubOneShotSeams(t)
	prefix := t.TempDir()
	makeVenvBin(t, prefix)
	if c := pythonVenvSh([]string{filepath.Join(prefix, "bin", "cli")}, &sb); c != 0 {
		t.Fatalf("sh ok = %d: %q", c, sb.String())
	}
	// recorded args are pip's argv after the binary: [install, <target>, …flags]
	if pip == nil || (*pip)[0] != "install" || (*pip)[1] != os.Getenv("SRCROOT") || !strings.Contains(strings.Join(*pip, " "), "--require-virtualenv") {
		t.Errorf("pip args = %v", *pip)
	}
	b, _ := os.ReadFile(filepath.Join(prefix, "bin", "cli"))
	if string(b) != string(launcher) {
		t.Errorf("entry point = %q, want the launcher", b)
	}

	// oneShot error
	pyRun = func(string, string, ...string) error { return errBoomPy }
	if pythonVenvSh([]string{filepath.Join(prefix, "bin", "cli")}, &sb) != 1 {
		t.Error("oneShot err → 1")
	}
}

// TestPythonVenvPy drives the .py entry point incl. arg parsing.
func TestPythonVenvPy(t *testing.T) {
	defer restorePy(t)()
	var sb strings.Builder

	if pythonVenvPy([]string{"--no-binary"}, &sb) != 2 {
		t.Error("no exe → 2")
	}

	t.Run("srcroot err", func(t *testing.T) {
		defer restorePy(t)()
		os.Unsetenv("SRCROOT")
		pyGetwd = func() (string, error) { return "", errBoomPy }
		if pythonVenvPy([]string{"/p/bin/c"}, &sb) != 1 {
			t.Error("srcRoot err → 1")
		}
	})

	root := t.TempDir()
	t.Setenv("SRCROOT", root)
	launcher := fakeVenvLaunch(t)
	prefix := t.TempDir()
	exe := filepath.Join(prefix, "bin", "app")
	makeVenvBin(t, prefix)

	// all options: --extra a b, --extra=c, --requirements-txt, --no-binary
	pip := stubOneShotSeams(t)
	var venvArgs []string
	pyRun = func(_, _ string, a ...string) error { venvArgs = a; return nil }
	if c := pythonVenvPy([]string{exe, "--extra", "a", "b", "--extra=c", "--requirements-txt", "--no-binary"}, &sb); c != 0 {
		t.Fatalf("py ok = %d: %q", c, sb.String())
	}
	joined := strings.Join(*pip, " ")
	if !strings.Contains(joined, root+"[a,b,c]") || !strings.Contains(joined, "-r "+filepath.Join(root, "requirements.txt")) || !strings.Contains(joined, "--no-binary :all:") {
		t.Errorf("py pip args = %v", *pip)
	}
	if !strings.Contains(strings.Join(venvArgs, " "), "--symlinks") {
		t.Errorf("py venv args = %v", venvArgs)
	}
	b, _ := os.ReadFile(exe)
	if string(b) != string(launcher) {
		t.Errorf("py entry point = %q, want the launcher", b)
	}

	// no extras → plain install target = root
	pip = stubOneShotSeams(t)
	if pythonVenvPy([]string{filepath.Join(prefix, "bin", "app2")}, &sb) != 0 {
		t.Fatal("py plain")
	}
	if (*pip)[1] != root {
		t.Errorf("plain install name = %q", (*pip)[1])
	}

	// oneShot error
	pyRun = func(string, string, ...string) error { return errBoomPy }
	if pythonVenvPy([]string{exe}, &sb) != 1 {
		t.Error("oneShot err → 1")
	}
}

// TestPythonVenvStubber covers the standalone stubber shim.
func TestPythonVenvStubber(t *testing.T) {
	defer restorePy(t)()
	var sb strings.Builder

	os.Unsetenv("VIRTUAL_ENV")
	if pythonVenvStubber([]string{"c"}, &sb) != 1 || !strings.Contains(sb.String(), "VIRTUAL_ENV not set") {
		t.Errorf("no VIRTUAL_ENV: %q", sb.String())
	}

	launcher := fakeVenvLaunch(t)
	prefix := t.TempDir()
	venv, _ := makeVenvBin(t, prefix)
	t.Setenv("VIRTUAL_ENV", venv)
	sb.Reset()
	if pythonVenvStubber(nil, &sb) != 2 {
		t.Error("no cmd → 2")
	}
	// happy: the launcher is installed at prefix/bin/c
	if pythonVenvStubber([]string{"c"}, &sb) != 0 {
		t.Fatalf("stubber ok: %q", sb.String())
	}
	if b, err := os.ReadFile(filepath.Join(prefix, "bin", "c")); err != nil || string(b) != string(launcher) {
		t.Errorf("entry point = %q, %v — want the launcher", b, err)
	}

	// install error: bin path blocked by a file.
	pf := t.TempDir()
	os.WriteFile(filepath.Join(pf, "bin"), []byte("x"), 0o644)
	t.Setenv("VIRTUAL_ENV", filepath.Join(pf, "venv"))
	if pythonVenvStubber([]string{"c"}, &sb) != 1 {
		t.Error("install err → 1")
	}
}

// TestPyDeleteEmptyDirs covers the cleanup helper's branches.
func TestPyDeleteEmptyDirs(t *testing.T) {
	// missing dir → no-op (ReadDir error)
	pyDeleteEmptyDirs(filepath.Join(t.TempDir(), "nope"))

	// dir with a file → kept
	d1 := t.TempDir()
	os.WriteFile(filepath.Join(d1, "f"), []byte("x"), 0o644)
	pyDeleteEmptyDirs(d1)
	if _, err := os.Stat(d1); err != nil {
		t.Error("dir with file should be kept")
	}

	// dir of only-empty subdirs → removed (recurses then removes)
	d2 := filepath.Join(t.TempDir(), "include")
	os.MkdirAll(filepath.Join(d2, "sub"), 0o755)
	pyDeleteEmptyDirs(d2)
	if _, err := os.Stat(d2); !os.IsNotExist(err) {
		t.Errorf("empty-subtree dir should be removed, err=%v", err)
	}
}

// TestPythonVenvMultiCallDispatch proves main() routes each old-family name.
func TestPythonVenvMultiCallDispatch(t *testing.T) {
	oldExit, oldArgs := osExit, os.Args
	defer func() { osExit, os.Args = oldExit, oldArgs }()
	got := -1
	osExit = func(c int) { got = c }
	for _, name := range []string{"python-venv.sh", "python-venv.py", "python-venv-stubber.sh"} {
		got = -1
		os.Args = []string{"/build/libexec/" + name} // no args → usage/error exit
		main()
		if got == -1 {
			t.Errorf("%s: main did not dispatch", name)
		}
	}
}
