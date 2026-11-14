package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

var errBoomPy = errors.New("boom")

// restorePy snapshots every zpkvenv package seam and returns a func that
// restores them, so a subtest can override freely: `defer restorePy(t)()`.
func restorePy(t *testing.T) func() {
	t.Helper()
	getwd, run, output, runEnv := pyGetwd, pyRun, pyOutput, pyRunEnv
	plainInit, worktree, commit, head, createTag := ggPlainInit, ggWorktree, ggCommit, ggHead, ggCreateTag
	gitInitTag, now, glob, goos := pyGitInitTag, pyNow, pyGlob, pyGOOS
	lookPath, relink, executable, goarch := pyLookPath, pyRelink, pyExecutable, pyGOARCH
	readlink := pyReadlink
	return func() {
		pyGetwd, pyRun, pyOutput, pyRunEnv = getwd, run, output, runEnv
		ggPlainInit, ggWorktree, ggCommit, ggHead, ggCreateTag = plainInit, worktree, commit, head, createTag
		pyGitInitTag, pyNow, pyGlob, pyGOOS = gitInitTag, now, glob, goos
		pyLookPath, pyRelink = lookPath, relink
		pyExecutable, pyGOARCH, pyReadlink = executable, goarch, readlink
	}
}

// writeSdist builds a minimal gzip-compressed tar at path with a single regular
// file entry, standing in for a python sdist (wrapped under a top-level dir).
func writeSdist(t *testing.T, path, name, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDefaultPyRunOutput covers the real exec helpers (happy + error) via a
// binary present on both Linux and macOS.
func TestDefaultPyRunOutput(t *testing.T) {
	if err := defaultPyRun(t.TempDir(), "/bin/echo", "hi"); err != nil {
		t.Errorf("defaultPyRun echo: %v", err)
	}
	if err := defaultPyRun(t.TempDir(), "/no/such/cmd-xyz"); err == nil {
		t.Error("defaultPyRun missing cmd: want error")
	}
	out, err := defaultPyOutput(t.TempDir(), "/bin/echo", "hey")
	if err != nil || strings.TrimSpace(out) != "hey" {
		t.Errorf("defaultPyOutput = %q, %v", out, err)
	}
	if _, err := defaultPyOutput(t.TempDir(), "/no/such/cmd-xyz"); err == nil {
		t.Error("defaultPyOutput missing cmd: want error")
	}
}

// TestSrcRoot covers the SRCROOT-set, getwd-fallback and getwd-error branches.
func TestSrcRoot(t *testing.T) {
	defer restorePy(t)()
	t.Setenv("SRCROOT", "/from/env")
	if got, _ := srcRoot(); got != "/from/env" {
		t.Errorf("srcRoot env = %q", got)
	}
	os.Unsetenv("SRCROOT")
	pyGetwd = func() (string, error) { return "/cwd", nil }
	if got, _ := srcRoot(); got != "/cwd" {
		t.Errorf("srcRoot cwd = %q", got)
	}
	pyGetwd = func() (string, error) { return "", errBoomPy }
	if _, err := srcRoot(); !errors.Is(err, errBoomPy) {
		t.Errorf("srcRoot err = %v", err)
	}
}

// TestZpkvenvDispatch drives the top-level argument parsing and every exit code.
func TestZpkvenvDispatch(t *testing.T) {
	defer restorePy(t)()
	// keep every subtest hermetic: SRCROOT points at a temp tree, git-init and
	// process spawns are stubbed to succeed unless a case overrides them.
	pyGitInitTag = func(string, string) error { return nil }
	pyRun = func(string, string, ...string) error { return nil }
	pyOutput = func(string, string, ...string) (string, error) { return "Python 3.12.4\n", nil }

	var sb strings.Builder
	code := func(args ...string) int { sb.Reset(); return zpkvenv(args, &sb) }

	if code() != 2 {
		t.Error("no args should be usage/2")
	}
	if code("stage") != 2 {
		t.Error("stage without prefix should be 2")
	}
	if code("stage", "--engine=poetry") != 2 {
		t.Error("engine-only, no prefix should be 2")
	}
	if code("stage", "/p") != 2 || !strings.Contains(sb.String(), "missing <version>") {
		t.Errorf("stage without version should be 2: %q", sb.String())
	}
	if code("bogus", "/p") != 2 || !strings.Contains(sb.String(), "unknown subcommand") {
		t.Errorf("unknown subcommand: %q", sb.String())
	}

	t.Run("srcroot error", func(t *testing.T) {
		defer restorePy(t)()
		os.Unsetenv("SRCROOT")
		pyGetwd = func() (string, error) { return "", errBoomPy }
		if zpkvenv([]string{"stage", "/p", "1.0"}, &sb) != 1 {
			t.Error("srcRoot error should be 1")
		}
	})

	launcher := fakeVenvLaunch(t)
	prefix := t.TempDir()
	t.Setenv("SRCROOT", t.TempDir())
	if c := code("stage", prefix, "1.2.3"); c != 0 {
		t.Errorf("stage ok = %d: %q", c, sb.String())
	}
	makeVenvBin(t, prefix)
	if c := code("seal", prefix, "streamlink"); c != 0 {
		t.Errorf("seal ok = %d: %q", c, sb.String())
	}
	// ⛔⛔ AND IT IS A BINARY, NOT A SHEBANG. What this used to assert was
	// `#!/usr/bin/env -S zpkx python@3.12` — a line that had already shipped
	// for months naming `pkgx`, upstream's runtime, which we do not publish;
	// that `env` is absent from a FROM-scratch image; and that `env -S` is
	// absent from busybox. The installed entry point now has no interpreter of
	// its own to go looking for (go-zpkg/zpkb#435).
	got, err := os.ReadFile(filepath.Join(prefix, "bin", "streamlink"))
	if err != nil {
		t.Fatalf("read entry point: %v", err)
	}
	if string(got) != string(launcher) {
		t.Errorf("entry point = %q, want the launcher binary", got)
	}
	if strings.HasPrefix(string(got), "#!") {
		t.Error("the entry point is still a script")
	}

	// stage error propagation (git init fails)
	pyGitInitTag = func(string, string) error { return errBoomPy }
	if code("stage", prefix, "1.0") != 1 {
		t.Error("stage error should be 1")
	}
	pyGitInitTag = func(string, string) error { return nil }
	// seal error propagation: the launcher is not installable.
	pyLookPath = func(string) (string, error) { return "", errBoomPy }
	if code("seal", prefix, "x") != 1 {
		t.Error("seal error should be 1")
	}
}

// TestPyStage covers the git-skip, poetry (both config calls + errors) and pip
// (--copies on/off) paths of stage.
func TestPyStage(t *testing.T) {
	defer restorePy(t)()

	// .git present → git init skipped; pip engine; Linux → --copies present.
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, ".git"), 0o755)
	var gotArgs []string
	pyRun = func(_, _ string, a ...string) error { gotArgs = a; return nil }
	pyGitInitTag = func(string, string) error { t.Fatal("git init must be skipped when .git exists"); return nil }
	pyGOOS = "linux"
	if err := pyStage(root, "/prefix", "1.0", "pip"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotArgs, " ") != "-m venv --copies "+filepath.Join("/prefix", "venv") {
		t.Errorf("linux venv args = %v", gotArgs)
	}

	// darwin → no --copies
	pyGOOS = "darwin"
	if err := pyStage(root, "/prefix", "1.0", "pip"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotArgs, " ") != "-m venv "+filepath.Join("/prefix", "venv") {
		t.Errorf("darwin venv args = %v", gotArgs)
	}

	// no .git → git init invoked; and its error propagates
	root2 := t.TempDir()
	called := false
	pyGitInitTag = func(r, v string) error { called = true; return nil }
	if err := pyStage(root2, "/p", "2.0", "pip"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("git init should run when .git absent")
	}
	pyGitInitTag = func(string, string) error { return errBoomPy }
	if err := pyStage(root2, "/p", "2.0", "pip"); !errors.Is(err, errBoomPy) {
		t.Errorf("git init error not propagated: %v", err)
	}

	// poetry engine: two config calls; error on the first, then on the second.
	pyGitInitTag = func(string, string) error { return nil }
	var calls int
	pyRun = func(_, _ string, a ...string) error { calls++; return nil }
	if err := pyStage(root, "/p", "1.0", "poetry"); err != nil || calls != 2 {
		t.Errorf("poetry stage calls=%d err=%v", calls, err)
	}
	pyRun = func(_, _ string, a ...string) error {
		if a[1] == "virtualenvs.create" {
			return errBoomPy
		}
		return nil
	}
	if err := pyStage(root, "/p", "1.0", "poetry"); !errors.Is(err, errBoomPy) {
		t.Errorf("poetry first-config error: %v", err)
	}
	pyRun = func(_, _ string, a ...string) error {
		if a[1] == "virtualenvs.in-project" {
			return errBoomPy
		}
		return nil
	}
	if err := pyStage(root, "/p", "1.0", "poetry"); !errors.Is(err, errBoomPy) {
		t.Errorf("poetry second-config error: %v", err)
	}
}

// TestPySealPip covers the pip path, which now installs the launcher and
// nothing else (the poetry path is exercised in TestPySealPoetry).
func TestPySealPip(t *testing.T) {
	defer restorePy(t)()
	launcher := fakeVenvLaunch(t)

	// ⛔ AND IT MUST NOT EXEC PYTHON AT ALL ANY MORE. It used to, on every
	// seal, only to read a version for the shebang of a script launcher. That
	// script is gone, so the exec — and the two error branches it brought with
	// it — have no caller left. A seam that fails the test if it is reached is
	// how this stays true: the next person to add `python --version` back here
	// has to justify it.
	pyOutput = func(string, string, ...string) (string, error) {
		t.Error("pySeal ran python for the pip engine, which no longer needs its version")
		return "", errBoomPy
	}

	// install error: prefix is a regular file, so <file>/bin cannot be made.
	file := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(file, []byte("x"), 0o644)
	if err := pySeal(t.TempDir(), file, "pip", []string{"x"}); err == nil {
		t.Error("expected an install error under a file prefix")
	}

	// happy: both names get the launcher, and the venv's absolute interpreter
	// link comes out relative.
	prefix := t.TempDir()
	makeVenvBin(t, prefix)
	if err := pySeal(t.TempDir(), prefix, "pip", []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "b"} {
		b, _ := os.ReadFile(filepath.Join(prefix, "bin", n))
		if string(b) != string(launcher) {
			t.Errorf("%s = %q, want the launcher", n, b)
		}
	}
	target, err := os.Readlink(filepath.Join(prefix, "venv", "bin", "python"))
	if err != nil || filepath.IsAbs(target) {
		t.Errorf("venv python = %q, %v — want a relative link", target, err)
	}
}

// TestPySealPoetry covers the poetry seal path end-to-end plus its error branches.
func TestPySealPoetry(t *testing.T) {
	defer restorePy(t)()
	fakeVenvLaunch(t)

	// The python version is read for the poetry path alone — it names the
	// site-packages directory the sdist is unpacked into — so its two failures
	// are asserted here, where the call actually lives.
	pyOutput = func(string, string, ...string) (string, error) { return "", errBoomPy }
	if err := pySeal(t.TempDir(), t.TempDir(), "poetry", []string{"x"}); !errors.Is(err, errBoomPy) {
		t.Errorf("version error: %v", err)
	}
	pyOutput = func(string, string, ...string) (string, error) { return "not a version", nil }
	if err := pySeal(t.TempDir(), t.TempDir(), "poetry", []string{"x"}); err == nil || !strings.Contains(err.Error(), "cannot parse") {
		t.Errorf("parse error: %v", err)
	}

	pyOutput = func(string, string, ...string) (string, error) { return "Python 3.12.1", nil }

	// poetry build error
	pyRun = func(string, string, ...string) error { return errBoomPy }
	if err := pySeal(t.TempDir(), t.TempDir(), "poetry", []string{"x"}); !errors.Is(err, errBoomPy) {
		t.Errorf("poetry build error: %v", err)
	}

	// glob error (bad pattern)
	pyRun = func(string, string, ...string) error { return nil }
	pyGlob = func(string) ([]string, error) { return nil, errBoomPy }
	if err := pySeal(t.TempDir(), t.TempDir(), "poetry", []string{"x"}); !errors.Is(err, errBoomPy) {
		t.Errorf("glob error: %v", err)
	}
	pyGlob = filepath.Glob

	// no sdist produced
	root := t.TempDir()
	if err := pySeal(root, t.TempDir(), "poetry", []string{"x"}); err == nil || !strings.Contains(err.Error(), "no sdist") {
		t.Errorf("no-sdist error: %v", err)
	}

	// happy: a real sdist tarball → extracted, .venv moved to prefix/venv.
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "dist"), 0o755)
	os.MkdirAll(filepath.Join(root, ".venv", "lib", "python3.12", "site-packages"), 0o755)
	// poetry's in-project .venv carries the same absolute interpreter link, and
	// it is moved to prefix/venv before the launcher is installed.
	os.MkdirAll(filepath.Join(root, ".venv", "bin"), 0o755)
	if err := os.Symlink(filepath.Join(t.TempDir(), "python3"), filepath.Join(root, ".venv", "bin", "python")); err != nil {
		t.Fatal(err)
	}
	writeSdist(t, filepath.Join(root, "dist", "pkg-1.0.tar.gz"), "pkg-1.0/mod.py", "print(1)\n")
	prefix := t.TempDir()
	if err := pySeal(root, prefix, "poetry", []string{"cli"}); err == nil {
		t.Error("a venv whose relativised interpreter does not exist must be refused")
	}
	// and again with an interpreter that is really there
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "dist"), 0o755)
	os.MkdirAll(filepath.Join(root, ".venv", "lib", "python3.12", "site-packages"), 0o755)
	os.MkdirAll(filepath.Join(root, ".venv", "bin"), 0o755)
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, "python3"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(store, "python3"), filepath.Join(root, ".venv", "bin", "python")); err != nil {
		t.Fatal(err)
	}
	writeSdist(t, filepath.Join(root, "dist", "pkg-1.0.tar.gz"), "pkg-1.0/mod.py", "print(1)\n")
	prefix = t.TempDir()
	if err := pySeal(root, prefix, "poetry", []string{"cli"}); err != nil {
		t.Fatalf("poetry seal: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(prefix, "venv", "lib", "python3.12", "site-packages", "mod.py")); err != nil || string(b) != "print(1)\n" {
		t.Errorf("extracted module = %q, %v", b, err)
	}

	// extract error: a corrupt (non-gzip) sdist.
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "dist"), 0o755)
	os.WriteFile(filepath.Join(root, "dist", "bad.tar.gz"), []byte("not gzip"), 0o644)
	if err := pySeal(root, t.TempDir(), "poetry", []string{"x"}); err == nil {
		t.Error("expected extract error on corrupt sdist")
	}

	// MkdirAll(prefix) error: prefix is under a regular file.
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "dist"), 0o755)
	os.MkdirAll(filepath.Join(root, ".venv"), 0o755)
	writeSdist(t, filepath.Join(root, "dist", "p.tar.gz"), "p/x", "y")
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, []byte("x"), 0o644)
	if err := pySeal(root, filepath.Join(f, "sub"), "poetry", []string{"x"}); err == nil {
		t.Error("expected MkdirAll(prefix) error")
	}

	// Rename error: destination prefix/venv already exists as a non-empty dir
	// while .venv is a dir → cross-name rename over existing populated dir fails.
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "dist"), 0o755)
	os.MkdirAll(filepath.Join(root, ".venv"), 0o755)
	writeSdist(t, filepath.Join(root, "dist", "p.tar.gz"), "p/x", "y")
	prefix = t.TempDir()
	os.MkdirAll(filepath.Join(prefix, "venv", "occupied"), 0o755)
	os.WriteFile(filepath.Join(prefix, "venv", "occupied", "f"), []byte("x"), 0o644)
	if err := pySeal(root, prefix, "poetry", []string{"x"}); err == nil {
		t.Error("expected Rename error over populated destination")
	}
}

// TestDefaultGitInitTag exercises the real go-git path plus each injected error.
func TestDefaultGitInitTag(t *testing.T) {
	defer restorePy(t)()
	pyNow = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	// happy path with real go-git in a temp dir
	root := t.TempDir()
	if err := defaultGitInitTag(root, "1.2.3"); err != nil {
		t.Fatalf("real git init: %v", err)
	}
	repo, err := gogit.PlainOpen(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := repo.Tag("1.2.3"); err != nil {
		t.Errorf("tag 1.2.3 missing: %v", err)
	}

	// each fallible go-git step returns an injected error in turn
	realInit, realWt, realCommit, realHead, realTag := ggPlainInit, ggWorktree, ggCommit, ggHead, ggCreateTag
	reset := func() {
		ggPlainInit, ggWorktree, ggCommit, ggHead, ggCreateTag = realInit, realWt, realCommit, realHead, realTag
	}
	ggPlainInit = func(string, bool) (*gogit.Repository, error) { return nil, errBoomPy }
	if err := defaultGitInitTag(t.TempDir(), "1"); !errors.Is(err, errBoomPy) {
		t.Errorf("init err: %v", err)
	}
	reset()
	ggWorktree = func(*gogit.Repository) (*gogit.Worktree, error) { return nil, errBoomPy }
	if err := defaultGitInitTag(t.TempDir(), "1"); !errors.Is(err, errBoomPy) {
		t.Errorf("worktree err: %v", err)
	}
	reset()
	ggCommit = func(*gogit.Worktree, string, *gogit.CommitOptions) (plumbing.Hash, error) {
		return plumbing.ZeroHash, errBoomPy
	}
	if err := defaultGitInitTag(t.TempDir(), "1"); !errors.Is(err, errBoomPy) {
		t.Errorf("commit err: %v", err)
	}
	reset()
	ggHead = func(*gogit.Repository) (*plumbing.Reference, error) { return nil, errBoomPy }
	if err := defaultGitInitTag(t.TempDir(), "1"); !errors.Is(err, errBoomPy) {
		t.Errorf("head err: %v", err)
	}
	reset()
	ggCreateTag = func(*gogit.Repository, string, plumbing.Hash, *gogit.CreateTagOptions) (*plumbing.Reference, error) {
		return nil, errBoomPy
	}
	if err := defaultGitInitTag(t.TempDir(), "1"); !errors.Is(err, errBoomPy) {
		t.Errorf("tag err: %v", err)
	}
	reset()
}

// TestZpkvenvMultiCallDispatch proves main() routes to zpkvenv under the shim
// name and a bad subcommand exits 2.
func TestZpkvenvMultiCallDispatch(t *testing.T) {
	oldExit, oldArgs := osExit, os.Args
	defer func() { osExit, os.Args = oldExit, oldArgs }()
	got := -1
	osExit = func(c int) { got = c }
	os.Args = []string{"/build/libexec/zpkvenv", "definitely-not-a-subcommand", "/p"}
	main()
	if got != 2 {
		t.Fatalf("zpkvenv dispatch exit = %d, want 2", got)
	}
}
