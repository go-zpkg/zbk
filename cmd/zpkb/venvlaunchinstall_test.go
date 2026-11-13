package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeVenvLaunch puts an executable named venvlaunch first on PATH and returns
// its bytes. It stands in for the real cmd/venvlaunch binary: this code copies
// whatever it finds, so the content only has to be recognisable.
func fakeVenvLaunch(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	body := []byte("\x7fELF this stands in for cmd/venvlaunch\n")
	if err := os.WriteFile(filepath.Join(dir, venvLaunchName), body, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return body
}

// makeVenvBin builds <prefix>/venv/bin in the shape `python -m venv` leaves:
// an ABSOLUTE symlink to the interpreter it was run with, plus a console
// script, which is a regular file and must be left alone.
func makeVenvBin(t *testing.T, prefix string) (venv, realPython string) {
	t.Helper()
	store := t.TempDir()
	realPython = filepath.Join(store, "python3")
	venv = filepath.Join(prefix, "venv")
	bin := filepath.Join(venv, "bin")
	for _, err := range []error{
		os.WriteFile(realPython, []byte("#!/bin/sh\nexit 0\n"), 0o755),
		os.MkdirAll(bin, 0o755),
		os.Symlink(realPython, filepath.Join(bin, "python")),
		os.WriteFile(filepath.Join(bin, "mycli"), []byte("#!"+filepath.Join(bin, "python")+"\n"), 0o755),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return venv, realPython
}

// TestInstallVenvLaunchCopiesAndRelativises is the happy path: every name gets
// the binary, executable; the venv's absolute python link becomes relative and
// still resolves; the console script is untouched.
func TestInstallVenvLaunchCopiesAndRelativises(t *testing.T) {
	defer restorePy(t)()
	want := fakeVenvLaunch(t)
	prefix := t.TempDir()
	venv, realPython := makeVenvBin(t, prefix)
	script, err := os.ReadFile(filepath.Join(venv, "bin", "mycli"))
	if err != nil {
		t.Fatal(err)
	}

	if err := installVenvLaunch(prefix, venv, []string{"mycli", "myother"}); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"mycli", "myother"} {
		p := filepath.Join(prefix, "bin", name)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s: installed %q, want the launcher", name, got)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: mode %v, want 0755 — an entry point nobody can execute", name, fi.Mode().Perm())
		}
	}

	link := filepath.Join(venv, "bin", "python")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(target) {
		t.Fatalf("python still points at an absolute path %q: the artifact would carry the build store's path", target)
	}
	// AND IT RESOLVES. A relative link that reaches nothing is the defect this
	// replaces, dressed differently.
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatalf("relative link does not resolve: %v", err)
	}
	wantResolved, err := filepath.EvalSymlinks(realPython)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != wantResolved {
		t.Errorf("python resolves to %q, want %q", resolved, wantResolved)
	}

	// The console script is a regular file, not a symlink: its absolute shebang
	// is deliberately left as it is, because venvlaunch passes the script to the
	// interpreter as an ARGUMENT and the kernel never reads that line.
	if got, err := os.ReadFile(filepath.Join(venv, "bin", "mycli")); err != nil || string(got) != string(script) {
		t.Errorf("console script was rewritten: %q (%v)", got, err)
	}
}

// TestInstallVenvLaunchIsIdempotent proves a second seal does not double-prefix
// the link it already made relative — the shape a rebuild takes.
func TestInstallVenvLaunchIsIdempotent(t *testing.T) {
	defer restorePy(t)()
	fakeVenvLaunch(t)
	prefix := t.TempDir()
	venv, _ := makeVenvBin(t, prefix)

	if err := installVenvLaunch(prefix, venv, []string{"mycli"}); err != nil {
		t.Fatal(err)
	}
	first, err := os.Readlink(filepath.Join(venv, "bin", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if err := installVenvLaunch(prefix, venv, []string{"mycli"}); err != nil {
		t.Fatal(err)
	}
	second, err := os.Readlink(filepath.Join(venv, "bin", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("a second seal changed the link: %q then %q", first, second)
	}
}

// TestInstallVenvLaunchRepairsMode covers the reason the destination is removed
// before it is written: os.WriteFile leaves an existing file's mode alone.
func TestInstallVenvLaunchRepairsMode(t *testing.T) {
	defer restorePy(t)()
	fakeVenvLaunch(t)
	prefix := t.TempDir()
	venv, _ := makeVenvBin(t, prefix)
	dst := filepath.Join(prefix, "bin", "mycli")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := installVenvLaunch(prefix, venv, []string{"mycli"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v after reinstall over a 0644 leftover, want 0755", fi.Mode().Perm())
	}
}

// TestInstallVenvLaunchErrors walks every failure the installer can report.
func TestInstallVenvLaunchErrors(t *testing.T) {
	t.Run("not on PATH", func(t *testing.T) {
		defer restorePy(t)()
		t.Setenv("PATH", t.TempDir())
		err := installVenvLaunch(t.TempDir(), t.TempDir(), []string{"c"})
		if err == nil || !strings.Contains(err.Error(), "build dependencies") {
			t.Fatalf("want an error naming the build dependency, got %v", err)
		}
	})

	t.Run("found then unreadable", func(t *testing.T) {
		defer restorePy(t)()
		pyLookPath = func(string) (string, error) {
			return filepath.Join(t.TempDir(), "vanished"), nil
		}
		if err := installVenvLaunch(t.TempDir(), t.TempDir(), []string{"c"}); err == nil {
			t.Fatal("want a read error")
		}
	})

	t.Run("bin is a file", func(t *testing.T) {
		defer restorePy(t)()
		fakeVenvLaunch(t)
		prefix := t.TempDir()
		if err := os.WriteFile(filepath.Join(prefix, "bin"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := installVenvLaunch(prefix, filepath.Join(prefix, "venv"), []string{"c"}); err == nil {
			t.Fatal("want a mkdir error")
		}
	})

	t.Run("destination is a non-empty directory", func(t *testing.T) {
		defer restorePy(t)()
		fakeVenvLaunch(t)
		prefix := t.TempDir()
		clash := filepath.Join(prefix, "bin", "c")
		if err := os.MkdirAll(clash, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(clash, "keep"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := installVenvLaunch(prefix, filepath.Join(prefix, "venv"), []string{"c"}); err == nil {
			t.Fatal("want a remove error")
		}
	})

	t.Run("bin is read-only", func(t *testing.T) {
		defer restorePy(t)()
		fakeVenvLaunch(t)
		prefix := t.TempDir()
		bin := filepath.Join(prefix, "bin")
		if err := os.MkdirAll(bin, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })
		if err := installVenvLaunch(prefix, filepath.Join(prefix, "venv"), []string{"c"}); err == nil {
			t.Fatal("want a write error")
		}
	})

	t.Run("no venv", func(t *testing.T) {
		defer restorePy(t)()
		fakeVenvLaunch(t)
		prefix := t.TempDir()
		if err := installVenvLaunch(prefix, filepath.Join(prefix, "venv"), []string{"c"}); err == nil {
			t.Fatal("want a ReadDir error for a missing venv/bin")
		}
	})
}

// TestFindVenvLaunch covers the lookup order: PATH first, because only PATH can
// hold the TARGET's launcher under a cross build, then the HOST's beside the
// running zpkb, which is what saves every python-venv recipe that has not
// declared the dependency.
func TestFindVenvLaunch(t *testing.T) {
	t.Run("PATH wins over the one beside zpkb", func(t *testing.T) {
		defer restorePy(t)()
		fakeVenvLaunch(t) // sets PATH
		beside := t.TempDir()
		if err := os.WriteFile(filepath.Join(beside, venvLaunchName), []byte("host"), 0o755); err != nil {
			t.Fatal(err)
		}
		pyExecutable = func() (string, error) { return filepath.Join(beside, "zpkb"), nil }
		got, err := findVenvLaunch()
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(got) == beside {
			t.Error("the host's launcher was preferred over the one on PATH: a cross build would put the wrong platform in the artifact")
		}
	})

	t.Run("beside zpkb, plain name", func(t *testing.T) {
		defer restorePy(t)()
		t.Setenv("PATH", t.TempDir())
		beside := t.TempDir()
		want := filepath.Join(beside, venvLaunchName)
		if err := os.WriteFile(want, []byte("host"), 0o755); err != nil {
			t.Fatal(err)
		}
		pyExecutable = func() (string, error) { return filepath.Join(beside, "zpkb"), nil }
		got, err := findVenvLaunch()
		if err != nil || got != want {
			t.Errorf("got %q, %v; want %q", got, err, want)
		}
	})

	t.Run("beside zpkb, release asset name", func(t *testing.T) {
		defer restorePy(t)()
		t.Setenv("PATH", t.TempDir())
		beside := t.TempDir()
		pyGOOS, pyGOARCH = "linux", "s390x"
		want := filepath.Join(beside, venvLaunchName+"-linux-s390x")
		if err := os.WriteFile(want, []byte("host"), 0o755); err != nil {
			t.Fatal(err)
		}
		pyExecutable = func() (string, error) { return filepath.Join(beside, "zpkb"), nil }
		got, err := findVenvLaunch()
		if err != nil || got != want {
			t.Errorf("got %q, %v; want %q", got, err, want)
		}
	})

	t.Run("cannot locate zpkb", func(t *testing.T) {
		defer restorePy(t)()
		t.Setenv("PATH", t.TempDir())
		pyExecutable = func() (string, error) { return "", errBoomPy }
		if _, err := findVenvLaunch(); !errors.Is(err, errBoomPy) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("nowhere, and the message says where it looked", func(t *testing.T) {
		defer restorePy(t)()
		t.Setenv("PATH", t.TempDir())
		beside := t.TempDir()
		pyExecutable = func() (string, error) { return filepath.Join(beside, "zpkb"), nil }
		_, err := findVenvLaunch()
		if err == nil {
			t.Fatal("want an error")
		}
		for _, want := range []string{"(PATH)", beside, "go-zpkg.github.io/venvlaunch"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the message does not mention %q: %v", want, err)
			}
		}
	})
}

// TestRelativiseVenvLinksErrors covers the branches of the relativiser that the
// installer's own tests cannot reach.
func TestRelativiseVenvLinksErrors(t *testing.T) {
	t.Run("relative prefix is refused", func(t *testing.T) {
		defer restorePy(t)()
		prefix := t.TempDir()
		makeVenvBin(t, prefix)
		t.Chdir(prefix)
		err := relativiseVenvLinks("venv")
		if err == nil || !strings.Contains(err.Error(), "absolute prefix is required") {
			t.Fatalf("want a refusal naming the requirement, got %v", err)
		}
	})

	// ⛔⛔ THIS USED TO MAKE <venv>/bin MODE 0444 — readable, not searchable —
	// so that os.ReadDir listed it and os.Readlink failed inside it. That is
	// true on linux and darwin, and FreeBSD, NetBSD and OpenBSD answered the
	// readlink anyway: 21 green checks and 3 red, on a change none of them was
	// about. A test that depends on where a kernel places a permission check is
	// testing the kernel, so the seam is the honest instrument here.
	t.Run("readlink fails", func(t *testing.T) {
		defer restorePy(t)()
		prefix := t.TempDir()
		venv, _ := makeVenvBin(t, prefix)
		pyReadlink = func(string) (string, error) { return "", errBoomPy }
		if err := relativiseVenvLinks(venv); !errors.Is(err, errBoomPy) {
			t.Fatalf("readlink error = %v", err)
		}
	})

	t.Run("relink fails", func(t *testing.T) {
		defer restorePy(t)()
		prefix := t.TempDir()
		venv, _ := makeVenvBin(t, prefix)
		pyRelink = func(string, string) error { return errBoomPy }
		if err := relativiseVenvLinks(venv); !errors.Is(err, errBoomPy) {
			t.Fatalf("relink error = %v", err)
		}
	})

	t.Run("a relink that does not resolve is caught", func(t *testing.T) {
		defer restorePy(t)()
		prefix := t.TempDir()
		venv, _ := makeVenvBin(t, prefix)
		pyRelink = func(path, _ string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("no-such-interpreter", path)
		}
		err := relativiseVenvLinks(venv)
		if err == nil || !strings.Contains(err.Error(), "does not") {
			t.Fatalf("want the resolution check to fail, got %v", err)
		}
	})
}

// TestDefaultRelink covers the atomic replacement and both of its failures.
func TestDefaultRelink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink("/absolute/elsewhere", link); err != nil {
		t.Fatal(err)
	}
	if err := defaultRelink(link, "real"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(link); err != nil || got != "real" {
		t.Errorf("readlink = %q, %v", got, err)
	}

	// ⛔ A LEFTOVER AT THE TEMPORARY NAME MAKES THIS REFUSE, IT DOES NOT MAKE
	// IT WRITE THROUGH. symlink(2) fails with EEXIST; the predecessor of this
	// code opened a predictable temporary name with 'wb' and followed whatever
	// was there.
	planted := link + ".zpkg-relink"
	if err := os.Symlink("/etc/passwd", planted); err != nil {
		t.Fatal(err)
	}
	if err := defaultRelink(link, "real"); err == nil {
		t.Error("want EEXIST on the planted temporary name")
	}
	if got, err := os.Readlink(planted); err != nil || got != "/etc/passwd" {
		t.Errorf("the planted link was altered: %q, %v", got, err)
	}
	if err := os.Remove(planted); err != nil {
		t.Fatal(err)
	}

	// Rename error: the destination is a non-empty directory.
	busy := filepath.Join(dir, "busy")
	if err := os.MkdirAll(busy, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(busy, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := defaultRelink(busy, "real"); err == nil {
		t.Error("want a rename error over a non-empty directory")
	}
}
