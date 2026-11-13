package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteLdSoConf: the tree is not self-sufficient by its filesystem alone,
// and this file is what lets a process started INSIDE it find libc.
//
// The directories are FOUND, not globbed, because libc.so.6 lives in
// lib/glibc-2.44/ — a versioned subdirectory that `*/v*/lib` misses. That miss
// is exactly what left /bin/sh dying on "libc.so.6: cannot open shared object
// file" in a container built from this tree.
func TestWriteLdSoConf(t *testing.T) {
	root := t.TempDir()
	zpkx := filepath.Join(root, "pkgx")
	for _, f := range []string{
		"gnu.org/glibc/v2.44.0/lib/glibc-2.44/libc.so.6", // the nested one
		"gnu.org/glibc/v2.44.0/lib/libanl.so.1",
		"zlib.net/v1.3.2/lib/libz.so.1.3.2",
		"llvm.org/v22.1.8/lib/libclang.so",
		"gnu.org/bash/v5.3/bin/bash",     // not a shared object
		"zlib.net/v1.3.2/include/zlib.h", // nor a header
	} {
		p := filepath.Join(zpkx, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	n, err := writeLdSoConf(stageOptions{Root: root, Log: func(string) {}}, zpkx)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "etc", "ld.so.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(body)), "\n")
	// ⛔ BUILT FROM guestZpkgDir, NOT FROM ITS VALUE: what this asserts is
	// that ld.so.conf names GUEST paths rather than staged ones, which is the
	// sentence three lines below. Hardcoding the root made it go red when the
	// root moved, which says nothing about ld.so.conf.
	want := []string{
		guestZpkgDir + "/gnu.org/glibc/v2.44.0/lib",
		guestZpkgDir + "/gnu.org/glibc/v2.44.0/lib/glibc-2.44",
		guestZpkgDir + "/llvm.org/v22.1.8/lib",
		guestZpkgDir + "/zlib.net/v1.3.2/lib",
	}
	if n != len(want) || strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %d dirs %v\nwant %d %v", n, got, len(want), want)
	}
	// GUEST paths, not staged ones: the file is read once the tree IS the root.
	for _, line := range got {
		if strings.Contains(line, root) {
			t.Errorf("a staged path leaked into the guest's config: %q", line)
		}
	}
}

func TestWriteLdSoConfNoSharedObjects(t *testing.T) {
	root := t.TempDir()
	zpkx := filepath.Join(root, "pkgx")
	if err := os.MkdirAll(filepath.Join(zpkx, "a.org/v1/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	n, err := writeLdSoConf(stageOptions{Root: root, Log: func(string) {}}, zpkx)
	if err != nil || n != 0 {
		t.Fatalf("got %d, %v", n, err)
	}
	// The file is still written, empty: an init that finds it absent cannot
	// tell "no libraries" from "not a --container tree".
	b, err := os.ReadFile(filepath.Join(root, "etc", "ld.so.conf"))
	if err != nil || len(b) != 0 {
		t.Fatalf("body %q err %v", b, err)
	}
}

func TestWriteLdSoConfUnwritable(t *testing.T) {
	root := t.TempDir()
	// /etc taken by a FILE: the mkdir must fail rather than be ignored.
	if err := os.WriteFile(filepath.Join(root, "etc"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeLdSoConf(stageOptions{Root: root, Log: func(string) {}}, filepath.Join(root, "pkgx")); err == nil {
		t.Fatal("expected the unwritable /etc to fail")
	}
}

// TestStageBuilderContainerWritesLdSoConf: --container is what turns the staged
// tree from "usable under bk's build wrapper" into "usable as a container root".
// Without the flag the file is absent, which is the control: an init finding it
// there must be able to trust that it was asked for.
func TestStageBuilderContainerWritesLdSoConf(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	o := stageOpts(root)
	o.Container = true
	var lines []string
	o.Log = func(s string) { lines = append(lines, s) }

	if err := stageBuilder(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "ld.so.conf")); err != nil {
		t.Fatalf("no /etc/ld.so.conf: %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "ld.so.conf written") {
		t.Errorf("the step is silent:\n%s", strings.Join(lines, "\n"))
	}

	plain := t.TempDir()
	if err := stageBuilder(stageOpts(plain)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(plain, "etc", "ld.so.conf")); err == nil {
		t.Error("without --container the file must not be there")
	}
}

// TestStageBuilderContainerSurfacesAWriteFailure: /etc taken by a file. The
// staging must fail, not stage a tree whose init will find nothing.
func TestStageBuilderContainerSurfacesAWriteFailure(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "etc"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := stageOpts(root)
	o.Container = true
	if err := stageBuilder(o); err == nil || !strings.Contains(err.Error(), "ld.so.conf") {
		t.Fatalf("got %v, want the ld.so.conf write to fail the staging", err)
	}
}

// TestWriteLdSoConfPartialWalkFails: a directory that cannot be read means the
// list is incomplete, and an incomplete ld.so.conf breaks the container
// silently — one library missing and every binary needing it dies with "cannot
// open shared object file", naming nothing.
func TestWriteLdSoConfPartialWalkFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable directories")
	}
	root := t.TempDir()
	zpkx := filepath.Join(root, "pkgx")
	locked := filepath.Join(zpkx, "a.org", "v1", "lib")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "libx.so.1"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	if _, err := writeLdSoConf(stageOptions{Root: root, Log: func(string) {}}, zpkx); err == nil {
		t.Fatal("an unreadable library directory must fail, not yield a short list")
	}
}
