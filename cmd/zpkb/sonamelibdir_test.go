package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-zpkg/bottle"
)

// ⛔ TestATestFixtureIsNotAnABI is the published defect, with the exact path
// that produced it.
//
// The Go distribution ships `src/debug/elf/testdata/libtiffxx.so_`, a fixture
// of the standard library's own ELF reader. sonamesFromTarball read every
// regular file in the tarball, so the published go.dev 1.27.3 bottle
// announced `org.go-zpkg.abi.provides = libtiffxx.so.6` on BOTH
// darwin/aarch64 and linux/x86-64 — measured against ghcr on 2026-11-01 — and
// `abi-libtiffxx.so.6 -> v1.27.3` appeared inside the go.dev store directory
// (go-zpkg/pkgm#73, second observation).
//
// Go ships no shared libraries. Since the resolver keys ABI compatibility on
// sonames (go-zpkg/bottle#83), that annotation was an offer to satisfy a
// libtiff consumer with the Go toolchain.
func TestATestFixtureIsNotAnABI(t *testing.T) {
	lib, err := os.ReadFile(filepath.Join("testdata", "libfoo.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	tb := gzBytes(tarBytes(map[string][]byte{
		// The real shape: a toolchain with no libraries of its own, carrying
		// a library-looking fixture deep in its source tree.
		"src/debug/elf/testdata/libtiffxx.so_": lib,
		"bin/go":                               []byte("#!/bin/sh\n"),
		"pkg/tool/linux_amd64/link":            []byte("#!/bin/sh\n"),
	}))
	got, err := sonamesFromTarball(tb, bottle.ExtTarGz)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("sonames = %v, want none: a fixture under src/ is not an ABI anybody can bind to", got)
	}
}

// TestALibraryInEveryLibdirIsStillFound: the fix must not throw away the
// answer it exists to give. These are exactly the directories bottle.LibDirs
// puts on LD_LIBRARY_PATH, so each one must still be read.
func TestALibraryInEveryLibdirIsStillFound(t *testing.T) {
	lib, err := os.ReadFile(filepath.Join("testdata", "libfoo.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, where := range []string{
		"lib/libfoo.so.1",
		"lib64/libfoo.so.1",
		// glibc's real libraries live one deeper, and LibDirs globs for it.
		"lib/glibc-2.41/libfoo.so.1",
	} {
		t.Run(where, func(t *testing.T) {
			got, err := sonamesFromTarball(gzBytes(tarBytes(map[string][]byte{where: lib})), bottle.ExtTarGz)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0] != "libfoo.so.1" {
				t.Errorf("sonames = %v for %s, want [libfoo.so.1]", got, where)
			}
		})
	}
}

// ⛔ TestLibexecIsNotALibdir. `libexec` starts with "lib" and holds helper
// PROGRAMS — git's own subcommands live there — so a prefix test would read
// every one of them as a library. The match is by path component for the same
// reason every prefix match in this fleet is.
func TestLibexecIsNotALibdir(t *testing.T) {
	for _, name := range []string{
		"libexec/git-core/git-remote-https",
		"lib-extra/libfoo.so.1",
		"share/libfoo.so.1",
		"src/debug/elf/testdata/libtiffxx.so_",
		"libfoo.so.1", // at the root, with no lib dir above it
	} {
		if inLibDir(name) {
			t.Errorf("inLibDir(%q) = true", name)
		}
	}
	for _, name := range []string{
		"lib/libfoo.so.1",
		"lib64/libfoo.so.1",
		"lib/glibc-2.41/libfoo.so.1",
		"./lib/libfoo.so.1",
		"lib/pkgconfig/../libfoo.so.1",
	} {
		if !inLibDir(name) {
			t.Errorf("inLibDir(%q) = false", name)
		}
	}
}
