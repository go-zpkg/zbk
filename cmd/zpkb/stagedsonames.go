package main

import (
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// auditStagedSonames reports every shared library a staged tree NEEDS and does
// not contain.
//
// The sovereign rootfs has nothing underneath it, so a NEEDED soname that no
// staged artifact provides is a binary that cannot start — and it says so only
// when something runs it, which is deep inside a build and attributed to
// whatever happened to run first. The s390x second generation met this twice
// in a row, on two different tools, a full build apart:
//
//	mkdir: error while loading shared libraries: libselinux.so.1
//	sed:   error while loading shared libraries: libselinux.so.1
//
// Both came from the same cause — an artifact built on a host that HAS libselinux,
// whose configure auto-detects it — and each cost a round trip to a runner to
// learn the next name. The tree can answer the whole question at once, before
// a single build starts.
//
// REPORTED, never fatal. A tree can legitimately carry an ELF for another
// purpose, and the staging step's job is to stage; refusing here would turn a
// useful census into a gate nobody can land a change past. The build that
// follows is the verdict.
func auditStagedSonames(zpkgDir string) string {
	provided, needed := scanSonames(zpkgDir)
	return reportSonames("builder", provided, needed, zpkgDir)
}

// scanSonames walks a tree and returns what it PROVIDES and what it NEEDS.
//
// Separate from the report because the same two sets answer the question over
// a registry, where each artifact is unpacked on its own: the 78 projects of a
// seed order cannot be installed together — cmake wants curl `>=5<8.13` and
// cargo wants `8` — so a union over separate trees is the only way to ask
// "which soname does NOBODY here provide".
func scanSonames(zpkgDir string) (provided map[string]bool, needed map[string][]string) {
	provided = map[string]bool{}
	needed = map[string][]string{} // soname -> the files that ask for it

	_ = filepath.WalkDir(zpkgDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		// A provider is named by its FILE, because that is what the loader
		// looks up: a DT_SONAME may differ, and a symlink chain
		// (libz.so -> libz.so.1.3.2) means several names for one object.
		if i := strings.Index(d.Name(), ".so"); i >= 0 {
			provided[d.Name()] = true
		}
		f, err := elf.Open(p)
		if err != nil {
			return nil // not an ELF, which is most of a tree
		}
		defer f.Close()
		libs, err := f.DynString(elf.DT_NEEDED)
		if err != nil {
			return nil
		}
		for _, l := range libs {
			needed[l] = append(needed[l], p)
		}
		return nil
	})

	// A symlink is a provider too, and WalkDir does not report its target as a
	// regular file when it points outside the tree — so count link NAMES.
	_ = filepath.WalkDir(zpkgDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&os.ModeSymlink != 0 && strings.Contains(d.Name(), ".so") {
			provided[d.Name()] = true
		}
		return nil
	})

	return provided, needed
}

// reportSonames names every soname that is needed and not provided, with who
// asks. `trim` is stripped from the asker paths, so a report over a staged
// tree reads as project/version/bin/name.
func reportSonames(who string, provided map[string]bool, needed map[string][]string, trim string) string {
	var missing []string
	for name := range needed {
		if !provided[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return fmt.Sprintf("%s: every NEEDED soname is provided (%d distinct)", who, len(needed))
	}
	sort.Strings(missing)
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d soname(s) are NEEDED and provided by nothing here — a binary that wants one cannot start:",
		who, len(missing))
	for _, name := range missing {
		who := needed[name]
		sort.Strings(who)
		// Three askers is enough to recognise the package; the full list is
		// hundreds of lines and the point is the NAME.
		shown := who
		more := ""
		if len(shown) > 3 {
			shown, more = shown[:3], fmt.Sprintf(" (+%d more)", len(who)-3)
		}
		for i, w := range shown {
			shown[i] = strings.TrimPrefix(w, trim+string(filepath.Separator))
		}
		fmt.Fprintf(&b, "\n  %s <- %s%s", name, strings.Join(shown, " "), more)
	}
	return b.String()
}
