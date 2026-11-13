package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// graphPantry builds the shape that actually defeated the seed order: a
// project whose BUILD dependency is not in its runtime closure, a two-cycle
// through build dependencies, and two dependents pinning one project to
// different version lines.
func graphPantry(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	// app -> lib at runtime; app build-depends on tool, which runtime-needs lib.
	writeClosureRecipe(t, p, "app.org",
		"dependencies:\n  lib.org: ^1\nbuild:\n  dependencies:\n    tool.org: '*'\n  script: make\n")
	writeClosureRecipe(t, p, "tool.org",
		"dependencies:\n  lib.org: \">=2<3.1\" # a trailing comment, which a regex once choked on\nbuild: make\n")
	writeClosureRecipe(t, p, "lib.org", "build: make\n")
	// The two-cycle: each build-depends on the other, like curl.se/ca-certs
	// and curl.se.
	writeClosureRecipe(t, p, "a.org", "build:\n  dependencies:\n    b.org: '*'\n  script: make\n")
	writeClosureRecipe(t, p, "b.org", "build:\n  dependencies:\n    a.org: '*'\n  script: make\n")
	// The cargo shape: one project naming the SAME dependency, with the same
	// constraint, in both its runtime and its build lists.
	writeClosureRecipe(t, p, "twice.org",
		"dependencies:\n  lib.org: ^1\nbuild:\n  dependencies:\n    lib.org: ^1\n  script: make\n")
	return p
}

// TestClosureBuildReachesWhatRuntimeCannot.
//
// The runtime closure is a DAG and is what a consumer needs. Filling an
// architecture from nothing needs the other graph: app.org cannot be built
// without tool.org, and no runtime walk will ever mention it.
func TestClosureBuildReachesWhatRuntimeCannot(t *testing.T) {
	p := graphPantry(t)
	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	if strings.Contains(out.String(), "tool.org") {
		t.Errorf("the RUNTIME closure must not reach a build dependency:\n%s", out.String())
	}

	out.Reset()
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "--build", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "tool.org") {
		t.Errorf("--build must reach it:\n%s", got)
	}
	// Still deps-first: lib and tool precede the thing that needs them.
	if strings.Index(got, "app.org") < strings.Index(got, "tool.org") {
		t.Errorf("order must stay dependencies-first:\n%s", got)
	}
}

// A two-cycle through build dependencies must TERMINATE, not recurse. With
// --build the graph genuinely has cycles — gnu.org/gcc build-depends on
// gnu.org/gcc — and a walk that refused to end on one would answer a question
// nobody asked.
func TestClosureBuildTerminatesOnACycle(t *testing.T) {
	p := graphPantry(t)
	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "--build", "a.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{"a.org", "b.org"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in:\n%s", want, got)
		}
	}
}

// TestClosureConstraints is the report that replaces a throwaway script.
//
// That script was wrong three times and each miss cost a dispatch on a
// two-core machine: it had no ">" in its operator list so `>=5<8.13` slipped
// past, it could not read a value with a trailing `#` comment, and it derived
// constraints from its own regex rather than from the reduction the builder
// uses. This asks build.ReduceDeps, so it cannot disagree with the build.
func TestClosureConstraints(t *testing.T) {
	p := graphPantry(t)
	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "--build", "--constraints", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	// Both lines on lib.org, including the one behind a trailing comment.
	for _, want := range []string{"lib.org", "^1", ">=2<3.1", "asked by app.org", "asked by tool.org"} {
		if !strings.Contains(got, want) {
			t.Errorf("constraints must carry %q:\n%s", want, got)
		}
	}
	// "*" says nothing and must not be listed: a report that names every
	// dependency buries the handful that pin a line.
	if strings.Contains(got, "asked by a.org") {
		t.Errorf("an unconstrained dependency must not appear:\n%s", got)
	}
}

// TestClosureImplicitNamesWhatRecipesCannot: the soname providers a walk over
// recipes is blind to by construction. perl declares nothing about libcrypt.
func TestClosureImplicitNamesWhatRecipesCannot(t *testing.T) {
	p := graphPantry(t)
	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "--implicit", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "github.com/besser82/libxcrypt") {
		t.Errorf("--implicit must name the soname providers:\n%s", got)
	}
	if !strings.Contains(got, "no recipe declares it") {
		t.Errorf("and say why they are listed apart:\n%s", got)
	}
	// They are NOT part of the order: these may be pulled in, not are.
	plain := bytes.Buffer{}
	runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "--build", "app.org"}, &plain, &errb)
	if strings.Contains(plain.String(), "libxcrypt") {
		t.Errorf("the order itself must not claim them:\n%s", plain.String())
	}
}

// TestClosureConstraintsGroupsAndDeduplicates.
//
// Two dependents asking the same thing is one line with two names; ONE
// dependent asking twice — rust-lang.org/cargo names openssl.org in both its
// runtime and its build lists — is one name, not two. "asked by cargo, cargo"
// reads as two demands where there is one, and this caught that.
func TestClosureConstraintsGroupsAndDeduplicates(t *testing.T) {
	p := graphPantry(t)
	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "--build", "--constraints",
		"app.org", "twice.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "asked by app.org, twice.org") {
		t.Errorf("two dependents on one constraint must share a line:\n%s", got)
	}
	if strings.Contains(got, "twice.org, twice.org") {
		t.Errorf("one dependent asking twice is one name:\n%s", got)
	}
}

// A dependency with no recipe in this pantry is NAMED, not silently dropped.
// It is the normal case for something that resolves from upstream — and on an
// architecture upstream does not carry, it is the thing that will fail.
func TestClosureGraphNamesAMissingRecipe(t *testing.T) {
	p := graphPantry(t)
	writeClosureRecipe(t, p, "needy.org", "dependencies:\n  nowhere.org: '*'\nbuild: make\n")
	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "--build", "needy.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(errb.String(), "skip nowhere.org") {
		t.Errorf("a dependency with no recipe must be reported: %q", errb.String())
	}
	if strings.Contains(out.String(), "nowhere.org") {
		t.Errorf("and must not be in the order, which is a build plan:\n%s", out.String())
	}
}

// TestClosureReadsTheOverlay, end to end: the edge that exists only in our
// overlay must appear in the order.
//
// Measured on the real trees before this was written — the overlay adds
// github.com/besser82/libxcrypt and github.com/google/brotli to the s390x
// seed closure, which are exactly the two projects that stopped a build
// today, each discovered several steps downstream of the recipe that names
// them.
func TestClosureReadsTheOverlay(t *testing.T) {
	pan, ov := t.TempDir(), t.TempDir()
	writeClosureRecipe(t, pan, "perl.org", "build: make\n")
	writeClosureRecipe(t, ov, "perl.org", "dependencies:\n  crypt.org: '*'\nbuild: make\n")
	writeClosureRecipe(t, pan, "crypt.org", "build: make\n")

	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", pan, "--platform", "linux/x86-64", "--build", "perl.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if strings.Contains(out.String(), "crypt.org") {
		t.Fatalf("premise wrong: upstream alone should not see it:\n%s", out.String())
	}

	out.Reset()
	if code := runClosure([]string{"--pantry", pan, "--overlay", ov, "--platform", "linux/x86-64", "--build", "perl.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out.String(), "crypt.org") {
		t.Errorf("the overlay's edge must be walked:\n%s", out.String())
	}
}

// TestClosureMergesAReducedOverlayEntry is the regression that sent bk back to
// this file. go-zpkg/pantry-overlay reduced its 183 entries to the keys they
// change, and a walk that preferred the overlay's copy WHOLE then read a
// fragment: `bk closure --build curl.se` collapsed from 54 projects to 8,
// because the entry states `dependencies` and the walk never saw upstream's
// build dependencies at all.
//
// The overrides are the same lesson on the other side. They describe 206
// projects, the overlay carries 183, and 178 of the overrides edit a
// dependency — so a project the overlay does not carry was read unoverridden.
// Measured on a pristine pantry: `bk closure --build rsync.samba.org` listed
// gnu.org/libidn2 without --overlay and not with it.
func TestClosureMergesAReducedOverlayEntry(t *testing.T) {
	pan, ov, ovr := t.TempDir(), t.TempDir(), t.TempDir()
	// A reduced entry: the dependency it changes, and NOTHING else.
	writeClosureRecipe(t, pan, "app.org",
		"dependencies:\n  lib.org: ^1\nbuild:\n  dependencies:\n    tool.org: '*'\n  script: make\n")
	writeClosureRecipe(t, ov, "app.org", "dependencies:\n  lib.org: ^2\n")
	// A project the overlay does not carry, whose override adds an edge.
	writeClosureRecipe(t, pan, "lib.org", "build: make\n")
	writeClosureRecipe(t, pan, "tool.org", "build: make\n")
	writeClosureRecipe(t, pan, "idn.org", "build: make\n")
	if err := os.WriteFile(filepath.Join(ovr, "lib.hcl"), []byte(
		"project = \"lib.org\"\nwhy = \"the published artifact needs it and upstream does not say so\"\n"+
			"edits = [{ path = \"dependencies[\\\"idn.org\\\"]\", set = \"*\" }]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := runClosure([]string{"--pantry", pan, "--overlay", ov, "--overrides", ovr,
		"--platform", "linux/x86-64", "--build", "app.org"}, &out, &errb)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	// Inherited from upstream through the merge: the fragment says nothing
	// about build dependencies, and tool.org is one.
	if !strings.Contains(got, "tool.org") {
		t.Errorf("a reduced entry must not hide upstream's build dependency:\n%s", got)
	}
	// Reached through the override, for a project the overlay does not carry.
	if !strings.Contains(got, "idn.org") {
		t.Errorf("the overrides must reach the pantry half under an overlay:\n%s", got)
	}
}
