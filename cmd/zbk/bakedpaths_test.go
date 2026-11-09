package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stagedTree writes files into a temporary tree and returns its root.
//
// A file under bin/ is one something executes, which is what rule C scans.
func stagedTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestTheTwoRealMechanismsAreBothCaught runs the check over the exact shapes the
// two recipes of 2026-11-09 would have shipped IF the store had been the source
// of the path.
//
// They reach the tree by different routes — one compiled into an ELF's .rodata,
// one substituted into a shell script — and the point of scanning BYTES rather
// than build inputs is that the check does not have to know which.
func TestTheTwoRealMechanismsAreBothCaught(t *testing.T) {
	store := "/opt/zpkg"
	root := stagedTree(t, map[string]string{
		// gnu.org/diffutils: AC_PATH_PROG([PR_PROGRAM],[pr]) → compiled in, so
		// the path sits among NUL-separated strings, not on a line of its own.
		"bin/diff": "\x7fELF\x02\x01\x01\x00no diff\x00" +
			"/opt/zpkg/gnu.org/coreutils/v9.7.0/bin/pr\x00pagination not supported\x00",
		// gnu.org/findutils: @SORT@ substituted into the installed script.
		"bin/updatedb": "#!/bin/sh\nsort=\"/opt/zpkg/gnu.org/coreutils/v9.7.0/bin/sort -z\"\n",
	})

	scan, err := scanStorePaths(root, store)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Files != 2 {
		t.Fatalf("read %d file(s), want 2", scan.Files)
	}
	hits := scan.ByProject["gnu.org/coreutils"]
	if len(hits) != 2 {
		t.Fatalf("gnu.org/coreutils: %d hit(s), want 2: %+v", len(hits), hits)
	}
	var inELF, inScript bool
	for _, h := range hits {
		if h.Version != "9.7.0" {
			t.Errorf("%s: version %q, want 9.7.0", h.File, h.Version)
		}
		switch h.File {
		case filepath.Join("bin", "diff"):
			inELF = true
			if !strings.HasSuffix(h.Path, "/bin/pr") {
				t.Errorf("bin/diff: matched %q", h.Path)
			}
		case filepath.Join("bin", "updatedb"):
			inScript = true
			if !strings.HasSuffix(h.Path, "/bin/sort") {
				t.Errorf("bin/updatedb: matched %q", h.Path)
			}
		}
	}
	if !inELF || !inScript {
		t.Errorf("compiled-in seen: %v, substituted seen: %v — both mechanisms must be found", inELF, inScript)
	}

	report, ok := reportStorePaths(scan, "gnu.org/findutils", nil, 0)
	if ok {
		t.Error("the verdict passed a tree holding another project's versioned path")
	}
	for _, want := range []string{"gnu.org/coreutils", "diff", "updatedb", "#397"} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not name %q:\n%s", want, report)
		}
	}
}

// TestTheThreeShippedDefectsAreEachNamed is the measurement that rewrote this
// check's scope, replayed as a test.
//
// Every string here was READ out of ~/.pkgx on 2026-11-09, from bottles the
// fleet ships today. The first version of this check — which looked only for
// another project's versioned store path — passed all three.
func TestTheThreeShippedDefectsAreEachNamed(t *testing.T) {
	root := stagedTree(t, map[string]string{
		// gnu.org/diffutils v3.12.0, bin/diff: AC_PATH_PROG's value, the BUILD
		// HOST's path, compiled in beside the string that proves which define
		// it is.
		"bin/diff": "\x00/usr/bin/pr\x00pagination not supported on this host\x00",
		// gnu.org/findutils v4.10.0, bin/updatedb: the host's sort, and three
		// references to the staging tree.
		"bin/updatedb": "if true\n    sort=\"/usr/bin/sort -z\"\n" +
			": ${LOCATE_DB=/opt/gnu.org/findutils/v4.10.0+brewing/var/locate/locatedb}\n" +
			": ${LIBEXECDIR=/opt/gnu.org/findutils/v4.10.0+brewing/libexec}\n" +
			": ${BINDIR=/opt/gnu.org/findutils/v4.10.0+brewing/bin}\n",
	})

	// The store on THIS machine is somewhere else entirely, which is the point:
	// a rule anchored on the local store root sees none of this.
	scan, err := scanStorePaths(root, "/Users/someone/.pkgx")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.ByProject) != 0 {
		t.Errorf("rule A matched something, so this fixture no longer proves it does not: %+v", scan.ByProject)
	}
	if len(scan.Staging) != 3 {
		t.Errorf("rule B found %d staging reference(s), want 3: %+v", len(scan.Staging), scan.Staging)
	}
	for _, want := range []string{"/usr/bin/pr", "/usr/bin/sort"} {
		if len(scan.Host[want]) == 0 {
			t.Errorf("rule C did not find %s; it found %v", want, pathsOf(scan.Host))
		}
	}

	report, ok := reportStorePaths(scan, "gnu.org/findutils", nil, 0)
	if ok {
		t.Errorf("a tree holding three shipped defects passed:\n%s", report)
	}
	for _, want := range []string{"+brewing", "#152", "CENSUS", "/usr/bin/pr", "/usr/bin/sort"} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not name %q:\n%s", want, report)
		}
	}
}

func pathsOf(m map[string][]storePathHit) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestAStagingPathHasNoDerogation: rule B is fatal whatever --allow says,
// because there is no tree in which a staging path is the intent.
func TestAStagingPathHasNoDerogation(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"bin/x": ": ${BINDIR=/opt/gnu.org/findutils/v4.10.0+brewing/bin}",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	report, ok := reportStorePaths(scan, "gnu.org/findutils",
		map[string]bool{"gnu.org/findutils": true}, 0)
	if ok {
		t.Errorf("--allow let a staging path through:\n%s", report)
	}
}

// TestUpstreamsOwnBakedPathIsFoundByTheCensus uses the string go-zpkg/zbk's
// fix/libtool-baked-tool-paths branch found inside a PUBLISHED bottle.
//
// It is not a store path — it is a CI runner's workspace — so rule A says
// nothing about it. Rule C is what sees it, which is the reason rule C exists.
func TestUpstreamsOwnBakedPathIsFoundByTheCensus(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"bin/libtoolize": ": ${SED=\"/__w/_actions/pkgxdev/brewkit/v1/libexec/sed\"}\n",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.ByProject) != 0 {
		t.Fatalf("rule A matched something outside the store layout: %+v", scan.ByProject)
	}
	want := "/__w/_actions/pkgxdev/brewkit/v1/libexec/sed"
	if len(scan.Host[want]) != 1 {
		t.Fatalf("the census did not name %s; it found %v", want, pathsOf(scan.Host))
	}
	// Not fatal: rule C counts, it does not refuse. Said as a test so that
	// flipping it later is a deliberate change with a failing test to update.
	report, ok := reportStorePaths(scan, "gnu.org/libtool", nil, 0)
	if !ok {
		t.Errorf("the census refused, which it must not do yet:\n%s", report)
	}
}

// TestAProjectsOwnPrefixIsItsToName keeps the check from refusing the normal
// case: a package naming its own libexec, data directory or loader.
func TestAProjectsOwnPrefixIsItsToName(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"lib/locate.dat": "\x00/opt/zpkg/gnu.org/findutils/v4.11.0/var/locatedb\x00",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	report, ok := reportStorePaths(scan, "gnu.org/findutils", nil, 0)
	if !ok {
		t.Errorf("refused a package for naming its own prefix:\n%s", report)
	}
	if !strings.Contains(report, "own prefix") || !strings.Contains(report, "1 reference(s)") {
		t.Errorf("the report hides the self-reference instead of counting it:\n%s", report)
	}
}

// TestTheDerogationStamps: --allow must not silence, it must print.
func TestTheDerogationStamps(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"lib/x.dat": "/opt/zpkg/gnu.org/coreutils/v9.7.0/bin/sort",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	report, ok := reportStorePaths(scan, "gnu.org/findutils",
		map[string]bool{"gnu.org/coreutils": true}, 0)
	if !ok {
		t.Errorf("--allow did not let the tree through:\n%s", report)
	}
	for _, want := range []string{"ALLOWED", "--allow gnu.org/coreutils", "x.dat"} {
		if !strings.Contains(report, want) {
			t.Errorf("the exemption is not visible in the report (%q missing):\n%s", want, report)
		}
	}
}

// TestANestedVSegmentDoesNotStealTheProjectName is the non-greedy case.
//
// A greedy project segment resolves this to project "nodejs.org/v22.1.0/lib" at
// version "8", which would then be compared against --project and reported
// under a name no recipe has — a finding nobody can act on.
func TestANestedVSegmentDoesNotStealTheProjectName(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"lib/x.dat": "/opt/zpkg/nodejs.org/v22.1.0/lib/v8/include/v8.h",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	hits := scan.ByProject["nodejs.org"]
	if len(hits) != 1 {
		t.Fatalf("nodejs.org: %d hit(s), want 1 — got %+v", len(hits), scan.ByProject)
	}
	if hits[0].Version != "22.1.0" {
		t.Errorf("version %q, want 22.1.0", hits[0].Version)
	}
}

// TestAProjectNameSpanningSlashesIsRead: gnu.org/gcc/libstdcxx is one project.
func TestAProjectNameSpanningSlashesIsRead(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"lib/x.so": "/opt/zpkg/gnu.org/gcc/libstdcxx/v15.2.0/lib/libstdc++.so.6",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scan.ByProject["gnu.org/gcc/libstdcxx"]; !ok {
		t.Fatalf("project read as %+v, want gnu.org/gcc/libstdcxx", scan.ByProject)
	}
}

// TestAMatchStraddlingTwoChunksIsStillSeen is the one property the streaming
// scan could silently lose, and the one that would make the gate pass a tree
// holding the defect.
//
// The path is placed so that it begins inside the first window and ends in the
// second. Counted once, not twice, because the overlap re-reads those bytes.
func TestAMatchStraddlingTwoChunksIsStillSeen(t *testing.T) {
	path := "/opt/zpkg/gnu.org/coreutils/v9.7.0/bin/sort"
	// The padding ends the path with a NUL, as a compiled-in string does:
	// without one, "sort" and the bytes after it are a single legal path
	// segment, which an earlier version of this test learnt the slow way.
	pad := strings.Repeat("A", scanChunk-10)
	body := pad + path + "\x00" + strings.Repeat("B", 64)

	hits, err := scanFileStorePaths(bytes.NewReader([]byte(body)), "bin/x", storePathPattern("/opt/zpkg"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("%d hit(s) across the chunk boundary, want exactly 1: %+v", len(hits), hits)
	}
	if hits[0].Path != path {
		t.Errorf("matched %q, want %q", hits[0].Path, path)
	}
	if want := int64(scanChunk - 10); hits[0].Offset != want {
		t.Errorf("offset %d, want %d", hits[0].Offset, want)
	}
}

// TestTheAllowedHostPathsAreNotCounted: /usr/bin/env in a shebang is the
// portable form, and a store path there would be worse.
func TestTheAllowedHostPathsAreNotCounted(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"bin/script": "#!/usr/bin/env sh\nexec /bin/sh \"$@\"\n",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Host) != 0 {
		t.Errorf("the census counted an allowed path: %v", pathsOf(scan.Host))
	}
}

// TestTheCensusReadsOnlyWhatRunsThings records the scope choice, so widening it
// is a deliberate change rather than a discovery.
func TestTheCensusReadsOnlyWhatRunsThings(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"share/man/man1/diff.1": "see /usr/bin/pr for pagination\n",
		"bin/diff":              "/usr/bin/pr\x00",
	})
	scan, err := scanStorePaths(root, "/opt/zpkg")
	if err != nil {
		t.Fatal(err)
	}
	hits := scan.Host["/usr/bin/pr"]
	if len(hits) != 1 {
		t.Fatalf("%d hit(s), want 1 — the man page must not be counted: %+v", len(hits), hits)
	}
	if got := filepath.ToSlash(hits[0].File); got != "bin/diff" {
		t.Errorf("counted %s, want bin/diff", got)
	}
	if scan.ExecFiles != 1 {
		t.Errorf("%d executable file(s), want 1", scan.ExecFiles)
	}
}

// TestEveryFlagIsRequired: the check must refuse rather than assume a tree.
func TestEveryFlagIsRequired(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--dir", "/tmp"},
		{"--dir", "/tmp", "--store", "/opt/zpkg"},
		{"--store", "/opt/zpkg", "--project", "a.org/b"},
	} {
		var out, errb bytes.Buffer
		if code := runBakedPaths(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, errb.String())
		}
		if !strings.Contains(errb.String(), "required") {
			t.Errorf("%v: does not say what is missing: %s", args, errb.String())
		}
	}
}

// TestTheCommandExitsOneOnAFinding wires the whole thing end to end.
func TestTheCommandExitsOneOnAFinding(t *testing.T) {
	root := stagedTree(t, map[string]string{
		"lib/updatedb.dat": "sort=\"/opt/zpkg/gnu.org/coreutils/v9.7.0/bin/sort -z\"\n",
	})
	var out, errb bytes.Buffer
	code := runBakedPaths([]string{
		"--dir", root, "--store", "/opt/zpkg", "--project", "gnu.org/findutils",
	}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "gnu.org/coreutils") {
		t.Errorf("stdout does not name the project: %s", out.String())
	}

	out.Reset()
	errb.Reset()
	code = runBakedPaths([]string{
		"--dir", root, "--store", "/opt/zpkg", "--project", "gnu.org/findutils",
		"--allow", "gnu.org/coreutils",
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("with --allow: exit %d, want 0\nstdout: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "ALLOWED") {
		t.Errorf("the derogation left no trace: %s", out.String())
	}
}
