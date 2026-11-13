package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// advisoryTree writes an advisory tree, keyed by project, and returns its root.
func advisoryTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for project, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(project), advisoryFile)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func advisories(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := runAdvisories(args, &out, &errb)
	return rc, out.String(), errb.String()
}

func file(project, body string) string {
	return "schema-version: 1\nproject: " + project + "\nadvisories:\n" + body
}

const detected = "  - id: CVE-1\n    events:\n      - timestamp: 2026-10-10T12:00:00Z\n        type: detection\n"

func TestAdvisoriesCountsStates(t *testing.T) {
	dir := advisoryTree(t, map[string]string{
		"curl.se": file("curl.se", detected+
			"  - id: CVE-2\n    events:\n      - timestamp: 2026-10-10T12:00:00Z\n        type: fixed\n        fixed-version: 8.5.0\n"),
		"x.org/protocol/xcb": file("x.org/protocol/xcb", detected),
	})
	rc, out, errb := advisories(t, "-dir", dir)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr:\n%s", rc, errb)
	}
	if !strings.Contains(out, "2 project(s) read") || !strings.Contains(out, "3 advisory(ies)") {
		t.Errorf("want both counts:\n%s", out)
	}
	if !strings.Contains(out, "detection                    2") || !strings.Contains(out, "fixed                        1") {
		t.Errorf("want the per-state counts:\n%s", out)
	}
	// A nested project name is the PATH, which is why the layout mirrors the
	// pantry rather than Wolfi's flat directory.
	if !strings.Contains(out, "2 project(s)") {
		t.Errorf("a nested project was not counted:\n%s", out)
	}
}

// Every state named, zero included.
func TestAdvisoriesPrintsZeroStates(t *testing.T) {
	dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
	_, out, _ := advisories(t, "-dir", dir)
	for _, s := range []string{"fixed                        0", "fix-not-planned              0", "pending-upstream-fix         0"} {
		if !strings.Contains(out, s) {
			t.Errorf("want %q in:\n%s", s, out)
		}
	}
}

// ⛔ The path and the file must agree. A file copied from a neighbour and only
// half edited would otherwise attach its findings to the wrong package.
func TestAdvisoriesRefusesAProjectThatDisagreesWithItsPath(t *testing.T) {
	dir := advisoryTree(t, map[string]string{"curl.se": file("openssl.org", detected)})
	rc, _, errb := advisories(t, "-dir", dir)
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(errb, "the file says project \"openssl.org\"") || !strings.Contains(errb, "curl.se") {
		t.Errorf("want both names in the complaint: %q", errb)
	}
}

func TestAdvisoriesNamesAFileItCannotParse(t *testing.T) {
	dir := advisoryTree(t, map[string]string{
		"good.org": file("good.org", detected),
		"bad.org":  file("bad.org", "  - id: CVE-1\n    events:\n      - type: detection\n"),
	})
	rc, out, errb := advisories(t, "-dir", dir)
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(errb, "bad.org") || !strings.Contains(errb, "has no timestamp") {
		t.Errorf("want the reason: %q", errb)
	}
	// And the good one is still counted, so one bad file does not void the
	// measurement.
	if !strings.Contains(out, "1 project(s) read") {
		t.Errorf("want the readable project still counted:\n%s", out)
	}
}

func TestAdvisoriesEmptyTreeFails(t *testing.T) {
	rc, _, errb := advisories(t, "-dir", t.TempDir())
	if rc != 1 || !strings.Contains(errb, "no advisories.yaml under") {
		t.Errorf("rc = %d, stderr = %q", rc, errb)
	}
}

func TestAdvisoriesAbsentTreeFails(t *testing.T) {
	rc, _, errb := advisories(t, "-dir", filepath.Join(t.TempDir(), "nope"))
	if rc != 1 || !strings.Contains(errb, "no advisories.yaml under") {
		t.Errorf("rc = %d, stderr = %q", rc, errb)
	}
}

func TestAdvisoriesListsEachProject(t *testing.T) {
	dir := advisoryTree(t, map[string]string{
		"curl.se": file("curl.se", detected+
			"  - id: CVE-2\n    events:\n      - timestamp: 2026-10-10T12:00:00Z\n        type: fixed\n        fixed-version: 8.5.0\n"),
	})
	rc, out, _ := advisories(t, "-dir", dir, "-list")
	if rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	// Ordered, so two runs agree: detection before fixed, alphabetically.
	if !strings.Contains(out, "curl.se") || !strings.Contains(out, "detection 1, fixed 1") {
		t.Errorf("want the per-project summary:\n%s", out)
	}
}

// The listing is SORTED, not merely in walk order.
//
// WalkDir is lexical per DIRECTORY, and that is not the same as sorting the
// joined project names: `.` (0x2E) sorts before `/` (0x2F), so a nested project
// and a dotted sibling come out in opposite orders. Measured — the walk yields
// `a/b` then `a.z`, sorting yields `a.z` then `a/b`. The pantry's naming scheme
// permits exactly that pair, and an output that depended on the walk would
// differ from one that sorted for no visible reason.
func TestAdvisoriesListingIsSortedNotWalkOrder(t *testing.T) {
	dir := advisoryTree(t, map[string]string{
		"a/b": file("a/b", detected),
		"a.z": file("a.z", detected),
	})
	rc, out, errb := advisories(t, "-dir", dir, "-list")
	if rc != 0 {
		t.Fatalf("rc = %d, stderr:\n%s", rc, errb)
	}
	iz, ib := strings.Index(out, "a.z"), strings.Index(out, "a/b")
	if iz < 0 || ib < 0 {
		t.Fatalf("both projects must be listed:\n%s", out)
	}
	if iz > ib {
		t.Errorf("a.z must precede a/b (sorted), got walk order:\n%s", out)
	}
}

func TestAdvisoriesWithoutListNamesNoProject(t *testing.T) {
	dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
	_, out, _ := advisories(t, "-dir", dir)
	if strings.Contains(out, "curl.se") {
		t.Errorf("the summary must not list projects:\n%s", out)
	}
}

// A file sitting at the root belongs to no project; reading it would name the
// root directory as one and then fail to match it.
func TestAdvisoriesIgnoresAFileAtTheRoot(t *testing.T) {
	dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
	if err := os.WriteFile(filepath.Join(dir, advisoryFile), []byte(file("x", detected)), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, out, errb := advisories(t, "-dir", dir)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	if !strings.Contains(out, "1 project(s) read") {
		t.Errorf("the root file was counted as a project:\n%s", out)
	}
}

func TestAdvisoriesBadFlag(t *testing.T) {
	if rc, _, _ := advisories(t, "-nonesuch"); rc != 2 {
		t.Error("an unknown flag must be a usage error")
	}
}

// A tree the walk cannot descend is an error, not an empty corpus.
func TestAdvisoriesUnreadableTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read an unreadable directory")
	}
	dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
	sub := filepath.Join(dir, "curl.se")
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
	rc, out, errb := advisories(t, "-dir", dir)
	if rc != 1 || !strings.Contains(errb, "advisories:") {
		t.Errorf("rc = %d, stderr = %q", rc, errb)
	}
	if strings.Contains(errb, "no advisories.yaml under") {
		t.Errorf("a walk error was reported as an empty tree: %q", errb)
	}
	if out != "" {
		t.Errorf("no totals belong to a run that could not read the tree: %q", out)
	}
}

// A file the walk FOUND and the read cannot open: the two failures are
// different and both must be named rather than one standing in for the other.
func TestAdvisoriesNamesAFileItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read an unreadable file")
	}
	dir := advisoryTree(t, map[string]string{
		"good.org": file("good.org", detected),
		"bad.org":  file("bad.org", detected),
	})
	p := filepath.Join(dir, "bad.org", advisoryFile)
	if err := os.Chmod(p, 0o000); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	rc, out, errb := advisories(t, "-dir", dir)
	if rc != 1 || !strings.Contains(errb, "bad.org") {
		t.Errorf("rc = %d, stderr = %q", rc, errb)
	}
	if !strings.Contains(out, "1 project(s) read") {
		t.Errorf("want the readable project still counted:\n%s", out)
	}
}

// Through the top-level dispatch, which is the only thing a CI lane invokes.
func TestAdvisoriesDispatch(t *testing.T) {
	dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
	var out, errb bytes.Buffer
	if code := run([]string{"advisories", "-dir", dir}, &out, &errb); code != 0 {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "1 project(s) read") {
		t.Errorf("want the totals on stdout, got %q", out.String())
	}
}
