package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vulnid(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := runVulnID(args, &out, &errb)
	return rc, out.String(), errb.String()
}

// writeTable puts an identity table beside the pantry and returns its path.
func writeTable(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identities.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// The three buckets, measured on one tree: a recipe whose versions block names
// a repo, one that names nothing, and one the table speaks for.
func TestVulnIDCountsTheThreeSources(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"curl.se/package.yml":     "distributable:\n  url: http://x/y.tgz\nversions:\n  github: curl/curl\n",
		"ftp.gnu.org/package.yml": "distributable:\n  url: http://ftp.gnu.org/g/x.tgz\nversions:\n  url: http://ftp.gnu.org/g/\n  match: /x-\\d/\n",
		"openssl.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  url: http://openssl.org/source/\n  match: /x-\\d/\n",
	})
	tab := writeTable(t, "schema-version: 1\nprojects:\n  openssl.org:\n    cpe: [openssl:openssl]\n")
	rc, out, errb := vulnid(t, "-dir", dir, "-table", tab)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr:\n%s", rc, errb)
	}
	for _, want := range []string{"3 recipe(s) read", "declared  1", "derived   1", "none      1"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
	// By database, so the shape is visible and not just the totals.
	if !strings.Contains(out, "GitHub         1") || !strings.Contains(out, "cpe            1") {
		t.Errorf("want a per-database breakdown:\n%s", out)
	}
}

// Every total is printed even when it is zero. A census that prints only its
// non-empty buckets cannot be told from one that failed to fill them.
func TestVulnIDPrintsZeroTotals(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"curl.se/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: curl/curl\n",
	})
	_, out, _ := vulnid(t, "-dir", dir)
	if !strings.Contains(out, "declared  0") || !strings.Contains(out, "none      0") {
		t.Errorf("want the empty buckets stated:\n%s", out)
	}
}

func TestVulnIDListsProjectsOfOneSource(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"curl.se/package.yml":     "distributable:\n  url: http://x/y.tgz\nversions:\n  github: curl/curl\n",
		"ftp.gnu.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  url: http://ftp.gnu.org/g/\n  match: /x-\\d/\n",
	})
	rc, out, errb := vulnid(t, "-dir", dir, "-list", "none")
	if rc != 0 {
		t.Fatalf("rc = %d, stderr:\n%s", rc, errb)
	}
	if !strings.Contains(out, "none (1):") || !strings.Contains(out, "ftp.gnu.org") {
		t.Errorf("want the unidentified project named:\n%s", out)
	}
	// And only that one: a list that printed everything would be useless.
	if strings.Contains(out, "curl.se  ") {
		t.Errorf("curl.se is derived and must not be listed under none:\n%s", out)
	}
}

func TestVulnIDListsDerivedWithTheirIdentities(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"curl.se/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: curl/curl\n",
	})
	_, out, _ := vulnid(t, "-dir", dir, "-list", "derived")
	if !strings.Contains(out, "GitHub:curl/curl") {
		t.Errorf("want the identity beside the project:\n%s", out)
	}
}

func TestVulnIDListsDeclared(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"openssl.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  url: http://openssl.org/s/\n  match: /x-\\d/\n",
	})
	tab := writeTable(t, "schema-version: 1\nprojects:\n  openssl.org:\n    cpe: [openssl:openssl]\n")
	_, out, _ := vulnid(t, "-dir", dir, "-table", tab, "-list", "declared")
	if !strings.Contains(out, "declared (1):") || !strings.Contains(out, "cpe:openssl:openssl") {
		t.Errorf("want the declared entry listed:\n%s", out)
	}
}

// Two identities on one project are both printed, separated. A project really
// can have two — NVD files berkeley_db under two product names — and a line
// that showed only the first would read as a complete answer.
func TestVulnIDListsEveryIdentityOfAProject(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"openssl.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  url: http://openssl.org/s/\n  match: /x-\\d/\n",
	})
	tab := writeTable(t, "schema-version: 1\nprojects:\n  openssl.org:\n    cpe: [openssl:openssl]\n    GitHub: [openssl/openssl]\n")
	_, out, _ := vulnid(t, "-dir", dir, "-table", tab, "-list", "declared")
	if !strings.Contains(out, "GitHub:openssl/openssl cpe:openssl:openssl") {
		t.Errorf("want both identities on the line:\n%s", out)
	}
}

// A project with no identity prints a placeholder rather than an empty column,
// so a truncated line cannot be read as a name.
func TestVulnIDShowsADashForNoIdentity(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"ftp.gnu.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  url: http://ftp.gnu.org/g/\n  match: /x-\\d/\n",
	})
	_, out, _ := vulnid(t, "-dir", dir, "-list", "none")
	if !strings.Contains(out, " -\n") {
		t.Errorf("want a dash for the absent identity:\n%s", out)
	}
}

// An empty corpus FAILS. This fleet has already published a zero that meant
// "could not read the corpus".
func TestVulnIDEmptyCorpusFails(t *testing.T) {
	rc, _, errb := vulnid(t, "-dir", t.TempDir())
	if rc == 0 {
		t.Fatal("an unreadable corpus reported success")
	}
	if !strings.Contains(errb, "the layout changed") {
		t.Errorf("want the reason: %q", errb)
	}
}

func TestVulnIDNamesWhatItCannotRead(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"good.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: o/r\n",
		"bad.org/package.hcl":  "build { script = \n",
	})
	rc, out, errb := vulnid(t, "-dir", dir)
	if rc == 0 {
		t.Fatal("a recipe that cannot be read reported success")
	}
	if !strings.Contains(errb, "bad.org") || !strings.Contains(errb, "nothing is claimed") {
		t.Errorf("want the unreadable recipe named: %q", errb)
	}
	// And the ones that COULD be read are still counted, so a single bad
	// recipe does not void the measurement.
	if !strings.Contains(out, "derived   1") {
		t.Errorf("want the readable recipe still counted:\n%s", out)
	}
}

func TestVulnIDRefusals(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"curl.se/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: curl/curl\n",
	})
	t.Run("a table that is not there", func(t *testing.T) {
		rc, _, errb := vulnid(t, "-dir", dir, "-table", filepath.Join(t.TempDir(), "absent.yml"))
		if rc != 1 || !strings.Contains(errb, "absent.yml") {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
	})
	t.Run("a table that does not parse", func(t *testing.T) {
		// Refused rather than ignored: a table read as empty would report
		// every declared project as having no identity.
		tab := writeTable(t, "schema-version: 1\nprojects:\n  p:\n    cpe: [openssl]\n")
		rc, _, errb := vulnid(t, "-dir", dir, "-table", tab)
		if rc != 1 || !strings.Contains(errb, "no vendor") {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
	})
	t.Run("an unknown -list value", func(t *testing.T) {
		rc, _, errb := vulnid(t, "-dir", dir, "-list", "everything")
		if rc != 2 || !strings.Contains(errb, "want declared, derived or none") {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
	})
	t.Run("an unknown flag", func(t *testing.T) {
		if rc, _, _ := vulnid(t, "-nonesuch"); rc != 2 {
			t.Errorf("rc = %d, want 2", rc)
		}
	})
	t.Run("a pantry that cannot be walked", func(t *testing.T) {
		// A tree the walk cannot descend is an error, not an empty corpus.
		//
		// ⛔ The first version of this put a FILE where projects/ should be
		// and asserted a non-zero exit. It passed, and proved nothing:
		// WalkDir on a file does not fail, it visits the file, so the run
		// took the empty-corpus path instead. Both paths exit 1, which is
		// exactly what made the wrong reason invisible — the coverage
		// profile is what gave it away.
		if os.Geteuid() == 0 {
			t.Skip("root can read an unreadable directory")
		}
		dir := lintTree(t, map[string]string{"a.org/package.yml": "versions:\n  github: o/a\n"})
		sub := filepath.Join(dir, "projects", "a.org")
		if err := os.Chmod(sub, 0o000); err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
		rc, out, errb := vulnid(t, "-dir", dir)
		if rc != 1 || !strings.Contains(errb, "vulnid:") {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
		// And it is NOT the empty-corpus message, which is the failure this
		// test exists to tell apart.
		if strings.Contains(errb, "the layout changed") {
			t.Errorf("reported an empty corpus for a walk error: %q", errb)
		}
		if out != "" {
			t.Errorf("no totals belong to a run that could not read the tree: %q", out)
		}
	})
}

// Through the top-level dispatch, which is the only thing a CI lane invokes.
func TestVulnIDDispatch(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"curl.se/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: curl/curl\n",
	})
	var out, errb bytes.Buffer
	if code := run([]string{"vulnid", "-dir", dir}, &out, &errb); code != 0 {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "derived   1") {
		t.Errorf("want the totals on stdout, got %q", out.String())
	}
}

// -list "" lists nothing and is not an error: the default must stay a summary.
func TestVulnIDWithoutListPrintsNoProjects(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"curl.se/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: curl/curl\n",
	})
	rc, out, _ := vulnid(t, "-dir", dir)
	if rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if strings.Contains(out, "curl.se") {
		t.Errorf("the summary must not list projects:\n%s", out)
	}
}

// The per-database breakdown is ordered by COUNT, then by name, so two runs
// over the same pantry print the same thing.
//
// ⛔ GitLab is given the LARGER count on purpose. The first version of this
// test gave the larger count to GitHub, where ordering by count and ordering
// by name agree — so deleting the count comparison altogether left it green.
// A test of a tie-break must put the two keys in conflict.
func TestVulnIDDatabasesAreOrderedByCount(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"a.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  gitlab: o/a\n",
		"b.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  gitlab: o/b\n",
		"c.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: o/c\n",
	})
	_, out, _ := vulnid(t, "-dir", dir)
	gh, gl := strings.Index(out, "GitHub"), strings.Index(out, "GitLab")
	if gh < 0 || gl < 0 || gl > gh {
		t.Errorf("GitLab (2) must precede GitHub (1), count before name:\n%s", out)
	}
}

// Ties break by name, which is the branch a count-only comparison leaves
// uncovered — and the one that makes the output non-deterministic.
func TestVulnIDEqualCountsAreOrderedByName(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"a.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  github: o/a\n",
		"c.org/package.yml": "distributable:\n  url: http://x/y.tgz\nversions:\n  gitlab: o/c\n",
	})
	_, out, _ := vulnid(t, "-dir", dir)
	gh, gl := strings.Index(out, "GitHub"), strings.Index(out, "GitLab")
	if gh < 0 || gl < 0 || gh > gl {
		t.Errorf("at one each, GitHub must still precede GitLab:\n%s", out)
	}
}
