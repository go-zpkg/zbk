package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/go-zpkg/artifact"
)

// mkStore lays out a pkgx store: one copy of the Mach-O fixture per project.
// testdata/libthing.1.dylib names @rpath/other.org/dep/v2/lib/libdep.2.dylib.
func mkStore(t *testing.T, projects ...string) string {
	t.Helper()
	lib, err := os.ReadFile(filepath.Join("testdata", "libthing.1.dylib"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, p := range projects {
		d := filepath.Join(dir, filepath.FromSlash(p), "v1.0.0", "lib")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "libthing.1.dylib"), lib, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Things that are not Mach-O, which a store is full of: one outside any
	// project (no owner) and one inside one (an owner, and not an object).
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not an object\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if len(projects) > 0 {
		d := filepath.Join(dir, filepath.FromSlash(projects[0]), "v1.0.0", "share")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "NOTES"), []byte("prose\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRefsByOwner(t *testing.T) {
	dir := mkStore(t, "acme.org/thing", "gnu.org/nettle")
	got := refsByOwner(dir)
	if len(got) != 2 {
		t.Fatalf("owners = %v", got)
	}
	for _, owner := range []string{"acme.org/thing", "gnu.org/nettle"} {
		if !got[owner]["other.org/dep"] {
			t.Errorf("%s did not report its reference: %v", owner, got[owner])
		}
	}
}

func TestOwnerOf(t *testing.T) {
	for _, tc := range []struct {
		rel, want string
		ok        bool
	}{
		{"gnupg.org/gpgme/v1.19.0/lib/libgpgme.11.dylib", "gnupg.org/gpgme", true},
		{"zlib.net/v1.3.2/lib/libz.1.dylib", "zlib.net", true},
		{"README", "", false},
		{"zlib.net/lib/libz.dylib", "", false},
	} {
		got, ok := ownerOf(tc.rel)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ownerOf(%q) = %q,%v; want %q,%v", tc.rel, got, ok, tc.want, tc.ok)
		}
	}
}

// Reachability is TRANSITIVE. rust-lang.org/cargo links libssh2 and openssl and
// declares neither, because libgit2.org brings both and says so — that is a
// declaration one hop further out, and counting it as a defect is what made the
// first version of this over-report.
func TestUndeclaredOfFollowsDeclarationsTransitively(t *testing.T) {
	g := &artifact.Graph{Deps: map[string][]artifact.Edge{
		"app.org": {{Of: "app.org", On: "mid.org"}},
		"mid.org": {{Of: "mid.org", On: "deep.org"}},
	}}
	// app.org references something two hops away: declared, through mid.org.
	if got := undeclaredOf("app.org", map[string]bool{"deep.org": true}, g); len(got) != 0 {
		t.Errorf("a transitively declared edge was reported: %v", got)
	}
	// and something nobody declares
	got := undeclaredOf("app.org", map[string]bool{"deep.org": true, "stranger.org": true}, g)
	if len(got) != 1 || got[0] != "stranger.org" {
		t.Errorf("undeclaredOf = %v, want [stranger.org]", got)
	}
	// a project never references itself into a defect
	if got := undeclaredOf("app.org", map[string]bool{"app.org": true}, g); len(got) != 0 {
		t.Errorf("self-reference reported: %v", got)
	}
}

func TestUndeclaredProjects(t *testing.T) {
	got, err := undeclaredProjects(nil, strings.NewReader("# c\n\na.org\n b.org 1.2\n"))
	if err != nil || len(got) != 2 || got[0] != "a.org" || got[1] != "b.org" {
		t.Fatalf("undeclaredProjects = %v, %v", got, err)
	}
	if got, _ := undeclaredProjects([]string{"x.org"}, strings.NewReader("ignored")); len(got) != 1 {
		t.Errorf("arguments did not win: %v", got)
	}
}

// End to end against the seams: an undeclared edge is reported, named, and the
// exit status says so.
func TestRunUndeclared(t *testing.T) {
	store := mkStore(t, "gnu.org/nettle")
	oldG, oldI := undeclaredGraph, undeclaredInstall
	defer func() { undeclaredGraph, undeclaredInstall = oldG, oldI }()
	undeclaredGraph = func(map[string]string, string, string) (*artifact.Graph, error) {
		return &artifact.Graph{Deps: map[string][]artifact.Edge{}}, nil
	}
	undeclaredInstall = func(map[string]string, string) ([]artifact.Resolved, error) { return nil, nil }

	code, out, _ := run2(t, "undeclared", "--store", store, "gnu.org/nettle")
	if code != 1 {
		t.Errorf("exit = %d, want 1 when something is undeclared", code)
	}
	if !strings.Contains(out, "gnu.org/nettle") || !strings.Contains(out, "other.org/dep") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(out, "1 undeclared edge(s)") {
		t.Errorf("the total is missing:\n%s", out)
	}
}

// Everything declared: nothing printed but the total, and a zero status.
func TestRunUndeclaredAllDeclared(t *testing.T) {
	store := mkStore(t, "gnu.org/nettle")
	oldG, oldI := undeclaredGraph, undeclaredInstall
	defer func() { undeclaredGraph, undeclaredInstall = oldG, oldI }()
	undeclaredGraph = func(map[string]string, string, string) (*artifact.Graph, error) {
		return &artifact.Graph{Deps: map[string][]artifact.Edge{
			"gnu.org/nettle": {{Of: "gnu.org/nettle", On: "other.org/dep"}},
		}}, nil
	}
	undeclaredInstall = func(map[string]string, string) ([]artifact.Resolved, error) { return nil, nil }

	code, out, _ := run2(t, "undeclared", "--store", store, "gnu.org/nettle")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if strings.Contains(out, "links but does not declare") {
		t.Errorf("a declared edge was reported:\n%s", out)
	}
}

// No projects at all is a usage error, not an empty success.
//
// stdin is set explicitly: the first version let it default to the test
// process's own, which is whatever the harness happened to leave there. It
// passed on darwin and linux and failed on all three BSD lanes, where the job
// runs over ssh — a test that reads the ambient stdin is testing the harness.
func TestRunUndeclaredWithNothingToDo(t *testing.T) {
	old := undeclaredStdin
	defer func() { undeclaredStdin = old }()
	undeclaredStdin = strings.NewReader("")
	if code, _, _ := run2(t, "undeclared"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

// An unknown flag is a usage error, and the message goes to stderr.
func TestRunUndeclaredBadFlag(t *testing.T) {
	if code, _, _ := run2(t, "undeclared", "--nope"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

// A project whose graph or install fails is reported and the sweep carries on:
// one unreachable recipe must not decide the answer for the rest.
func TestRunUndeclaredKeepsGoingPastAFailure(t *testing.T) {
	store := mkStore(t, "gnu.org/nettle")
	oldG, oldI := undeclaredGraph, undeclaredInstall
	defer func() { undeclaredGraph, undeclaredInstall = oldG, oldI }()

	undeclaredGraph = func(roots map[string]string, _, _ string) (*artifact.Graph, error) {
		if roots["broken.org"] != "" {
			return nil, errors.New("no such project")
		}
		return &artifact.Graph{Deps: map[string][]artifact.Edge{}}, nil
	}
	undeclaredInstall = func(roots map[string]string, _ string) ([]artifact.Resolved, error) {
		if roots["offline.org"] != "" {
			return nil, errors.New("registry unreachable")
		}
		return nil, nil
	}
	code, out, errb := run2(t, "undeclared", "--store", store, "broken.org", "offline.org", "gnu.org/nettle")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	for _, want := range []string{"no such project", "registry unreachable"} {
		if !strings.Contains(errb, want) {
			t.Errorf("stderr missing %q: %s", want, errb)
		}
	}
	if !strings.Contains(out, "gnu.org/nettle") {
		t.Errorf("the reachable project was not swept:\n%s", out)
	}
}

// With no --store the command makes its own and removes it, so a sweep leaves
// nothing behind on a machine that may have hundreds of closures a day.
func TestRunUndeclaredMakesAndRemovesItsOwnStore(t *testing.T) {
	var made string
	oldT, oldG, oldI := undeclaredTempDir, undeclaredGraph, undeclaredInstall
	defer func() { undeclaredTempDir, undeclaredGraph, undeclaredInstall = oldT, oldG, oldI }()
	undeclaredTempDir = func(dir, pattern string) (string, error) {
		d, err := os.MkdirTemp(dir, pattern)
		made = d
		return d, err
	}
	undeclaredGraph = func(map[string]string, string, string) (*artifact.Graph, error) {
		return &artifact.Graph{Deps: map[string][]artifact.Edge{}}, nil
	}
	undeclaredInstall = func(map[string]string, string) ([]artifact.Resolved, error) { return nil, nil }

	if code, _, _ := run2(t, "undeclared", "a.org"); code != 0 {
		t.Errorf("exit = %d, want 0 for an empty store", code)
	}
	if made == "" {
		t.Fatal("no temporary store was made")
	}
	if _, err := os.Stat(made); !os.IsNotExist(err) {
		t.Errorf("the temporary store survived: %s", made)
	}
}

// And when it cannot make one, it says so rather than writing somewhere else.
func TestRunUndeclaredCannotMakeAStore(t *testing.T) {
	old := undeclaredTempDir
	defer func() { undeclaredTempDir = old }()
	undeclaredTempDir = func(string, string) (string, error) { return "", errors.New("no space") }
	code, _, errb := run2(t, "undeclared", "a.org")
	if code != 1 || !strings.Contains(errb, "no space") {
		t.Errorf("exit=%d stderr=%q", code, errb)
	}
}

// A reader that fails mid-list is an error, not a short list: solving half a
// pantry and reporting it as the whole answer is the worse outcome.
func TestUndeclaredProjectsOnAFailingReader(t *testing.T) {
	if _, err := undeclaredProjects(nil, iotest.ErrReader(errors.New("boom"))); err == nil {
		t.Error("a failing reader read as an empty list")
	}
}

// Two projects sharing one store: an owner already reported is not reported
// twice, however many closures it turns up in.
func TestRunUndeclaredReportsAnOwnerOnce(t *testing.T) {
	store := mkStore(t, "gnu.org/nettle")
	oldG, oldI := undeclaredGraph, undeclaredInstall
	defer func() { undeclaredGraph, undeclaredInstall = oldG, oldI }()
	undeclaredGraph = func(map[string]string, string, string) (*artifact.Graph, error) {
		return &artifact.Graph{Deps: map[string][]artifact.Edge{}}, nil
	}
	undeclaredInstall = func(map[string]string, string) ([]artifact.Resolved, error) { return nil, nil }

	_, out, _ := run2(t, "undeclared", "--store", store, "a.org", "b.org")
	if n := strings.Count(out, "gnu.org/nettle"); n != 1 {
		t.Errorf("the owner was reported %d times:\n%s", n, out)
	}
}

// A stdin that fails mid-list stops the command: solving half a pantry and
// reporting it as the whole answer is the worse outcome.
func TestRunUndeclaredOnAFailingStdin(t *testing.T) {
	old := undeclaredStdin
	defer func() { undeclaredStdin = old }()
	undeclaredStdin = iotest.ErrReader(errors.New("pipe broke"))
	code, _, errb := run2(t, "undeclared")
	if code != 1 || !strings.Contains(errb, "pipe broke") {
		t.Errorf("exit=%d stderr=%q", code, errb)
	}
}
