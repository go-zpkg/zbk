package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
)

// provWith builds an in-toto referrer whose resolvedDependencies hold exactly
// the given URIs — the wire shape, so the reader is tested against what a
// registry serves and not against a struct we share with the writer.
func provWith(uris ...map[string]any) bottle.Referrer {
	deps := make([]map[string]any, 0, len(uris))
	deps = append(deps, uris...)
	b, _ := json.Marshal(map[string]any{
		"predicate": map[string]any{
			"buildDefinition": map[string]any{"resolvedDependencies": deps},
		},
	})
	return bottle.Referrer{ArtifactType: artifactInToto, Blob: b}
}

// ⛔⛔ "RECORDS NOTHING" AND "COULD NOT BE READ" ARE DIFFERENT ANSWERS.
// Every bottle published before bk v0.17.0 records no build environment, so a
// reader that returned a plain error for both would report the whole registry
// as broken — and a sweep built on it would be useless for deciding anything.
func TestEnvAttestedBySeparatesAbsenceFromFailure(t *testing.T) {
	if _, err := envAttestedBy(nil); !errors.Is(err, errNoProvenance) {
		t.Errorf("no attestation at all gave %v, want errNoProvenance", err)
	}
	_, err := envAttestedBy([]bottle.Referrer{provWith()})
	if !errors.Is(err, errNoEnvironment) {
		t.Errorf("an attestation with no environment gave %v, want errNoEnvironment", err)
	}
	// Malformed JSON is neither: it is a failure, and must not read as an
	// absence.
	bad := []bottle.Referrer{{ArtifactType: artifactInToto, Blob: []byte("{not json")}}
	_, err = envAttestedBy(bad)
	if err == nil || errors.Is(err, errNoEnvironment) || errors.Is(err, errNoProvenance) {
		t.Errorf("malformed provenance gave %v, want a parse failure", err)
	}
}

// IT READS THE ENVIRONMENT AND IGNORES THE SOURCE, which shares the list. The
// two are told apart by shape: a source material carries a sha256 of fetched
// bytes, an environment material carries a purl and no digest.
func TestEnvAttestedByReadsOnlyTheEnvironmentEntries(t *testing.T) {
	// ⛔ THE SOURCE URI HOLDS AN "@" ON PURPOSE. Written without one, this
	// fixture let a mutation that dropped the purl-prefix check SURVIVE: a
	// URI with no "@" is discarded by the version split anyway, so the test
	// passed for a second reason and measured nothing. A real source URI can
	// carry one — `https://user@host/...`, a tag named with one — and then
	// the prefix check is the only thing standing between a source archive
	// and being counted as a compiler.
	refs := []bottle.Referrer{provWith(
		map[string]any{"uri": "https://dl@example.com/jq-1.8.2.tar.gz", "digest": map[string]string{"sha256": "abc"}},
		map[string]any{"uri": "pkg:pkgx/go.dev@1.27.2"},
		map[string]any{"uri": "pkg:pkgx/gnu.org/glibc@2.44.0"},
	)}
	env, err := envAttestedBy(refs)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 2 {
		t.Fatalf("read %d entries, want 2: %+v", len(env), env)
	}
	// Sorted, so two bottles of the same closure compare as text.
	if env[0].Project != "gnu.org/glibc" || env[1].Project != "go.dev" {
		t.Errorf("not sorted by project: %+v", env)
	}
	if env[1].Version != "1.27.2" {
		t.Errorf("go.dev version = %q", env[1].Version)
	}
	// ⛔ THE SOURCE ARCHIVE IS NOT AN ENVIRONMENT ENTRY. Without this the
	// reader would count it and report an environment where there is none.
	for _, e := range env {
		if strings.Contains(e.Project, "example.com") {
			t.Errorf("the source archive was read as an environment entry: %+v", env)
		}
	}
}

// ⛔ THE LAST "@", because a project name is a path and a version never
// contains one. Cutting at the first would split pkg:pkgx/x@1@2 in the wrong
// place.
func TestEnvAttestedBySplitsAtTheLastAt(t *testing.T) {
	env, err := envAttestedBy([]bottle.Referrer{provWith(
		map[string]any{"uri": "pkg:pkgx/weird@name@1.2.3"},
	)})
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1 || env[0].Project != "weird@name" || env[0].Version != "1.2.3" {
		t.Errorf("split wrongly: %+v", env)
	}
	// And an entry with nothing after the "@", or nothing before it, is not
	// an entry: it is dropped rather than recorded as half of one.
	for _, u := range []string{"pkg:pkgx/x@", "pkg:pkgx/@1.2.3"} {
		if e, _ := envAttestedBy([]bottle.Referrer{provWith(map[string]any{"uri": u})}); len(e) != 0 {
			t.Errorf("%q produced %+v", u, e)
		}
	}
}

// ⛔⛔ A SWEEP MUST NOT FOLD "UNREADABLE" INTO "RECORDS NOTHING". An
// unreachable registry has told us nothing, and counting it as an absence is
// the same defect as a census that could not read reporting zero.
func TestTheSweepCountsTheThreeOutcomesSeparately(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "l.txt")
	if err := os.WriteFile(list, []byte("a.org 1\n# a comment\n\nb.org 2\nc.org 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	// The fakes now answer with what a REGISTRY answers — referrers — so
	// envAttestedBy runs for real in every case instead of being bypassed.
	sourceAttestations = func(_, proj, _, _, _ string) ([]bottle.Referrer, error) {
		switch proj {
		case "a.org":
			return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/go.dev@1.27.2"})}, nil
		case "b.org":
			return []bottle.Referrer{provWith()}, nil // an attestation recording nothing
		default:
			return nil, errors.New("dial tcp: network is unreachable")
		}
	}
	var out, errb strings.Builder
	code := sweepBuildEnv(list, "oci://x", "linux", "aarch64", requirement{}, &out, &errb)
	if code != 1 {
		t.Errorf("code = %d, want 1 (something is not recorded)", code)
	}
	got := out.String()
	if !strings.Contains(got, "3 read · 1 record a build environment · 1 record none · 1 unreadable") {
		t.Errorf("the three outcomes are not counted separately:\n%s", got)
	}
	if !strings.Contains(got, "ERROR   c.org") {
		t.Errorf("the unreadable one is not named as an error:\n%s", got)
	}
}

// AN EMPTY LIST IS A FAILURE, not a clean registry — the same rule gopin
// states for its own corpus.
func TestTheSweepRefusesAnEmptyList(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "l.txt")
	if err := os.WriteFile(list, []byte("# nothing but a comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	if code := sweepBuildEnv(list, "oci://x", "linux", "aarch64", requirement{}, &out, &errb); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "not an empty registry") {
		t.Errorf("the refusal does not say why:\n%s", errb.String())
	}
}

// A LINE THE READER CANNOT USE IS NAMED, not skipped: a silent skip makes the
// totals smaller for a reason nobody can see.
func TestAMalformedLineIsNamedRatherThanSkipped(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "l.txt")
	if err := os.WriteFile(list, []byte("a.org 1\nb.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readProjectVersions(list)
	if err == nil {
		t.Fatal("a line with one field was accepted")
	}
	if !strings.Contains(err.Error(), "l.txt:2") || !strings.Contains(err.Error(), "b.org") {
		t.Errorf("the refusal locates nothing: %v", err)
	}
}

// THE COMMAND ITSELF, through the dispatch a user reaches. The repository
// gates at 100% coverage, and a CLI entry nobody exercises is exactly where a
// flag parses wrongly or an exit status is lost.
func TestBuildEnvCommand(t *testing.T) {
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	sourceAttestations = func(_, proj, _, _, _ string) ([]bottle.Referrer, error) {
		if proj == "missing.org" {
			return []bottle.Referrer{provWith()}, nil
		}
		return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/go.dev@1.27.2"})}, nil
	}

	t.Run("one bottle, environment recorded", func(t *testing.T) {
		code, out, _ := run2(t, "buildenv", "--platform", "linux/aarch64", "a.org", "1.2.3")
		if code != 0 {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(out, "go.dev 1.27.2") {
			t.Errorf("the entry is not printed:\n%s", out)
		}
		// The totals, as everywhere else here: a command that prints a list
		// and no count leaves the reader counting lines.
		if !strings.Contains(out, "1 entry(ies) recorded") {
			t.Errorf("no total:\n%s", out)
		}
	})

	// ⛔ AN ABSENCE EXITS NON-ZERO AND SAYS WHICH BOTTLE. A script asking
	// "is this comparable?" reads the status.
	t.Run("one bottle, nothing recorded", func(t *testing.T) {
		code, _, errb := run2(t, "buildenv", "--platform", "linux/aarch64", "missing.org", "1")
		if code != 1 {
			t.Errorf("code = %d, want 1", code)
		}
		if !strings.Contains(errb, "missing.org") || !strings.Contains(errb, "no build environment") {
			t.Errorf("the refusal names neither the bottle nor the reason:\n%s", errb)
		}
	})

	t.Run("a platform that is not os/arch is refused", func(t *testing.T) {
		code, _, errb := run2(t, "buildenv", "--platform", "linux", "a.org", "1")
		if code != 2 {
			t.Errorf("code = %d, want 2", code)
		}
		if !strings.Contains(errb, "is not os/arch") {
			t.Errorf("the refusal does not say why:\n%s", errb)
		}
	})

	// Two arguments are needed, and the usage names BOTH forms — a reader
	// who wanted the sweep should not have to guess that it exists.
	t.Run("wrong argument count prints both usages", func(t *testing.T) {
		code, _, errb := run2(t, "buildenv", "--platform", "linux/aarch64", "a.org")
		if code != 2 {
			t.Errorf("code = %d, want 2", code)
		}
		if !strings.Contains(errb, "--list") {
			t.Errorf("the usage hides the sweep form:\n%s", errb)
		}
	})

	t.Run("an unknown flag is refused", func(t *testing.T) {
		if code, _, _ := run2(t, "buildenv", "--nope"); code != 2 {
			t.Errorf("code = %d, want 2", code)
		}
	})

	t.Run("the sweep runs through the command", func(t *testing.T) {
		dir := t.TempDir()
		list := filepath.Join(dir, "l.txt")
		if err := os.WriteFile(list, []byte("a.org 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		code, out, _ := run2(t, "buildenv", "--platform", "linux/aarch64", "--list", list)
		if code != 0 {
			t.Fatalf("code = %d out=%q", code, out)
		}
		if !strings.Contains(out, "1 read · 1 record a build environment") {
			t.Errorf("the sweep did not report:\n%s", out)
		}
	})

	// A list that cannot be READ is not a list that is empty.
	t.Run("an unreadable list is a refusal, not an empty sweep", func(t *testing.T) {
		code, _, errb := run2(t, "buildenv", "--platform", "linux/aarch64", "--list",
			filepath.Join(t.TempDir(), "absent.txt"))
		if code != 2 {
			t.Errorf("code = %d, want 2", code)
		}
		if strings.Contains(errb, "not an empty registry") {
			t.Errorf("an unreadable list was reported as an empty one:\n%s", errb)
		}
	})
}

// WITH NO --platform IT ASKS THE MACHINE, which is the default a person gets.
func TestBuildEnvDefaultsToThisMachine(t *testing.T) {
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	var gotOS, gotArch string
	sourceAttestations = func(_, _, _, osn, arch string) ([]bottle.Referrer, error) {
		gotOS, gotArch = osn, arch
		return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/go.dev@1.27.2"})}, nil
	}
	if code, _, errb := run2(t, "buildenv", "a.org", "1.2.3"); code != 0 {
		t.Fatalf("code = %d err=%q", code, errb)
	}
	if gotOS == "" || gotArch == "" {
		t.Errorf("the default platform resolved to %q/%q", gotOS, gotArch)
	}
}

// ⛔ AND WHEN THE MACHINE CANNOT BE RESOLVED, it says so instead of reading
// the registry for a platform it invented.
//
// No seam for this: target.Resolve() reads ZPKB_TARGET, and a platform bk
// does not support makes the real function fail — the same case that once made
// `bk lint` refuse to run. A fake would test the fake.
func TestBuildEnvRefusesAnUnsupportedTarget(t *testing.T) {
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	reached := false
	sourceAttestations = func(_, _, _, _, _ string) ([]bottle.Referrer, error) {
		reached = true
		return nil, nil
	}
	t.Setenv("ZPKB_TARGET", "plan9/pdp11")

	var out, errb strings.Builder
	// Not through run2: it clears ZPKB_TARGET on purpose, which is the
	// right thing for every other test here and the wrong thing for this one.
	code := runBuildEnv([]string{"a.org", "1.2.3"}, &out, &errb)
	if code != 2 {
		t.Errorf("code = %d, want 2; stderr=%q", code, errb.String())
	}
	if reached {
		t.Error("it read the registry for a platform it could not resolve")
	}
	if errb.Len() == 0 {
		t.Error("it refused in silence")
	}
}

// ⛔⛔ "DOES NOT USE IT" IS NEITHER STALE NOR OK, and keeping it apart is the
// whole care in judge().
//
// A C package has no `go.dev`. Counted as STALE it would rebuild the entire
// registry for a Go release; counted as OK it would make the figure
// meaningless. That is the mistake a denylist makes when it inherits a
// taxonomy's blind spot.
func TestJudgeKeepsFourOutcomesApart(t *testing.T) {
	want := requirement{Project: "go.dev", Version: "1.27.2"}
	for name, c := range map[string]struct {
		env  []attestedEnv
		want envVerdict
	}{
		"nothing recorded":   {nil, vUnknown},
		"older compiler":     {[]attestedEnv{{"go.dev", "1.27.1"}}, vStale},
		"the wanted version": {[]attestedEnv{{"go.dev", "1.27.2"}}, vOK},
		"a newer one":        {[]attestedEnv{{"go.dev", "1.28.0"}}, vOK},
		"a C package":        {[]attestedEnv{{"gnu.org/glibc", "2.44.0"}}, vNotUsed},
		// ⛔ A REBUILD OF THE COMPILER COUNTS. go.dev 1.27.1_1 is 1.27.1 built
		// again, which does NOT contain the fix that landed in 1.27.2.
		"a rebuild of the old one": {[]attestedEnv{{"go.dev", "1.27.1_1"}}, vStale},
	} {
		if got := judge(c.env, want); got != c.want {
			t.Errorf("%s: judge = %v, want %v", name, got, c.want)
		}
	}
}

// -needs REFUSES WHAT IT CANNOT MEAN rather than judging against nonsense.
func TestNeedsRefusesWhatItCannotMean(t *testing.T) {
	for _, s := range []string{"go.dev", "@1.27.2", "go.dev@", "go.dev@1.2.3\x1b[2K"} {
		if _, err := parseRequirement(s); err == nil {
			t.Errorf("%q was accepted as a requirement", s)
		}
	}
	// THE POSITIVE CONTROL, without which the four above would pass on a
	// parser that accepts nothing.
	r, err := parseRequirement("go.dev@1.27.2")
	if err != nil || r.Project != "go.dev" || r.Version != "1.27.2" {
		t.Errorf("a real requirement was refused: %+v %v", r, err)
	}
}

// THE SWEEP COUNTS THE JUDGEMENT SEPARATELY FROM THE READING, and says both.
// A sweep that reported "3 stale" without saying how many it could not judge
// would be read as "3 of 3".
func TestTheSweepSaysWhatItCouldNotJudge(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "l.txt")
	if err := os.WriteFile(list, []byte("old.org 1\nnew.org 1\nc.org 1\nblank.org 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	sourceAttestations = func(_, proj, _, _, _ string) ([]bottle.Referrer, error) {
		switch proj {
		case "old.org":
			return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/go.dev@1.27.1"})}, nil
		case "new.org":
			return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/go.dev@1.27.2"})}, nil
		case "c.org":
			return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/gnu.org/glibc@2.44.0"})}, nil
		default:
			return []bottle.Referrer{provWith()}, nil
		}
	}
	var out, errb strings.Builder
	code := sweepBuildEnv(list, "oci://x", "linux", "aarch64",
		requirement{Project: "go.dev", Version: "1.27.2"}, &out, &errb)
	if code != 1 {
		t.Errorf("code = %d, want 1 (something is stale)", code)
	}
	got := out.String()
	if !strings.Contains(got, "of those: 1 need rebuilding for go.dev>=1.27.2 · 1 already have it · 1 never used it") {
		t.Errorf("the judgement is not counted in four:\n%s", got)
	}
	// ⛔ AND IT SAYS WHAT IT COULD NOT JUDGE. Without this line the reader
	// takes "1 need rebuilding" for the whole answer.
	if !strings.Contains(got, "1 record nothing, so this says nothing about them") {
		t.Errorf("the unjudgeable bottle is not named as such:\n%s", got)
	}
	// The stale line carries the version it HAS, not only that it is old.
	if !strings.Contains(got, "STALE   old.org 1: go.dev 1.27.1, want >=1.27.2") {
		t.Errorf("the stale line does not say which version it has:\n%s", got)
	}
}

// WITHOUT -needs IT DOES NOT JUDGE, and must not print a verdict nobody asked
// for.
func TestWithoutNeedsThereIsNoJudgement(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "l.txt")
	if err := os.WriteFile(list, []byte("a.org 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	sourceAttestations = func(_, _, _, _, _ string) ([]bottle.Referrer, error) {
		return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/go.dev@1.0.0"})}, nil
	}
	var out, errb strings.Builder
	if code := sweepBuildEnv(list, "oci://x", "linux", "aarch64", requirement{}, &out, &errb); code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if strings.Contains(out.String(), "need rebuilding") || strings.Contains(out.String(), "STALE") {
		t.Errorf("it judged without being asked:\n%s", out.String())
	}
	// ⛔ AND THE PLAIN LINE IS STILL THERE. Asserting only the ABSENCE of a
	// verdict let a mutation through: routed into the judgement with an empty
	// requirement, nothing matches the empty project name, so every bottle
	// prints "n/a" — which contains neither "STALE" nor "need rebuilding"
	// and passed. A negative assertion needs its positive beside it.
	if !strings.Contains(out.String(), "env     a.org 1: 1 entry(ies)") {
		t.Errorf("the plain reading line is missing:\n%s", out.String())
	}
}

// -needs THROUGH THE COMMAND, both the good path and the refusal. The flag is
// parsed in runBuildEnv, so a test on parseRequirement alone leaves the wiring
// — and its exit status — unexercised.
func TestNeedsThroughTheCommand(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "l.txt")
	if err := os.WriteFile(list, []byte("old.org 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	sourceAttestations = func(_, _, _, _, _ string) ([]bottle.Referrer, error) {
		return []bottle.Referrer{provWith(map[string]any{"uri": "pkg:pkgx/go.dev@1.27.1"})}, nil
	}

	t.Run("a stale bottle exits non-zero and says which version it has", func(t *testing.T) {
		code, out, _ := run2(t, "buildenv", "--platform", "linux/aarch64",
			"--needs", "go.dev@1.27.2", "--list", list)
		if code != 1 {
			t.Errorf("code = %d, want 1", code)
		}
		if !strings.Contains(out, "STALE   old.org 1: go.dev 1.27.1") {
			t.Errorf("the stale line is missing:\n%s", out)
		}
	})

	// ⛔ A MALFORMED REQUIREMENT IS REFUSED BEFORE ANY READING. Judging
	// against nonsense would produce a verdict somebody might act on.
	t.Run("a malformed requirement is refused", func(t *testing.T) {
		reached := false
		sourceAttestations = func(_, _, _, _, _ string) ([]bottle.Referrer, error) {
			reached = true
			return nil, nil
		}
		code, _, errb := run2(t, "buildenv", "--platform", "linux/aarch64",
			"--needs", "go.dev", "--list", list)
		if code != 2 {
			t.Errorf("code = %d, want 2", code)
		}
		if reached {
			t.Error("it read the registry before refusing the requirement")
		}
		if !strings.Contains(errb, "not project@version") {
			t.Errorf("the refusal does not say why:\n%s", errb)
		}
	})
}

// versionOf answers "" for a project the environment does not hold — which is
// the shape the n/a line relies on, and the branch the four-outcome test
// reaches only through judge().
func TestVersionOfAProjectThatIsNotThere(t *testing.T) {
	env := []attestedEnv{{Project: "go.dev", Version: "1.27.2"}}
	if got := versionOf(env, "go.dev"); got != "1.27.2" {
		t.Errorf("versionOf = %q", got)
	}
	if got := versionOf(env, "gnu.org/glibc"); got != "" {
		t.Errorf("versionOf of an absent project = %q, want empty", got)
	}
}
