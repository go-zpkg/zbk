package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// stubRegistry answers the two registry reads nextRebuild makes: which
// versions are tagged, and which of them are published for a platform.
func stubRegistry(t *testing.T, tags []string, publishedOn map[string][]string, err error) {
	t.Helper()
	oldV, oldP := versionsFor, publishedTagFor
	t.Cleanup(func() { versionsFor, publishedTagFor = oldV, oldP })

	versionsFor = func(_, _, _ string) ([]artifact.Ver, bool, error) {
		if err != nil {
			return nil, false, err
		}
		out := make([]artifact.Ver, 0, len(tags))
		for _, s := range tags {
			out = append(out, artifact.ParseVer(s))
		}
		return out, true, nil
	}
	publishedTagFor = func(_ string, v artifact.Ver, osn, arch string) (string, bool, error) {
		for _, s := range publishedOn[osn+"/"+arch] {
			if s == v.Raw {
				return v.Raw, true, nil
			}
		}
		return "", false, nil
	}
}

// TestTheFirstRebuildIsOne: the version is published, so a new build of it
// supersedes rather than replaces.
func TestTheFirstRebuildIsOne(t *testing.T) {
	stubRegistry(t, []string{"3.3.11"}, map[string][]string{"darwin/aarch64": {"3.3.11"}}, nil)
	n, err := nextRebuild("fftw.org", "3.3.11", "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("nextRebuild = %d, want 1", n)
	}
	if got := rebuiltVersion("3.3.11", n); got != "3.3.11_1" {
		t.Errorf("rebuiltVersion = %q, want 3.3.11_1", got)
	}
}

// ⛔ TestNothingPublishedMeansNoCounter. A `_1` on a version that is not here
// claims a predecessor that does not exist, and would sort AFTER a plain
// `3.3.11` published later — so the first artifact of a version must be plain.
func TestNothingPublishedMeansNoCounter(t *testing.T) {
	stubRegistry(t, []string{"3.3.11"}, map[string][]string{"linux/x86-64": {"3.3.11"}}, nil)
	n, err := nextRebuild("fftw.org", "3.3.11", "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("nextRebuild = %d on a platform with nothing published, want 0", n)
	}
	if got := rebuiltVersion("3.3.11", n); got != "3.3.11" {
		t.Errorf("rebuiltVersion = %q, want the plain version", got)
	}
}

// ⛔⛔ TestTheCounterIsPerPlatform is the one that does damage if wrong. A tag
// listing spans EVERY platform, so counting tags rather than publications
// would let a darwin rebuild take its number from a linux one — leaving a gap
// on one platform and a collision on the other.
func TestTheCounterIsPerPlatform(t *testing.T) {
	stubRegistry(t,
		[]string{"3.3.11", "3.3.11_1", "3.3.11_2"},
		map[string][]string{
			"linux/x86-64":   {"3.3.11", "3.3.11_1", "3.3.11_2"},
			"darwin/aarch64": {"3.3.11"},
		}, nil)

	if n, _ := nextRebuild("fftw.org", "3.3.11", "linux", "x86-64"); n != 3 {
		t.Errorf("linux next = %d, want 3", n)
	}
	if n, _ := nextRebuild("fftw.org", "3.3.11", "darwin", "aarch64"); n != 1 {
		t.Errorf("darwin next = %d, want 1 — it counted linux's rebuilds", n)
	}
}

// TestAnotherVersionsRebuildsAreNotCounted: `3.3.12_4` says nothing about how
// many times `3.3.11` has been rebuilt.
func TestAnotherVersionsRebuildsAreNotCounted(t *testing.T) {
	stubRegistry(t,
		[]string{"3.3.11", "3.3.12", "3.3.12_4"},
		map[string][]string{"darwin/aarch64": {"3.3.11", "3.3.12", "3.3.12_4"}}, nil)

	n, err := nextRebuild("fftw.org", "3.3.11", "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("nextRebuild = %d, want 1 — a neighbour's counter leaked in", n)
	}
}

// ⛔ TestAnUnreadableRegistryRefusesRatherThanGuesses. A guessed number is a
// COLLISION: two lanes both thinking they are _1 would have one overwrite the
// other, which is the defect this whole mechanism exists to stop.
func TestAnUnreadableRegistryRefusesRatherThanGuesses(t *testing.T) {
	stubRegistry(t, nil, nil, errors.New("dial tcp: connection refused"))
	_, err := nextRebuild("fftw.org", "3.3.11", "darwin", "aarch64")
	if err == nil {
		t.Fatal("an unreadable registry produced a rebuild number")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the error does not carry the registry's reason: %v", err)
	}
}

// ⛔ AND A PUBLICATION CHECK THAT FAILS IS ALSO A REFUSAL, not a skip. If
// "is this one published?" errors and the loop simply moves on, the highest
// rebuild found is lower than the real one and the next build collides with
// an existing tag.
func TestAFailedPublicationCheckRefuses(t *testing.T) {
	oldV, oldP := versionsFor, publishedTagFor
	t.Cleanup(func() { versionsFor, publishedTagFor = oldV, oldP })
	versionsFor = func(_, _, _ string) ([]artifact.Ver, bool, error) {
		return []artifact.Ver{artifact.ParseVer("3.3.11")}, true, nil
	}
	publishedTagFor = func(string, artifact.Ver, string, string) (string, bool, error) {
		return "", false, errors.New("registry said 500")
	}
	_, err := nextRebuild("fftw.org", "3.3.11", "darwin", "aarch64")
	if err == nil {
		t.Fatal("a failed publication check produced a rebuild number")
	}
	for _, want := range []string{"3.3.11", "darwin/aarch64", "500"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q: %v", want, err)
		}
	}
}

// ⛔ END TO END THROUGH THE FACTORY, because every test above calls
// nextRebuild directly and would pass unchanged if --rebuild were wired to
// nothing. This is the one that proves the flag reaches the published tag.
func TestTheFactoryPublishesTheRebuiltVersion(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	// The harness offers two versions. Publishing only 2.0 makes the two
	// cases appear in ONE run: the published one must gain a counter, the
	// unpublished one must not. A test where every version behaves alike
	// cannot tell "the flag works" from "the flag is on for everything".
	stubRegistry(t, []string{"2.0"}, map[string][]string{"linux/x86-64": {"2.0"}}, nil)

	code := h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
		"--platform", "linux/x86-64", "--rebuild", "--force")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if len(h.published) == 0 {
		t.Fatal("nothing was published, so nothing is asserted")
	}
	want := map[string]string{"2.0": "2.0_1", "1.0": "1.0"}
	seen := map[string]bool{}
	for _, p := range h.published {
		seen[p.version] = true
	}
	for built, expect := range want {
		if !seen[expect] {
			t.Errorf("a build of %s published %v, want %q", built, keysOf(seen), expect)
		}
	}
}

// ⛔ AND THE FACTORY FAILS THE PROJECT RATHER THAN PUBLISHING WITHOUT A
// NUMBER. This is the branch that matters most and the easiest to get wrong:
// if an unreadable registry fell through to "no counter", a rebuild would
// quietly REPLACE the tag it was supposed to supersede — the exact outcome
// --rebuild exists to prevent, reached by the error path.
func TestAFactoryRebuildFailsRatherThanPublishingUnnumbered(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	stubRegistry(t, nil, nil, errors.New("dial tcp: connection refused"))

	h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
		"--platform", "linux/x86-64", "--rebuild", "--force")

	if len(h.published) != 0 {
		t.Errorf("%d artifact(s) published although the rebuild number could not be read", len(h.published))
	}
	detail := h.detailFile(t)
	if !strings.Contains(detail, "rebuild") || !strings.Contains(detail, "connection refused") {
		t.Errorf("the failure is not attributed to the rebuild read:\n%s", detail)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRebuiltVersionLeavesZeroAlone, because `3.3.11_0` is a spelling of
// `3.3.11` that nothing else in the fleet produces, and two spellings of one
// artifact is what the tag rules exist to prevent.
func TestRebuiltVersionLeavesZeroAlone(t *testing.T) {
	if got := rebuiltVersion("3.3.11", 0); got != "3.3.11" {
		t.Errorf("rebuiltVersion(…, 0) = %q, want 3.3.11", got)
	}
}

// TestSameNumsIgnoresTheCounterAndNothingElse.
func TestSameNumsIgnoresTheCounterAndNothingElse(t *testing.T) {
	if !sameNums(artifact.ParseVer("3.3.11_7"), artifact.ParseVer("3.3.11")) {
		t.Error("a rebuild is not recognised as the same version")
	}
	if sameNums(artifact.ParseVer("3.3.11"), artifact.ParseVer("3.3.1")) {
		t.Error("3.3.1 and 3.3.11 were treated as the same version")
	}
	if sameNums(artifact.ParseVer("3.3.11"), artifact.ParseVer("3.3.11.0")) {
		t.Error("a different component count was treated as the same version")
	}
}
