package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// fakePublication installs the two seams for the duration of a test:
// `published` is the set of "project@version" the registry carries, and
// `newest` is what PickVersionFor would answer per project.
func fakePublication(t *testing.T, published map[string]bool, newest map[string]string) {
	t.Helper()
	oldTag, oldPick := lockPublishedTagFor, lockPickPublished
	lockPublishedTagFor = func(project string, v artifact.Ver, osn, arch string) (string, bool, error) {
		if published[project+"@"+v.Raw] {
			return v.Raw + "--" + osn + "-" + arch, true, nil
		}
		return "", false, nil
	}
	lockPickPublished = func(project, constraint, osn, arch string) (artifact.Ver, error) {
		if v, ok := newest[project]; ok {
			return artifact.ParseVer(v), nil
		}
		return artifact.Ver{}, errors.New("nothing published")
	}
	t.Cleanup(func() { lockPublishedTagFor, lockPickPublished = oldTag, oldPick })
}

// fakeConstrainedPick installs the `-runnable` resolver and RECORDS the
// constraints it was handed, because dropping them was the defect.
func fakeConstrainedPick(t *testing.T, answer func(project string, constraints []string) (string, error)) *map[string][]string {
	t.Helper()
	seen := map[string][]string{}
	old := lockPickPublishedAll
	lockPickPublishedAll = func(project string, constraints []string, osn, arch string) (artifact.Ver, error) {
		seen[project] = constraints
		v, err := answer(project, constraints)
		if err != nil {
			return artifact.Ver{}, err
		}
		return artifact.ParseVer(v), nil
	}
	t.Cleanup(func() { lockPickPublishedAll = old })
	return &seen
}

// ⛔ A LOCK PINNED WHAT COULD NOT BE INSTALLED AND SAID NOTHING. Measured
// 2026-10-09: `bk lock -platform linux/aarch64 curl.se` pinned
// curl.se/ca-certs 2026.09.25 and openssl.org 4.0.3, neither published, and
// `pkgx --lock` refused the file in a FROM-scratch container. 2 pins of 5,
// and the writing of it was silent.
func TestLockNamesThePinsThePlatformCannotInstall(t *testing.T) {
	fakePublication(t,
		map[string]bool{
			"curl.se@8.17.0":     true,
			"nghttp2.org@1.70.0": true,
			"zlib.net@1.3.2":     true,
		},
		map[string]string{
			"curl.se/ca-certs": "2026.8.13",
			"openssl.org":      "4.0.2",
		})
	pins := []lockedPin{
		{Project: "curl.se", Version: "8.17.0"},
		{Project: "curl.se/ca-certs", Version: "2026.09.25"},
		{Project: "nghttp2.org", Version: "1.70.0"},
		{Project: "openssl.org", Version: "4.0.3"},
		{Project: "zlib.net", Version: "1.3.2"},
	}
	bad, failed := unpublishedPins(pins, "linux", "aarch64")
	if len(failed) != 0 {
		t.Fatalf("unexpected lookup failures: %v", failed)
	}
	if len(bad) != 2 {
		t.Fatalf("found %d unpublished pins, want 2: %+v", len(bad), bad)
	}
	var b strings.Builder
	reportUnpublished(&b, pins, bad, failed, "linux/aarch64", artifact.PinsFromRecipes, 0)
	got := b.String()
	for _, want := range []string{
		"2 of 5 pin(s) NOT published",
		"curl.se/ca-certs",
		"2026.09.25",
		"published here: 2026.8.13", // what you COULD have had
		"openssl.org",
		"pkgx --lock` cannot run it",
		"`bk lock -runnable`", // and what to do about it
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not contain %q:\n%s", want, got)
		}
	}
	// AND IT DOES NOT ACCUSE THE PUBLISHED ONES.
	for _, fine := range []string{"nghttp2.org", "zlib.net"} {
		if strings.Contains(got, fine) {
			t.Errorf("%s is published but was named:\n%s", fine, got)
		}
	}
}

// THE CLEAN CASE IS SAID OUT LOUD. The defect this replaces was a silence;
// a conditional message would leave "all installable" looking exactly like a
// bk that does not check at all.
func TestLockSaysSoWhenEveryPinIsInstallable(t *testing.T) {
	fakePublication(t, map[string]bool{"zlib.net@1.3.2": true}, nil)
	pins := []lockedPin{{Project: "zlib.net", Version: "1.3.2"}}
	bad, failed := unpublishedPins(pins, "linux", "aarch64")
	if len(bad) != 0 || len(failed) != 0 {
		t.Fatalf("bad=%+v failed=%v", bad, failed)
	}
	var b strings.Builder
	reportUnpublished(&b, pins, bad, failed, "linux/aarch64", artifact.PinsFromRecipes, 0)
	got := b.String()
	if !strings.Contains(got, "1 of 1 pin(s) published") || !strings.Contains(got, "can run this file") {
		t.Errorf("a clean lock said nothing useful:\n%s", got)
	}
}

// ⛔ A LOOKUP THAT COULD NOT BE MADE IS NOT A PASS. Treating a registry
// error as "published" is how a check becomes decoration — the same shape as
// `pkgx outdated` printing nothing with the network down.
func TestAFailedLookupIsNotTreatedAsPublished(t *testing.T) {
	oldTag := lockPublishedTagFor
	lockPublishedTagFor = func(string, artifact.Ver, string, string) (string, bool, error) {
		return "", false, errors.New("dial tcp: network is unreachable")
	}
	t.Cleanup(func() { lockPublishedTagFor = oldTag })

	pins := []lockedPin{{Project: "zlib.net", Version: "1.3.2"}}
	bad, failed := unpublishedPins(pins, "linux", "aarch64")
	if len(failed) != 1 {
		t.Fatalf("a failed lookup was not reported: bad=%+v failed=%v", bad, failed)
	}
	// NOT counted as unpublished either: we do not know, and saying either
	// thing would be making it up.
	if len(bad) != 0 {
		t.Errorf("a failed lookup was reported as unpublished: %+v", bad)
	}
	var b strings.Builder
	reportUnpublished(&b, pins, bad, failed, "linux/aarch64", artifact.PinsFromRecipes, 0)
	got := b.String()
	if !strings.Contains(got, "could NOT be asked about") || !strings.Contains(got, "not an all-clear") {
		t.Errorf("the report reads as a pass:\n%s", got)
	}
	if strings.Contains(got, "can run this file") {
		t.Errorf("an unasked question was reported as a clean lock:\n%s", got)
	}
}

// A PROJECT WITH NOTHING PUBLISHED AT ALL reads differently from one that is
// merely behind: there is no version to fall back to, and the report must
// not print an empty one.
func TestAProjectWithNothingPublishedSaysThat(t *testing.T) {
	fakePublication(t, nil, nil)
	pins := []lockedPin{{Project: "brand.new", Version: "0.1.0"}}
	bad, failed := unpublishedPins(pins, "linux", "aarch64")
	if len(bad) != 1 || bad[0].Published != "" {
		t.Fatalf("bad=%+v failed=%v", bad, failed)
	}
	var b strings.Builder
	reportUnpublished(&b, pins, bad, failed, "linux/aarch64", artifact.PinsFromRecipes, 0)
	if !strings.Contains(b.String(), "nothing published here") {
		t.Errorf("an unpublished project read as behind:\n%s", b.String())
	}
}

// IN -runnable MODE THE REMEDY IS NOT OFFERED, because it is already in use:
// a message telling you to pass the flag you passed is noise.
func TestTheRemedyIsNotOfferedToSomebodyAlreadyUsingIt(t *testing.T) {
	fakePublication(t, nil, map[string]string{"a.org": "1.0.0"})
	pins := []lockedPin{{Project: "a.org", Version: "2.0.0"}}
	bad, failed := unpublishedPins(pins, "linux", "aarch64")
	var b strings.Builder
	reportUnpublished(&b, pins, bad, failed, "linux/aarch64", artifact.PinsPublished, 0)
	if strings.Contains(b.String(), "-runnable` pins") {
		t.Errorf("-runnable was suggested to a -runnable run:\n%s", b.String())
	}
}

func TestLockModeOfNamesTheTwoQuestions(t *testing.T) {
	if lockModeOf(true) != artifact.PinsPublished || lockModeOf(false) != artifact.PinsFromRecipes {
		t.Errorf("lockModeOf: %q / %q", lockModeOf(true), lockModeOf(false))
	}
}

// `-runnable` END TO END: the file it writes carries the PUBLISHED versions
// and says so, so that `bk lock --check` re-resolves by the same question.
func TestRunnableLockPinsWhatIsPublishedAndSaysSo(t *testing.T) {
	p, _ := lockbed(t, map[string]string{
		"app.org": "dependencies:\n  lib.org: '*'\n" + lockableRecipe,
		"lib.org": lockableRecipe,
	})
	// The recipes can build 1.2.4; the factory has only ever published 1.2.3.
	// That gap is the whole reason the mode exists.
	fakeConstrainedPick(t, func(string, []string) (string, error) { return "1.2.3", nil })

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-runnable", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, `pinned           = "published"`) {
		t.Errorf("the lock does not say how it was pinned:\n%s", got)
	}
	if !strings.Contains(got, `"app.org" = { version = "1.2.3"`) {
		t.Errorf("the lock did not pin the PUBLISHED version:\n%s", got)
	}
	// ⛔ AND THE DEFAULT STILL PINS THE RECIPE'S, which is what
	// `bk factory --lock` is about to build. A flag that changed both modes
	// would be a silent change of meaning for every existing lock.
	out.Reset()
	errb.Reset()
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), `"app.org" = { version = "1.2.4"`) {
		t.Errorf("the default mode no longer pins the recipe's version:\n%s", out.String())
	}
	if !strings.Contains(out.String(), `pinned           = "recipes"`) {
		t.Errorf("the default mode is not stated:\n%s", out.String())
	}
	// ⛔ AND THE VERDICT REACHES THE OPERATOR. The unit tests above call
	// reportUnpublished directly, so none of them could tell whether
	// runLock prints it at all — which is exactly the gap that let the
	// original silence through. Found by a mutation that deleted the call
	// and was not caught.
	if !strings.Contains(errb.String(), "2 of 2 pin(s) published for linux/x86-64") {
		t.Errorf("runLock does not report the publication verdict:\n%s", errb.String())
	}
}

// A PROJECT WITH NOTHING PUBLISHED IS A HOLE IN A RUNNABLE LOCK, not a line
// quietly left at the recipe's version: the mode's whole promise is that
// every line can be installed. A hole makes the command exit non-zero, as
// an unresolved project already did.
func TestRunnableLockRefusesAProjectWithNothingPublished(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	fakeConstrainedPick(t, func(string, []string) (string, error) { return "", errors.New("NAME_UNKNOWN") })

	var out, errb bytes.Buffer
	code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-runnable", "lib.org"}, &out, &errb)
	if code == 0 {
		t.Error("a runnable lock with an uninstallable line reported success")
	}
	if !strings.Contains(errb.String(), "nothing published for linux/x86-64") {
		t.Errorf("the hole is not explained:\n%s", errb.String())
	}
}

// ⛔ `--check` TAKES THE MODE FROM THE FILE, as it already takes the roots
// and the platform. Naming it again on the command line would let the two
// disagree, and the check would then be of a different question.
func TestCheckRefusesRunnableOnTheCommandLine(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--check", "some.lock.hcl", "-runnable"}, &out, &errb); code != 2 {
		t.Fatalf("code=%d, want 2; err=%q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "would ask a different question") {
		t.Errorf("the refusal does not say why:\n%s", errb.String())
	}
}

// ⛔⛔ A PER-PROJECT "NEWEST PUBLISHED" IS NOT A CLOSURE. The first version
// of -runnable asked for "*", reasoning that the newest runnable version
// beat none at all. Measured 2026-10-09 by running the lock it wrote in a
// FROM-scratch container:
//
//	lock: 5 of 5 pin(s) published for linux/aarch64 — `pkgx --lock` can run this file
//	pkgx: no version of openssl.org satisfies "=4.0.2" AND "^3";
//	      asked for by =4.0.2 (requested), ^3 (curl.se)
//
// curl.se 8.20 demands openssl ^3 and the newest published openssl is 4.0.2,
// so the lock pinned a set that cannot resolve — under a line claiming pkgx
// could run it. The reading of the code said it was fine; only running it
// said otherwise.
func TestRunnablePassesTheClosuresDemandsToTheResolver(t *testing.T) {
	p, _ := lockbed(t, map[string]string{
		"app.org": "dependencies:\n  lib.org: ^1\n" + lockableRecipe,
		"lib.org": lockableRecipe,
	})
	seen := fakeConstrainedPick(t, func(_ string, constraints []string) (string, error) {
		// THE FAKE HONOURS THEM, so a resolver that dropped them would
		// produce a different VERSION and not merely a different argument:
		// the test fails on the lock's contents, which is what a reader of
		// the lock would see.
		for _, c := range constraints {
			if c == "^1" {
				return "1.2.3", nil
			}
		}
		return "9.9.9", nil
	})

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-runnable", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if got := (*seen)["lib.org"]; len(got) != 1 || got[0] != "^1" {
		t.Errorf("lib.org's demands reached the resolver as %q, want [^1]", got)
	}
	if !strings.Contains(out.String(), `"lib.org" = { version = "1.2.3"`) {
		t.Errorf("the constrained version was not pinned:\n%s", out.String())
	}
	// The root has no demand on it, and that is not the same as a missing
	// entry: it must resolve, not be skipped.
	if !strings.Contains(out.String(), `"app.org" = { version = "9.9.9"`) {
		t.Errorf("a root with no demands did not resolve:\n%s", out.String())
	}
}

// ⛔ ZERO PINS IS NOT A CLEAN VERDICT. "0 of 0 published — pkgx can run this
// file" is a true sentence about an empty set that reads as an endorsement —
// the same shape as the silence this whole change replaces. Seen in a test's
// failure output while fixing something else.
func TestAnEmptyPinSetIsNotReportedAsRunnable(t *testing.T) {
	var b strings.Builder
	reportUnpublished(&b, nil, nil, nil, "linux/aarch64", artifact.PinsFromRecipes, 0)
	got := b.String()
	if strings.Contains(got, "can run this file") {
		t.Errorf("an empty lock was endorsed:\n%s", got)
	}
	if !strings.Contains(got, "nothing was pinned") {
		t.Errorf("an empty lock did not say so:\n%s", got)
	}
}

// ⛔ A COUNT CANNOT SEE WHAT IS MISSING. Measured 2026-10-09 on the real
// pantry: `bk lock -runnable curl.se` could not pin openssl.org at all —
// nothing published satisfies what the closure demands of it — so the file
// held FOUR pins, under the line
//
//	lock: 4 of 4 pin(s) published for linux/aarch64 — `pkgx --lock` can run this file
//
// Every pin present was installable and the sentence was true. The lock was
// still a closure with a hole in it, and the exit status (1) said so while
// the prose contradicted it.
func TestAVerdictSeesTheProjectsThatCouldNotBePinnedAtAll(t *testing.T) {
	pins := []lockedPin{{Project: "curl.se", Version: "8.20"}}
	var b strings.Builder
	reportUnpublished(&b, pins, nil, nil, "linux/aarch64", artifact.PinsPublished, 1)
	got := b.String()
	if strings.Contains(got, "can run this file") {
		t.Errorf("a lock with a hole was endorsed:\n%s", got)
	}
	if !strings.Contains(got, "NOT a closure") {
		t.Errorf("the hole is not named as such:\n%s", got)
	}
	// AND THE POSITIVE CONTROL: with no holes, the same pins ARE endorsed —
	// otherwise this would pass on a verdict that endorses nothing.
	b.Reset()
	reportUnpublished(&b, pins, nil, nil, "linux/aarch64", artifact.PinsPublished, 0)
	if !strings.Contains(b.String(), "can run this file") {
		t.Errorf("a complete lock was not endorsed:\n%s", b.String())
	}
}

// ⛔ A ROOT'S CONSTRAINT REACHES THE PUBLISHED RESOLVER TOO.
//
// `-runnable` resolves through publishedVersionFor(project, demands[project]),
// and `demands` is built from DEPENDENTS — a root has none, so without the
// root's own constraint being appended it arrived empty and the newest
// published version won whatever was asked.
//
// This seam exists because dropping constraints was the original defect; it
// records what the resolver was handed, which is the only way to tell "asked
// for 1.2.3 and got it" from "asked for nothing and happened to get 1.2.3".
func TestRunnableLockHandsTheRootsConstraintToThePublishedResolver(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"app.org": lockableRecipe})
	seen := fakeConstrainedPick(t, func(_ string, _ []string) (string, error) { return "1.2.3", nil })

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-runnable", "app.org@1.2.3"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	got := (*seen)["app.org"]
	if len(got) != 1 || got[0] != "1.2.3" {
		t.Errorf("the published resolver was handed %v, want [1.2.3]", got)
	}
}

// The control: no constraint on the root, nothing handed over. Without it,
// "always append something" would satisfy the test above.
func TestRunnableLockHandsNothingWhenTheRootIsUnconstrained(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"app.org": lockableRecipe})
	seen := fakeConstrainedPick(t, func(_ string, _ []string) (string, error) { return "1.2.4", nil })

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-runnable", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if got := (*seen)["app.org"]; len(got) != 0 {
		t.Errorf("an unconstrained root was given %v", got)
	}
}

// ⛔ AND --check HANDS IT OVER TOO, for a runnable lock.
//
// Checking re-resolves by the question the file answers; for a published lock
// that is publishedVersionFor, so the root's constraint has to reach it there
// as well. Without this, `--check` on a correctly pinned runnable lock would
// re-resolve to the newest published version and report drift that is not
// there — and a drift report nobody can reproduce is worse than none.
func TestLockCheckHandsTheRootsConstraintToThePublishedResolver(t *testing.T) {
	p, files := lockbed(t, map[string]string{"app.org": lockableRecipe})
	lockPath := filepath.Join(t.TempDir(), "runnable.hcl")
	fakeConstrainedPick(t, func(_ string, _ []string) (string, error) { return "1.2.3", nil })

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-runnable", "-o", lockPath, "app.org@1.2.3"}, &out, &errb); code != 0 {
		t.Fatalf("writing: code=%d err=%q", code, errb.String())
	}
	if err := os.WriteFile(lockPath, (*files)[lockPath], 0o644); err != nil {
		t.Fatal(err)
	}

	// A FRESH recorder for the check, so what it sees cannot be the write's.
	seen := fakeConstrainedPick(t, func(_ string, _ []string) (string, error) { return "1.2.3", nil })
	out.Reset()
	errb.Reset()
	if code := runLock([]string{"--pantry", p, "--check", lockPath}, &out, &errb); code != 0 {
		t.Fatalf("check: code=%d\n%s%s", code, out.String(), errb.String())
	}
	got := (*seen)["app.org"]
	if len(got) != 1 || got[0] != "1.2.3" {
		t.Errorf("--check handed the published resolver %v, want [1.2.3]", got)
	}
}
