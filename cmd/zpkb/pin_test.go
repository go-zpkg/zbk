package main

import (
	"strings"
	"testing"
)

func TestSplitPin(t *testing.T) {
	for _, tc := range []struct{ in, proj, want string }{
		{"cmake.org", "cmake.org", ""},
		{"cmake.org@=4.4.2", "cmake.org", "=4.4.2"},
		{"gnu.org/glibc@^2", "gnu.org/glibc", "^2"},
		// A project name cannot contain '@', so the first one is always the cut.
		{"crates.io/pqrs@>=0.3", "crates.io/pqrs", ">=0.3"},
		// A trailing '@' with nothing after it pins nothing.
		{"foo@", "foo", ""},
	} {
		proj, want := splitPin(tc.in)
		if proj != tc.proj || want != tc.want {
			t.Errorf("splitPin(%q) = %q,%q — want %q,%q", tc.in, proj, want, tc.proj, tc.want)
		}
	}
}

// TestMatchingPrefersThePerProjectPin: the whole point — one dispatch, each
// project at the version its own gap names, while --versions still governs the
// projects that carried no pin.
func TestMatchingPrefersThePerProjectPin(t *testing.T) {
	var out, errb strings.Builder
	f := &factory{
		want:    "^3",
		wantPer: map[string]string{"cmake.org": "=4.4.2"},
		stdout:  &out, stderr: &errb,
	}

	got := f.matching("cmake.org", []string{"4.4.2", "4.4.1", "3.31.12"})
	if len(got) != 1 || got[0] != "4.4.2" {
		t.Fatalf("cmake.org matched %v, want just 4.4.2", got)
	}
	// The unpinned project still obeys --versions.
	if got := f.matching("groonga.org", []string{"3.9.0", "4.0.0"}); len(got) != 1 || got[0] != "3.9.0" {
		t.Fatalf("groonga.org matched %v, want just 3.9.0", got)
	}
}

// TestMatchingRangeWarningNamesThePin: the "that is a RANGE" warning has to
// quote the constraint actually in force, or it points at the wrong flag.
func TestMatchingRangeWarningNamesThePin(t *testing.T) {
	var out, errb strings.Builder
	f := &factory{wantPer: map[string]string{"gnu.org/glibc": "2.28.0"}, stdout: &out, stderr: &errb}

	f.matching("gnu.org/glibc", []string{"2.28.0", "2.29.0", "2.33.0"})

	if !strings.Contains(errb.String(), "is a RANGE") || !strings.Contains(errb.String(), `"=2.28.0"`) {
		t.Errorf("the warning does not name the fix: %q", errb.String())
	}
	// It must point at the pin, not at --versions, or it sends the operator to
	// the wrong knob.
	if !strings.Contains(errb.String(), `the pin "gnu.org/glibc@2.28.0"`) {
		t.Errorf("the warning does not name where the constraint came from: %q", errb.String())
	}
}

// TestConstraintFor: the empty pin map falls through to --versions, and a
// project with no pin does too.
func TestConstraintFor(t *testing.T) {
	f := &factory{want: "^3", wantPer: map[string]string{"a.org": "=1.0"}}
	if got := f.constraintFor("a.org"); got != "=1.0" {
		t.Errorf("pinned project: %q", got)
	}
	if got := f.constraintFor("b.org"); got != "^3" {
		t.Errorf("unpinned project: %q", got)
	}
	if got := (&factory{}).constraintFor("c.org"); got != "" {
		t.Errorf("no constraint at all: %q", got)
	}
}

// TestMatchingNoMatchNamesTheConstraintInForce: the failure an operator reads
// when the pinned version does not exist has to quote the pin, not --versions.
func TestMatchingNoMatchNamesTheConstraintInForce(t *testing.T) {
	var out, errb strings.Builder
	f := &factory{want: "^3", wantPer: map[string]string{"a.org": "=9.9.9"}, stdout: &out, stderr: &errb}
	if got := f.matching("a.org", []string{"1.0.0"}); len(got) != 0 {
		t.Fatalf("matched %v, want none", got)
	}
	if got := f.constraintFor("a.org"); got != "=9.9.9" {
		t.Fatalf("constraintFor = %q", got)
	}
}

// TestRunFactoryPinnedRecipeWord is the feature end to end: one dispatch, the
// project pinned in the recipes list itself.
func TestRunFactoryPinnedRecipeWord(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	if code := h.run(t, "--recipes", "lib.org@^1"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if got := strings.Join(h.built, " "); got != "lib.org@=1.0" {
		t.Fatalf("built = %q, want only the 1.x line", got)
	}
	if !strings.Contains(h.out.String(), `dropped by the pin "lib.org@^1"`) {
		t.Fatalf("the pin is not named in the drop:\n%s", h.out.String())
	}
}
