package main

import (
	"strings"
	"testing"
)

// TestRunFactoryNoClosureBuildsOnlyWhatWasAsked is the repair-run shape: the
// dependency is already published, and expanding to it costs a rebuild at
// whatever upstream released this week while the target waits behind it.
func TestRunFactoryNoClosureBuildsOnlyWhatWasAsked(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "dep.org", "versions:\n  github: a/dep/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "app.org",
		"versions:\n  github: a/app/tags\ndependencies:\n  dep.org: '*'\nbuild: make\n")

	// Without the flag the dependency is built first — that is what makes a
	// first fill work, and the control that proves the flag does something.
	if code := h.run(t, "--recipes", "app.org", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	full := strings.Join(h.built, " ")
	if !strings.Contains(full, "dep.org") || !strings.Contains(full, "app.org") {
		t.Fatalf("built = %q, want the dependency and the app", full)
	}

	h2 := newFactoryHarness(t)
	writeClosureRecipe(t, h2.pantry, "dep.org", "versions:\n  github: a/dep/tags\nbuild: make\n")
	writeClosureRecipe(t, h2.pantry, "app.org",
		"versions:\n  github: a/app/tags\ndependencies:\n  dep.org: '*'\nbuild: make\n")
	if code := h2.run(t, "--recipes", "app.org", "--max-versions", "1", "--no-closure"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h2.errb.String())
	}
	only := strings.Join(h2.built, " ")
	if strings.Contains(only, "dep.org") {
		t.Errorf("--no-closure still built the dependency: %q", only)
	}
	if !strings.Contains(only, "app.org") {
		t.Errorf("--no-closure did not build the target: %q", only)
	}
	if !strings.Contains(h2.out.String(), "closure: 1 project(s)") {
		t.Errorf("the project count must reflect what will actually be built:\n%s", h2.out.String())
	}
}
