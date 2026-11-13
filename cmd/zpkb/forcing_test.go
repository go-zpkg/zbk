package main

import (
	"strings"
	"testing"
)

// TestForceDoesNotRebuildTheClosure is the cost this fixes: a manual dispatch
// sets --force to refresh the bottles it NAMED, and that used to force every
// dependency the closure walk added as well.
func TestForceDoesNotRebuildTheClosure(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "dep.org", "versions:\n  github: a/dep/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "app.org",
		"versions:\n  github: a/app/tags\ndependencies:\n  dep.org: '*'\nbuild: make\n")
	// Everything is already published, which is the situation a repair run is
	// in: only --force decides whether anything gets rebuilt.
	factoryHasPlatform = func(_, project, tag, _, _ string) (bool, error) {
		h.checked = append(h.checked, project+"@"+tag)
		return true, nil
	}

	if code := h.run(t, "--recipes", "app.org", "--max-versions", "1", "--force"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	built := strings.Join(h.built, " ")
	if !strings.Contains(built, "app.org") {
		t.Errorf("--force must still rebuild what was asked for: %q", built)
	}
	if strings.Contains(built, "dep.org") {
		t.Errorf("--force rebuilt a published dependency nobody asked for: %q", built)
	}
	if !strings.Contains(h.out.String(), "SKIP dep.org") {
		t.Errorf("the dependency should have been skipped as published:\n%s", h.out.String())
	}
}

func TestForcing(t *testing.T) {
	f := &factory{force: true, requested: map[string]bool{"a.org": true}}
	if !f.forcing("a.org") {
		t.Error("a requested project must be forced")
	}
	if f.forcing("dep.org") {
		t.Error("a closure dependency must not be")
	}
	if (&factory{requested: map[string]bool{"a.org": true}}).forcing("a.org") {
		t.Error("without --force nothing is forced")
	}
}
