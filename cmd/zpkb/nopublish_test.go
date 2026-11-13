package main

import (
	"strings"
	"testing"
)

// ⛔⛔ THE ONE IRREVERSIBLE STEP, AND ONLY THAT ONE. `--no-publish` exists so
// a recipe can be built TWICE and the two artifacts compared (`zpkb reproduce`)
// without pushing a second copy of something already published. If it skipped
// the build it would be useless for the question it exists for; if it pushed
// anyway it would be a lie.
func TestNoPublishBuildsAndPushesNothing(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	// A control first: without the flag, this recipe IS built and IS
	// published. Otherwise "nothing was published" below could mean the run
	// did nothing at all, which is the way this test could pass while
	// proving nothing. It caught the first version of this test, which drove
	// an empty pantry and built zero recipes.
	if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
		t.Fatalf("control run: code=%d\n%s\n%s", code, h.out.String(), h.errb.String())
	}
	if len(h.built) == 0 {
		t.Fatal("the control built nothing — the harness is not driving a build")
	}
	if len(h.published) == 0 {
		t.Fatal("the control published nothing — there is no publish to suppress")
	}

	h2 := newFactoryHarness(t)
	writeClosureRecipe(t, h2.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	code := h2.run(t, "--no-publish", "--recipes", "lib.org", "--max-versions", "1")
	if code != 0 {
		t.Fatalf("--no-publish run: code=%d\n%s\n%s", code, h2.out.String(), h2.errb.String())
	}
	// ⛔ BUILT, AND NOT PUSHED. A flag that skipped the build would be useless
	// for the question it exists for — two builds compared — and one that
	// pushed anyway would be a lie. Both halves asserted.
	if len(h2.built) == 0 {
		t.Error("--no-publish built nothing; it suppresses the PUSH, not the build")
	}
	if len(h2.published) != 0 {
		t.Errorf("--no-publish published %d artifact(s): %v", len(h2.published), h2.published)
	}
	out := h2.out.String()
	if !strings.Contains(out, "BUILT") || !strings.Contains(out, "not published") {
		t.Errorf("the run does not say the artifact was built and not published:\n%s", out)
	}
	// And it must name where the artifact actually is, since that is the whole
	// point: something has to be left to compare.
	if !strings.Contains(out, h2.artifacts) {
		t.Errorf("the run does not say where the artifact was staged:\n%s", out)
	}
}

// ⛔ REFUSED, NOT IGNORED. Both of these would do something other than what
// was asked and still look like they worked.
func TestNoPublishRefusesTheCombinationsThatMakeNoSense(t *testing.T) {
	for _, c := range []struct {
		name  string
		args  []string
		wants []string
	}{
		{
			// Mirroring IS publishing: a mirror that publishes nothing
			// downloads each artifact and discards it.
			name:  "with --mirror-from",
			args:  []string{"factory", "--no-publish", "--mirror-from", "https://dist.pkgx.dev", "--platform", "linux/x86-64"},
			wants: []string{"Mirroring IS publishing", "discard"},
		},
		{
			// --rebuild mints the next free `_N` against the registry so a
			// NEW tag can be pushed beside the published one. With nothing
			// pushed the counter is minted against a registry that never sees
			// the result.
			name:  "with --rebuild",
			args:  []string{"factory", "--no-publish", "--rebuild", "--platform", "linux/x86-64"},
			wants: []string{"nothing is pushed", "never sees the result"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, _, errb := run2(t, c.args...)
			if code != 2 {
				t.Errorf("code=%d, want 2 (a usage refusal)", code)
			}
			for _, w := range c.wants {
				if !strings.Contains(errb, w) {
					t.Errorf("the refusal does not say %q:\n%s", w, errb)
				}
			}
		})
	}
}

// The flag is reachable from the environment as well as the command line,
// the way every other factory switch is — the sovereign build script passes
// its settings through `sudo --preserve-env`, not as arguments.
func TestNoPublishIsReadableFromTheEnvironment(t *testing.T) {
	t.Setenv("NO_PUBLISH", "1")
	// Paired with --mirror-from so the refusal above proves the flag was
	// seen: a run that ignored NO_PUBLISH would get past this guard.
	code, _, errb := run2(t, "factory", "--mirror-from", "https://dist.pkgx.dev", "--platform", "linux/x86-64")
	if code != 2 || !strings.Contains(errb, "Mirroring IS publishing") {
		t.Errorf("NO_PUBLISH=1 was not read from the environment: code=%d\n%s", code, errb)
	}
}
