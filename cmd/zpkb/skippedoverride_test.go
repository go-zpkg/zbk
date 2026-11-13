package main

import (
	"bytes"
	"strings"
	"testing"
)

// A project whose override did not apply is not built. The recipe on disk is
// the UNPATCHED one, so a build of it either fails for the reason the patch
// removes — which is what happened to mozilla.org/nss twice on 2026-09-24 —
// or succeeds and publishes a bottle missing a correction somebody made on
// purpose. The second is worse, and only this refusal catches it.
func TestBuildOneRefusesAProjectWithASkippedOverride(t *testing.T) {
	var out bytes.Buffer
	f := &factory{
		stdout:           &out,
		platform:         "darwin/aarch64",
		skippedOverrides: map[string][]string{"mozilla.org/nss": {"mozilla.org-nss-darwin-werror.patch"}},
	}
	f.buildOne(nil, "mozilla.org/nss", "3.119")

	if f.failed != 1 {
		t.Fatalf("failed = %d, want 1", f.failed)
	}
	if got := f.failures.String(); got != "mozilla.org/nss 3.119 override\n" {
		t.Errorf("failures.txt line = %q", got)
	}
	// The patch is NAMED: an operator has to re-cut that file, and a message
	// that only said "an override did not apply" would send them looking.
	if d := f.failuresDetail.String(); !strings.Contains(d, "mozilla.org-nss-darwin-werror.patch") {
		t.Errorf("the detail does not name the patch: %q", d)
	}
	if !strings.Contains(out.String(), "OVERRIDE FAIL") {
		t.Errorf("stdout did not announce it: %q", out.String())
	}
}
