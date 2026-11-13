package main

import "testing"

// ⛔⛔ EVERY BOTTLE ALREADY PUBLISHED RECORDS `pkg:pkgx/`, AND THIS COMMAND'S
// JOB IS TO ANSWER ABOUT BOTTLES THAT EXIST.
//
// `zbk buildenv` reads a published bottle's provenance to say what it was
// built against. If the read path followed the mint path to `pkg:generic/`,
// the answer for the whole existing registry would become "the provenance
// records no build environment" — a sentence that is indistinguishable from a
// bottle published before provenance existed at all, which is the one
// distinction envAttestedBy was written to preserve.
func TestABottleSignedWithTheRetiredPurlIsStillUnderstood(t *testing.T) {
	for _, tc := range []struct{ uri, project, version string }{
		{"pkg:pkgx/go.dev@1.27.1", "go.dev", "1.27.1"},
		{"pkg:generic/go.dev@1.27.1", "go.dev", "1.27.1"},
		// A project name is a PATH, and the version is what follows the LAST
		// "@" — cutting at the first would shorten the project silently.
		{"pkg:pkgx/gnu.org/glibc@2.44.0", "gnu.org/glibc", "2.44.0"},
		{"pkg:generic/gnu.org/glibc@2.44.0", "gnu.org/glibc", "2.44.0"},
		{"pkg:generic/weird@name@1.2.3", "weird@name", "1.2.3"},
	} {
		project, version, ok := cutPurl(tc.uri)
		if !ok {
			t.Errorf("%q was not understood at all", tc.uri)
			continue
		}
		if project != tc.project || version != tc.version {
			t.Errorf("%q → %q @ %q, want %q @ %q", tc.uri, project, version, tc.project, tc.version)
		}
	}
}

// What is not a purl of ours is not read as one, and a malformed one is
// skipped rather than guessed at.
func TestWhatIsNotOursIsNotRead(t *testing.T) {
	for _, uri := range []string{
		"pkg:npm/left-pad@1.3.0",         // somebody else's ecosystem
		"pkg:genericx/go.dev@1.0",        // a longer type that merely starts the same
		"https://example.org/go.dev@1.0", // not a purl
		"pkg:generic/go.dev",             // no version
		"pkg:generic/@1.0",               // no project
		"pkg:generic/go.dev@",            // empty version
		"pkg:pkgx/go.dev",                // the retired spelling, still malformed
	} {
		if _, _, ok := cutPurl(uri); ok {
			t.Errorf("%q was read as a purl of ours", uri)
		}
	}
}

// ⛔ THE MINT PATH HAS ONE SPELLING. Two current spellings would mean the
// change never finishes: a later reader could not tell which bottles were
// built after it.
func TestOnlyOneSpellingIsMinted(t *testing.T) {
	got := purlFor("gnu.org/bash", "5.2.37")
	if want := "pkg:generic/gnu.org/bash@5.2.37"; got != want {
		t.Errorf("purlFor = %q, want %q", got, want)
	}
	if purlPrefix == legacyPurlPrefix {
		t.Fatal("the minted prefix and the retired one are the same string")
	}
	// And what it mints is what it reads back, which is the property that
	// stops the two halves drifting apart.
	project, version, ok := cutPurl(got)
	if !ok || project != "gnu.org/bash" || version != "5.2.37" {
		t.Errorf("cutPurl(purlFor(...)) = %q @ %q, ok=%v", project, version, ok)
	}
}
