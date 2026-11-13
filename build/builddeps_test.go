package build

import (
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
)

// TestBuildDeps: build-time dependencies live under the free-form `build:`
// node, not in a typed field, and they can name an unpublishable version just
// as runtime ones can — `bk depgaps` counts both, so it needs them exported.
func TestBuildDeps(t *testing.T) {
	rec := &pantry.Recipe{Build: map[string]any{
		"dependencies": map[string]any{"openssl.org": "^1.1"},
		"script":       "make",
	}}
	if got := BuildDeps(rec); len(got) != 1 || got["openssl.org"] != "^1.1" {
		t.Fatalf("got %v", got)
	}
	// A recipe whose build is a bare script string has none, and must not panic.
	if got := BuildDeps(&pantry.Recipe{Build: "make"}); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
	// Nor one whose build carries no dependencies key.
	if got := BuildDeps(&pantry.Recipe{Build: map[string]any{"script": "make"}}); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}
