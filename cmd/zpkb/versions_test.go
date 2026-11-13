package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A list-form `versions:` spec makes the candidates hardcoded in the recipe, so
// `bk versions` needs no network (no git ls-remote / HTTP) to be exercised.
const listRecipe = "versions:\n  - \"1.2.0\"\n  - \"1.10.0\"\n  - \"1.3.0\"\ndistributable: https://x/v{{version.raw}}.tgz\nbuild: \"true\"\ntest: \"true\"\n"

func writeVersionsRecipe(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "package.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersionsCommand(t *testing.T) {
	rec := writeVersionsRecipe(t, listRecipe)
	code, out, errs := run2(t, "versions", "--recipe", rec)
	if code != 0 {
		t.Fatalf("versions: code=%d err=%q", code, errs)
	}
	// newest first, one "version<TAB>tag" line each (list-form tag == version).
	want := "1.10.0\t1.10.0\n1.3.0\t1.3.0\n1.2.0\t1.2.0\n"
	if out != want {
		t.Errorf("versions output = %q; want %q", out, want)
	}
}

func TestVersionsCommandErrors(t *testing.T) {
	// missing --recipe
	if c, _, _ := run2(t, "versions"); c != 2 {
		t.Errorf("no-recipe code=%d", c)
	}
	// bad flag
	if c, _, _ := run2(t, "versions", "-nope"); c != 2 {
		t.Errorf("bad-flag code=%d", c)
	}
	// unreadable recipe
	if c, _, _ := run2(t, "versions", "--recipe", filepath.Join(t.TempDir(), "nope.yml")); c != 1 {
		t.Errorf("missing-recipe code=%d", c)
	}
	// invalid recipe content
	bad := filepath.Join(t.TempDir(), "bad.yml")
	os.WriteFile(bad, []byte("build: [oops\n"), 0o644)
	if c, _, _ := run2(t, "versions", "--recipe", bad); c != 1 {
		t.Errorf("bad-recipe code=%d", c)
	}
	// versions.List error: a list-form spec whose candidates are all unparseable.
	noneParse := writeVersionsRecipe(t, "versions:\n  - nightly\n  - edge\nbuild: \"true\"\ntest: \"true\"\n")
	if c, _, e := run2(t, "versions", "--recipe", noneParse); c != 1 {
		t.Errorf("list-error code=%d err=%q", c, e)
	}
}
