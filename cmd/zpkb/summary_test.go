package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/pantry"
)

// A catalogue is a ~50 KB artefact every reader downloads, and some
// descriptions are paragraphs. Carrying them whole would multiply its size
// for text nothing displays.
func TestSummaryOf(t *testing.T) {
	long := strings.Repeat("word ", 80) // 400 characters, no sentence end
	for name, tc := range map[string]struct {
		in   pantry.Recipe
		want func(string) bool
	}{
		"summary wins over description": {
			pantry.Recipe{Summary: "a JSON processor", Description: "something much longer"},
			func(s string) bool { return s == "a JSON processor" },
		},
		"description is the fallback": {
			pantry.Recipe{Description: "  a   JSON   processor  "},
			func(s string) bool { return s == "a JSON processor" }, // and whitespace collapsed
		},
		"cut at the first sentence": {
			pantry.Recipe{Description: "Short one. Then a great deal more that nobody needs."},
			func(s string) bool { return s == "Short one" },
		},
		"a long one is cut at a word": {
			pantry.Recipe{Description: long},
			func(s string) bool {
				return len(s) <= summaryMax+len("…") && strings.HasSuffix(s, "…") &&
					!strings.HasSuffix(s, "wor…")
			},
		},
		"nothing at all": {
			pantry.Recipe{},
			func(s string) bool { return s == "" },
		},
	} {
		r := tc.in
		if got := summaryOf(&r); !tc.want(got) {
			t.Errorf("%s: summaryOf = %q", name, got)
		}
	}
}

// A sentence end BEYOND the cut must not win: "…. " at character 900 is not
// a short summary, and taking it would carry the paragraph this bound
// exists to drop.
func TestSummaryIgnoresALateSentenceEnd(t *testing.T) {
	r := pantry.Recipe{Description: strings.Repeat("x", 400) + ". and more"}
	got := summaryOf(&r)
	if len(got) > summaryMax+len("…") {
		t.Errorf("a late sentence end carried %d characters", len(got))
	}
}

// And the counts the command prints, which are what tell whoever publishes
// it whether a search over this catalogue is worth anything.
func TestCatalogSaysHowMuchItKnows(t *testing.T) {
	const described = "versions:\n  - 1.0.0\nbuild: make\n" +
		"summary: a JSON processor\nprovides:\n  - bin/jq\n  - lib/libjq.so\n"
	p, _, _ := catbed(t, map[string]string{
		"a.org": described, "b.org": catRecipe, "c.org": catRecipe,
	}, nil)
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "1 of 3 project(s) name their commands, 1 describe themselves") {
		t.Errorf("the counts are wrong or missing: %q", errb.String())
	}
	cat, err := bottle.UnmarshalCatalog(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := cat.Lookup("a.org")
	if strings.Join(a.Provides, " ") != "jq" {
		t.Errorf("provides = %v, want just the command (no lib/, no bin/ prefix)", a.Provides)
	}
	if a.Summary != "a JSON processor" {
		t.Errorf("summary = %q", a.Summary)
	}
	// And a search over the catalogue that was just built finds it by the
	// command, which is the whole point of carrying the field.
	hits := cat.Search("jq")
	if len(hits) == 0 || hits[0].Project != "a.org" || hits[0].Why != "command" {
		t.Errorf("search over the built catalogue = %+v", hits)
	}
}
