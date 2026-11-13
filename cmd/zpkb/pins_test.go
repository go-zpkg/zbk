package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

// The pin a project needs is the INTERSECTION of what its dependents ask, which
// is often narrower than any one of them: cmake.org is asked for `^3.20` and
// `>=3<3.29`, neither admits the other, and [3.20, 3.29) satisfies both.
func TestIntersectConstraints(t *testing.T) {
	for name, c := range map[string]struct {
		in   []string
		want string
	}{
		// ONE constraint is not an intersection: the author's words go
		// through untouched, whatever their shape.
		"one constraint":            {[]string{"~3.11"}, "~3.11"},
		"a bare version is a caret": {[]string{"2", "^2"}, ">=2<3"},
		"three that agree":          {[]string{">=3<3.12", "~3.11", ">=3<3.15"}, ">=3.11<3.12"},
		"neither admits the other":  {[]string{"^3.20", ">=3<3.29"}, ">=3.20<3.29"},
		"an exact pin":              {[]string{"=8.6.16"}, "=8.6.16"},
		// An exact pin BESIDE another: python.org asks tcl-lang.org for
		// =8.6.16 while the line it sits on is ^8, and the intersection is
		// the one version.
		"an exact pin beside a line": {[]string{"=8.6.16", "^8"}, ">=8.6.16<8.6.17"},
		"a caret and its major":      {[]string{"1", "^1"}, ">=1<2"},
		// No ceiling stays no ceiling. The sentinel standing in for one printed
		// itself once — `kernel.org/linux-headers@>=5.6<1073741824` — which is a
		// constraint a registry answers nothing for.
		"no upper bound":        {[]string{">=5.6"}, ">=5.6"},
		"two lower bounds":      {[]string{">=3", ">=4.2"}, ">=4.2"},
		"a ceiling and a floor": {[]string{">=3", "<19"}, ">=3<19"},
		"disjoint":              {[]string{"~5.42", "~5.44"}, ""},
		"three disjoint majors": {[]string{"20", "21", "<19"}, ""},
		// Unreadable ALONE is fine: nothing to combine it with, and pkgx
		// parses what the recipe said. It is only a problem beside another.
		"unreadable alone":      {[]string{"latest"}, "latest"},
		"one unreadable of two": {[]string{"^3", "whatever"}, ""},
		"nothing at all":        {nil, ""},
		// A version is not always digits and dots. The pantry carries `0.94n`,
		// and sourceforge advertises a `9.1.0rc0` for tcl where no 9.1.0 was
		// ever released. A component is read up to its first non-digit rather
		// than making the whole constraint unreadable.
		"a non-numeric suffix": {[]string{"~0.94n"}, "~0.94n"},
		// The suffix arithmetic still has to be right where there IS
		// something to combine.
		"a suffix beside another": {[]string{"~0.94n", ">=0.9"}, ">=0.94<0.95"},
		"a release candidate":     {[]string{"=9.1.0rc0"}, "=9.1.0rc0"},
	} {
		if got := intersectConstraints(c.in); got != c.want {
			t.Errorf("%s: intersectConstraints(%v) = %q, want %q", name, c.in, got, c.want)
		}
	}
}

// pins walks the graph's own demands, so what it emits is what the factory
// would resolve — and a disagreement is REPORTED, because the answer there is
// two builds rather than a choice.
func TestClosureGraphPins(t *testing.T) {
	g := newClosureGraph(nil, "", target.Target{Platform: "linux", Arch: "x86-64"}, true, nil)
	g.order = []string{"dep.org", "split.org", "free.org", "app.org"}
	g.demands = map[string]map[string][]string{
		"dep.org":   {"~3.11": {"app.org"}, ">=3<3.15": {"other.org"}},
		"split.org": {"~5.42": {"a.org"}, "~5.44": {"b.org"}},
	}
	pins, conflicts := g.pins()
	if len(pins) != 1 || pins[0] != "dep.org@>=3.11<3.12" {
		t.Errorf("pins = %v", pins)
	}
	if len(conflicts) != 1 || !strings.Contains(conflicts[0], "split.org") ||
		!strings.Contains(conflicts[0], "~5.42") || !strings.Contains(conflicts[0], "a.org") {
		t.Errorf("conflicts = %v — must name the project, the lines and who asks", conflicts)
	}
	// A project nothing constrains yields no pin: dispatching `free.org@` would
	// be a constraint nothing satisfies.
	for _, p := range pins {
		if strings.HasPrefix(p, "free.org") || strings.HasPrefix(p, "app.org") {
			t.Errorf("an unconstrained project must not be pinned: %v", pins)
		}
	}

	// Through the printer, which is what a dispatch reads.
	var out bytes.Buffer
	printGraph(g, false, true, false, &out)
	s := out.String()
	if !strings.Contains(s, "dep.org@>=3.11<3.12") {
		t.Errorf("the pin is not printed:\n%s", s)
	}
	if !strings.Contains(s, "# NO single version") || !strings.Contains(s, "split.org") {
		t.Errorf("a disagreement must be printed, not dropped:\n%s", s)
	}
	// --pins prints pins, not the order: a dispatch pasting both would ask for
	// every project twice, once unpinned.
	if strings.Contains(s, "\napp.org\n") {
		t.Errorf("--pins must not also print the order:\n%s", s)
	}
}
