package main

import (
	"fmt"
	"sort"
	"strings"
)

// unbounded stands in for "no upper bound" inside the interval arithmetic. It
// is a version number no project will reach, and it must never reach the
// OUTPUT: see intersectConstraints.
const unbounded = 1 << 30

// pins turns the demands a closure records into the `project@constraint` words
// a `bk factory --recipes` dispatch takes.
//
// It exists because a REQUESTED project is not covered by the constraint
// resolution the factory does for a closure-only dependency: the operator named
// it, so the operator's --versions decides. On the s390x seed that meant
// dispatching gnu.org/gcc and getting 16.2.0 after twenty-five minutes of
// compiling, while gnu.org/glibc asks for 14.
//
// Typing the pins by hand is what this replaces, and by hand is how it went
// wrong: a batch listed in an order the topological file did not have, and a
// constraint report read through a filter that hid 39 of its 49 rows.
//
// Where a project's dependents cannot agree, it is REPORTED rather than
// decided. perl.org is asked for ~5.42 and ~5.44 and llvm.org for 20, 21 and
// <19; those are separate builds, and a tool that picked one would quietly
// starve the other's dependents.
func (g *closureGraph) pins() (pins, conflicts []string) {
	for _, proj := range g.order {
		d := g.demands[proj]
		if len(d) == 0 {
			continue
		}
		cs := make([]string, 0, len(d))
		for c := range d {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		if c := intersectConstraints(cs); c != "" {
			pins = append(pins, proj+"@"+c)
			continue
		}
		parts := make([]string, 0, len(cs))
		for _, c := range cs {
			by := append([]string(nil), d[c]...)
			sort.Strings(by)
			parts = append(parts, fmt.Sprintf("%s (%s)", c, strings.Join(by, ", ")))
		}
		conflicts = append(conflicts, fmt.Sprintf("%-28s %s", proj, strings.Join(parts, "  vs  ")))
	}
	return pins, conflicts
}

// intersectConstraints returns a constraint matching exactly the versions every
// member of cs matches, or "" when nothing can.
//
// Written as `>=lo<hi`, which is pkgx's own grammar and appears in the pantry
// already (`curl.se: >=5<8.13`). Narrowing to an interval rather than picking
// one of the inputs is what makes cmake.org answerable: it is asked for `^3.20`
// and `>=3<3.29`, neither admits the other, and [3.20, 3.29) satisfies both. A
// first version looked for a surviving constraint instead and called that a
// conflict.
//
// A shape constraintRange does not understand yields "" — an unhandled
// constraint becomes a reported disagreement, never a wrong pin.
func intersectConstraints(cs []string) string {
	// One constraint is not an intersection. Pass the AUTHOR'S words through:
	// pkgx parses them by construction — they came out of a recipe it already
	// reads — while `>=2<3` is my arithmetic's rendering of `2` and only as
	// right as constraintRange is.
	//
	// 32 of the 49 constrained projects in the s390x seed closure have exactly
	// one, so this is most of them, and for those the pin is now the recipe's
	// own text.
	if len(cs) == 1 {
		return cs[0]
	}
	var lo, hi []int
	for i, c := range cs {
		l, h, ok := constraintRange(c)
		if !ok {
			return ""
		}
		if i == 0 || cmpParts(l, lo) > 0 {
			lo = l
		}
		if i == 0 || cmpParts(h, hi) < 0 {
			hi = h
		}
	}
	if len(lo) == 0 || cmpParts(lo, hi) >= 0 {
		return "" // empty: ~5.42 and ~5.44 have nothing in common
	}
	// An upper bound nobody set stays unset. The sentinel that stands in for
	// "no ceiling" inside the arithmetic printed itself once —
	// `kernel.org/linux-headers@>=5.6<1073741824` — which is a constraint a
	// registry would answer nothing for.
	if cmpParts(hi, []int{unbounded}) >= 0 {
		return ">=" + joinParts(lo)
	}
	return ">=" + joinParts(lo) + "<" + joinParts(hi)
}

// constraintRange reads a pkgx constraint as the half-open interval [lo, hi).
func constraintRange(c string) (lo, hi []int, ok bool) {
	switch {
	case strings.HasPrefix(c, ">=") && strings.Contains(c, "<"):
		l, h, _ := strings.Cut(strings.TrimPrefix(c, ">="), "<")
		return verParts(l), verParts(h), true
	case strings.HasPrefix(c, ">="):
		return verParts(strings.TrimPrefix(c, ">=")), []int{unbounded}, true
	case strings.HasPrefix(c, "<"):
		return []int{0}, verParts(strings.TrimPrefix(c, "<")), true
	case strings.HasPrefix(c, "="):
		v := verParts(strings.TrimPrefix(c, "="))
		return v, bumpAt(v, len(v)-1), true
	case strings.HasPrefix(c, "~"):
		// `~3.11` is 3.11.x: the LAST named component may grow.
		v := verParts(strings.TrimPrefix(c, "~"))
		return v, bumpAt(v, len(v)-1), true
	case strings.HasPrefix(c, "^"):
		v := verParts(strings.TrimPrefix(c, "^"))
		return v, bumpAt(v, 0), true
	case c != "" && c[0] >= '0' && c[0] <= '9':
		// A BARE version is a caret range: `2` is 2.x, `3.20` is 3.20 upward
		// within major 3 — the same reading --versions documents. Treating it
		// as an exact match is how mpdecimal's `2` was read as "anything" and
		// 4.0.1 got built.
		v := verParts(c)
		return v, bumpAt(v, 0), true
	}
	return nil, nil, false
}

func verParts(s string) []int {
	var out []int
	for _, f := range strings.Split(s, ".") {
		n := 0
		for _, r := range f {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

// bumpAt is v with component i incremented and everything after it dropped —
// the exclusive upper bound of the range v pins at that depth.
//
// i is always in range: verParts never returns an empty slice (strings.Split
// of "" is one empty field), so the callers' 0 and len(v)-1 both index it. A
// guard here would be a branch no test could reach.
func bumpAt(v []int, i int) []int {
	out := append([]int(nil), v[:i+1]...)
	out[i]++
	return out
}

func cmpParts(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func joinParts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ".")
}
