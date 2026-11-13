package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/recipefile"
)

// expandSets replaces any root that is a SET with the packages it names.
//
// A set is an ordinary recipe carrying `members` — see pantry.Recipe.Members
// for why it is a recipe and not a new kind of file. Expanding at the ROOT is
// what makes it cost nothing downstream: the dependency walk, the topological
// order, `bk factory`, the publisher and the installer all keep working on
// discrete projects and never learn the word.
//
// Nested: a set may name another set, because the alternative is that the
// first person who wants "the toolchain plus these three" copies the
// toolchain's list. Depth is bounded and a cycle is REPORTED rather than
// followed — a set that contains itself is a mistake someone should see, and
// silently de-duplicating it would hide the day two sets were written to
// include each other.
//
// Order is the file's, not the map's: Go randomises map iteration, and a
// closure whose roots arrive in a different order every run produces a
// different feedback arc set inside a cycle — which is a build order that
// changes for no reason. Members are sorted.
func expandSets(set *logical.Set, overlayDir, pantryDir string, roots []string, warn func(string)) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(p string, trail []string)
	walk = func(p string, trail []string) {
		for _, t := range trail {
			if t == p {
				if warn != nil {
					warn(fmt.Sprintf("set: %s contains itself (%s) — not followed",
						trail[0], strings.Join(append(trail, p), " → ")))
				}
				return
			}
		}
		members, ok, err := setMembers(set, overlayDir, pantryDir, p)
		if err != nil && warn != nil {
			warn(fmt.Sprintf("set: %v", err))
		}
		if !ok {
			// Not a set, or unreadable. An unreadable root is the walk's
			// business to report, not this function's: it has one job.
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			return
		}
		if warn != nil {
			warn(fmt.Sprintf("set: %s names %d member(s)", p, len(members)))
		}
		for _, m := range members {
			walk(m, append(trail, p))
		}
	}
	for _, r := range roots {
		walk(r, nil)
	}
	return out
}

// setMembers reads a project's recipe and returns its members, sorted, or
// false when it is not a set.
//
// A recipe carrying BOTH members and a distributable is refused rather than
// guessed at: it is either a package someone started turning into a set or a
// set someone pasted a download into, and building either reading would be
// wrong.
func setMembers(set *logical.Set, overlayDir, pantryDir, project string) ([]string, bool, error) {
	r, _, err := recipefile.LoadBuildRecipe(set, overlayDir, pantryDir, project)
	if err != nil || r == nil || len(r.Members) == 0 {
		return nil, false, nil
	}
	if r.Distributable != nil {
		return nil, false, fmt.Errorf("%s carries BOTH members and a distributable — "+
			"it is either a package someone began turning into a set or a set someone pasted a "+
			"download into, and building either reading would be wrong; treating it as a package",
			project)
	}
	out := make([]string, 0, len(r.Members))
	for name := range r.Members {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, true, nil
}
