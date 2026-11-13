package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"

	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/overrides"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
)

// runOverrides implements `bk overrides`: apply every patch in a directory to a
// pantry checkout and fail if any of them no longer applies.
//
// A patch stops applying when upstream edits the lines its context hangs on, or
// when one of ours does. Nothing about the build says so afterwards: the recipe
// is merely the unpatched one, and it fails for whatever reason the patch
// existed to remove. Measured 2026-09-24 on go-zpkg/packages, 3 of 231
// overrides had stopped — among them the -Werror switch mozilla.org/nss needs,
// whose absence cost two rebuilds and a duplicate fix for a defect that was
// already fixed.
//
// The factory already reports this, at build time, in a log nobody reads until
// something breaks. This is the same fact asked EARLY, by the same applier:
// overrides.Apply, not `git apply`. bk patches with go-gitdiff, and a check
// that shelled out to git would be a second opinion — one that can pass while
// the builder's own applier refuses, which is the failure it is meant to catch.
func runOverrides(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("overrides", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", "overrides", "directory of recipe overrides: *.patch applied to the tree, *.hcl applied as each recipe is read")
	pantryDir := fset.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout to patch — a FRESH one, since a patch already applied does not apply twice")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	// BEFORE the patches, not after. They are applied to the same tree, and
	// while both formats are present a patch does the logical override's work
	// first — every one of them then reports "already true" and the run says
	// upstream has caught up with all 205. It has not; we had.
	logicalCode, logicalSeen := checkLogical(*dir, *pantryDir, stdout, stderr)

	res, err := overridesApply(overrides.Options{
		Dir:  *dir,
		Root: *pantryDir,
		Warn: func(s string) { fmt.Fprintln(stderr, s) },
	})
	if err != nil {
		fmt.Fprintf(stderr, "overrides: %v\n", err)
		return 1
	}

	// The DENOMINATOR, beside the count. "0 skipped" out of nothing read is
	// the same sentence as "0 skipped" out of every patch, and only one of
	// them is a pass — a `--dir` pointing at an empty directory would
	// otherwise report a clean run forever.
	total := len(res.Applied) + len(res.Skipped)
	if total+logicalSeen == 0 {
		fmt.Fprintf(stderr, "overrides: nothing in %s — is that the right directory?\n", *dir)
		return 1
	}
	if total > 0 {
		fmt.Fprintf(stdout, "%d patch override(s): %d applied, %d no longer apply\n", total, len(res.Applied), len(res.Skipped))
	}
	if len(res.Skipped) == 0 {
		return max(0, logicalCode)
	}

	// Named by PROJECT as well as by patch: the patch name says which file was
	// meant to change, and the project says what will be built wrong.
	projects := make([]string, 0, len(res.SkippedProjects))
	for p := range res.SkippedProjects {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	for _, p := range projects {
		names := append([]string(nil), res.SkippedProjects[p]...)
		sort.Strings(names)
		fmt.Fprintf(stderr, "  %s would build from an UNPATCHED recipe: %v\n", p, names)
	}
	return 1
}

// checkLogical applies every *.hcl override to the recipe it names and says
// what each one did. It returns the exit code it wants and how many overrides
// it saw.
//
// This is the ongoing gate the *.patch check has always been, asked of a format
// that can answer it better. A diff could only say "applies" or "does not", and
// "does not" covers two opposite situations. These three are distinguished:
//
//	applied    the recipe needed it
//	redundant  UPSTREAM HAS CAUGHT UP — delete the override
//	gone       what it edits is not there any more: an error
//
// The middle one is the reason to run this on a schedule rather than only in
// CI. An override directory only ever grows unless something tells you which
// entries have stopped being needed, and a unified diff never could.
func checkLogical(dir, pantryDir string, stdout, stderr io.Writer) (int, int) {
	set, err := logical.LoadDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "overrides: %v\n", err)
		return 1, 0
	}
	projects := set.Projects()
	if len(projects) == 0 {
		return 0, 0
	}

	applied, redundant := 0, 0
	var obsolete, broken, declined []string
	for _, proj := range projects {
		// Through the loader, so the recipe is read, overridden and validated
		// exactly as the factory will do it. A check that read the file its
		// own way would be checking its own reader.
		// ⛔⛔ WHOSE FAULT THE SCHEMA REFUSAL IS DEPENDS ON WHEN IT HAPPENS, AND
		// THE FIRST VERSION OF THIS FIX GOT THAT WRONG. Since the schema was
		// closed (#423) we refuse 42 of upstream's 1932 recipes — deliberately,
		// they use keys nothing here implements — and this loop reported every
		// error as "whose premise is gone", so `additional properties
		// 'aliases' not allowed` read as *our patch no longer applies to
		// python.org*. That is a finding about THEIR file, not ours.
		//
		// But treating every schema refusal that way is equally wrong, and
		// `TestOverridesChecksTheLogicalOnes/it_produces_something_a_recipe_
		// may_not_say` says so: an override that sets `distributable = 7`
		// produces a recipe the schema refuses, and that one IS ours. A test
		// older than this change caught the over-correction.
		//
		// So the upstream recipe is validated FIRST. If it is already refused,
		// nothing can be concluded about our override and the project is
		// declined. If it validates and the OVERRIDDEN result does not, the
		// override produced it, and that fails.
		if _, uerr := recipefile.Load(pantryDir, proj); errors.Is(uerr, pantry.ErrSchema) {
			// ⛔ COUNTED, NOT SKIPPED. A tolerant skip becomes a silent filter:
			// if this ever covers most of the set, the "N logical override(s)"
			// line above is measuring almost nothing, and the count below is
			// the only thing that would say so.
			declined = append(declined, fmt.Sprintf("  %s", proj))
			continue
		}
		_, res, err := recipefile.LoadOverriddenReporting(set, pantryDir, proj)
		if err != nil {
			broken = append(broken, fmt.Sprintf("  %s: %v", proj, err))
			continue
		}
		allRedundant := true
		for _, r := range res {
			if r.Outcome == logical.Applied {
				applied++
				allRedundant = false
				continue
			}
			redundant++
		}
		if allRedundant && len(res) > 0 {
			obsolete = append(obsolete, fmt.Sprintf("  %s (%s)", proj, set.Files[proj]))
		}
	}

	fmt.Fprintf(stdout, "%d logical override(s): %d operation(s) applied, %d already true\n",
		len(projects), applied, redundant)
	if len(declined) > 0 {
		sort.Strings(declined)
		fmt.Fprintf(stdout, "%d of %d upstream recipe(s) this schema declines, so their "+
			"overrides were not checked:\n", len(declined), len(projects))
		for _, d := range declined {
			fmt.Fprintln(stdout, d)
		}
	}
	if len(obsolete) > 0 {
		sort.Strings(obsolete)
		fmt.Fprintf(stdout, "%d override(s) upstream has caught up with — delete them:\n", len(obsolete))
		for _, o := range obsolete {
			fmt.Fprintln(stdout, o)
		}
	}
	if len(broken) > 0 {
		sort.Strings(broken)
		fmt.Fprintf(stderr, "%d override(s) whose premise is gone:\n", len(broken))
		for _, b := range broken {
			fmt.Fprintln(stderr, b)
		}
		return 1, len(projects)
	}
	return 0, len(projects)
}

// overridesApply is a seam: the failure paths here are a filesystem's, and a
// test must reach them without contriving an unreadable directory.
var overridesApply = overrides.Apply
