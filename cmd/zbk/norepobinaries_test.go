package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// maxTrackedBytes is what a source file may plausibly weigh. A compiled binary
// is not.
const maxTrackedBytes = 2 << 20 // 2 MiB

// allowedLarge names tracked files that may exceed the limit on purpose.
// Empty today; a line added here should say WHY in its value rather than just
// silence the gate.
var allowedLarge = map[string]string{}

// ⛔⛔ A 19 MB COMPILED BINARY SAT IN HEAD FOR THREE MONTHS. `bk` — this
// command's old name — was committed by #9 in August 2026, never touched
// again, and never noticed: nothing referenced it, `.gitignore` did not
// mention it, and no check looked. Measured before removing it:
//
//	raw     19 771 746 bytes
//	on disk 10 575 333 bytes, of a ~15 MiB .git
//
// So one dead file was about two thirds of the repository and every clone paid
// for it. ⛔ Removing it from HEAD does NOT reclaim the history: only a rewrite
// would, and a rewrite changes commit ids, so every tag would have to be
// recreated — which this project does not do, by rule. The weight is therefore
// permanent, and the only thing still worth protecting is the future.
//
// This is that protection. It reads TRACKED files rather than the working
// tree, because a developer's own build output is untracked and must not fail
// anybody's test run — that false positive is how a gate gets deleted.
func TestNoCompiledBinaryIsTracked(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on this lane")
	}
	top, err := exec.Command(git, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	root := strings.TrimSpace(string(top))

	// -C the toplevel: run from this package's directory, `git ls-files` would
	// list only what is under it, and the binary that prompted this test sat at
	// the repository root.
	out, err := exec.Command(git, "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	names := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	// A gate that read nothing reports the same clean result as one that read
	// everything, so the corpus is asserted before it is judged.
	if len(names) < 50 {
		t.Fatalf("only %d tracked file(s) listed; the listing is wrong, not the repository", len(names))
	}

	var heavy []string
	for _, name := range names {
		if name == "" {
			continue
		}
		fi, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			continue // tracked but not checked out here; not this test's business
		}
		if fi.Size() <= maxTrackedBytes {
			continue
		}
		if why, ok := allowedLarge[filepath.ToSlash(name)]; ok {
			t.Logf("allowed: %s (%d bytes) — %s", name, fi.Size(), why)
			continue
		}
		heavy = append(heavy, name)
	}
	if len(heavy) > 0 {
		t.Errorf("%d of %d tracked file(s) are over %d bytes, which is what a committed "+
			"build artefact looks like — remove it, or add it to allowedLarge with a "+
			"reason:\n  %s",
			len(heavy), len(names), maxTrackedBytes, strings.Join(heavy, "\n  "))
		return
	}
	// Only claimed when it is true: the first version logged "none over the
	// limit" unconditionally, directly under a failure naming one.
	t.Logf("%d tracked file(s) read, none over %d bytes", len(names), maxTrackedBytes)
}
