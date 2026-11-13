package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// cyclePantry: a two-cycle through build dependencies, a self-loop, and a
// chain that is in neither. The shapes are the real ones — gnu.org/gcc
// build-depends on gnu.org/gcc, curl.se/ca-certs runs curl to fetch its bundle
// while curl needs the bundle.
func cyclePantry(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	writeClosureRecipe(t, p, "curl.org",
		"dependencies:\n  lib.org: ^1\nbuild:\n  dependencies:\n    certs.org: '*'\n  script: make\n")
	writeClosureRecipe(t, p, "certs.org",
		"build:\n  dependencies:\n    curl.org: '*'\n  script: make\n")
	writeClosureRecipe(t, p, "gcc.org",
		"build:\n  dependencies:\n    gcc.org: '*'\n  script: make\n")
	writeClosureRecipe(t, p, "lib.org", "build: make\n")
	return p
}

func cyclesOf(t *testing.T, args ...string) (string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	if code := runClosure(args, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	return out.String(), errb.String()
}

// TestClosureNamesTheCyclesItBreaks. `visit` marks before recursing, so it
// terminates on a cycle by ignoring whichever edge closes it — and which edge
// that is depends on the order projects were reached. The COMPONENT does not:
// it is a property of the graph, which is why this reports Tarjan's strongly
// connected components rather than the back edges the walk happened to find.
func TestClosureNamesTheCyclesItBreaks(t *testing.T) {
	p := cyclePantry(t)
	base := []string{"--pantry", p, "--platform", "linux/x86-64"}

	out, _ := cyclesOf(t, append(append([]string{}, base...), "--cycles", "curl.org", "gcc.org")...)
	got := strings.Split(strings.TrimSpace(out), "\n")
	want := []string{"certs.org curl.org", "gcc.org"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("components = %q, want %q", got, want)
	}

	// Reaching the same graph from the other end names the same set. A back
	// edge would not: from gcc.org first, the DFS closes the two-cycle on the
	// other side.
	out2, _ := cyclesOf(t, append(append([]string{}, base...), "--cycles", "gcc.org", "certs.org")...)
	if out2 != out {
		t.Errorf("the answer moved with the roots:\n%q\nvs\n%q", out2, out)
	}

	// The RUNTIME graph is a DAG: asking it for cycles has one answer.
	writeClosureRecipe(t, p, "certs.org", "dependencies:\n  lib.org: '*'\nbuild: make\n")
	if out, _ := cyclesOf(t, append(append([]string{}, base...), "curl.org")...); out == "" {
		t.Error("premise: the runtime walk still produces an order")
	}
}

// The order is a plan, and the reader has to be told which part of it the
// traversal decided. It is not optional output.
func TestClosureWarnsThatPartOfTheOrderIsAGuess(t *testing.T) {
	p := cyclePantry(t)
	base := []string{"--pantry", p, "--platform", "linux/x86-64"}

	out, errb := cyclesOf(t, append(append([]string{}, base...), "--build", "curl.org")...)
	if !strings.Contains(errb, "the order WITHIN each is a guess") {
		t.Errorf("stderr must say so:\n%s", errb)
	}
	if !strings.Contains(errb, "certs.org curl.org") {
		t.Errorf("and name the component:\n%s", errb)
	}
	// 3 projects in 1 cycle, not "1 cycle" alone: the size is what says
	// whether the order is mostly a plan or mostly a guess. Measured on the
	// s390x seed, 32 of 77 projects are in one.
	if !strings.Contains(errb, "2 project(s) in 1 dependency cycle(s)") {
		t.Errorf("the count must carry both numbers:\n%s", errb)
	}
	if !strings.Contains(out, "curl.org") {
		t.Errorf("and the order is still emitted:\n%s", out)
	}

	// A graph with no cycle says nothing. A warning that always fires is not
	// read.
	q := t.TempDir()
	writeClosureRecipe(t, q, "app.org", "dependencies:\n  lib.org: '*'\nbuild: make\n")
	writeClosureRecipe(t, q, "lib.org", "build: make\n")
	if _, errb := cyclesOf(t, "--pantry", q, "--platform", "linux/x86-64", "--build", "app.org"); errb != "" {
		t.Errorf("a DAG must be silent: %q", errb)
	}
}

// warnCycles with no way to warn is a no-op rather than a panic: the graph is
// also built by callers that pass no warn function.
func TestWarnCyclesWithoutAWarner(t *testing.T) {
	warnCycles([][]string{{"a", "b"}}, nil)
}
