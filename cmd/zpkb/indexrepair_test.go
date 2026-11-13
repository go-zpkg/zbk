package main

import (
	"errors"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type fakeEnsurer struct {
	repaired  map[string]bool // "project tag" -> repair happened
	repairAll bool
	err       error
	calls     []string
}

func (f *fakeEnsurer) EnsureIndexed(project, ver string, _ ocispec.Descriptor) (bool, error) {
	f.calls = append(f.calls, project+" "+ver)
	if f.err != nil {
		return false, f.err
	}
	return f.repairAll || f.repaired[project+" "+ver], nil
}

func withEnsurer(t *testing.T, e *fakeEnsurer, err error) {
	t.Helper()
	orig := newOCIClient
	newOCIClient = func(string) (indexEnsurer, error) {
		if err != nil {
			return nil, err
		}
		return e, nil
	}
	t.Cleanup(func() { newOCIClient = orig })
}

// TestRepairIndexesChecksEveryPublish: the pass exists because a racer can drop
// a platform from ANY index this run wrote, so checking a subset is checking
// nothing.
func TestRepairIndexesChecksEveryPublish(t *testing.T) {
	e := &fakeEnsurer{repaired: map[string]bool{"b.org 2.0.0": true}}
	withEnsurer(t, e, nil)
	pubs := []published{
		{project: "a.org", tag: "1.0.0"},
		{project: "b.org", tag: "2.0.0"},
		{project: "c.org", tag: "3.0.0"},
	}
	var out, errb strings.Builder

	if n := repairIndexes("oci://x/y", pubs, &out, &errb); n != 1 {
		t.Fatalf("repaired %d, want 1", n)
	}
	if len(e.calls) != 3 {
		t.Errorf("checked %v, want all three", e.calls)
	}
	if !strings.Contains(out.String(), "b.org 2.0.0") {
		t.Errorf("the repair is not reported:\n%s", out.String())
	}
	if strings.Contains(out.String(), "a.org") {
		t.Errorf("an intact index was reported as repaired:\n%s", out.String())
	}
}

// TestRepairIndexesKeepsGoingAfterAnError: one unreachable project must not
// hide the state of the others — the run has already done the work.
func TestRepairIndexesKeepsGoingAfterAnError(t *testing.T) {
	e := &fakeEnsurer{err: errors.New("registry down")}
	withEnsurer(t, e, nil)
	pubs := []published{{project: "a.org", tag: "1.0.0"}, {project: "b.org", tag: "2.0.0"}}
	var out, errb strings.Builder

	if n := repairIndexes("oci://x/y", pubs, &out, &errb); n != 0 {
		t.Fatalf("repaired %d", n)
	}
	if len(e.calls) != 2 {
		t.Errorf("stopped after the first error: %v", e.calls)
	}
	if !strings.Contains(errb.String(), "registry down") {
		t.Errorf("the cause is not reported: %q", errb.String())
	}
}

// TestRepairIndexesNoopsWithoutWork: nothing published, or no registry, means
// nothing to check — and no client to build.
func TestRepairIndexesNoopsWithoutWork(t *testing.T) {
	e := &fakeEnsurer{}
	withEnsurer(t, e, nil)
	var out, errb strings.Builder

	if n := repairIndexes("oci://x/y", nil, &out, &errb); n != 0 {
		t.Errorf("repaired %d with nothing published", n)
	}
	if n := repairIndexes("", []published{{project: "a.org", tag: "1"}}, &out, &errb); n != 0 {
		t.Errorf("repaired %d with no dist", n)
	}
	if len(e.calls) != 0 {
		t.Errorf("talked to a registry anyway: %v", e.calls)
	}
}

// TestRepairIndexesReportsAnUnusableRegistry, rather than failing the run: the
// bottles are pushed and valid, and throwing away a whole build over an index
// check would cost more than the check is worth.
func TestRepairIndexesReportsAnUnusableRegistry(t *testing.T) {
	withEnsurer(t, nil, errors.New("bad dist"))
	var out, errb strings.Builder

	if n := repairIndexes("oci://x/y", []published{{project: "a.org", tag: "1"}}, &out, &errb); n != 0 {
		t.Errorf("repaired %d", n)
	}
	if !strings.Contains(errb.String(), "bad dist") {
		t.Errorf("the cause is not reported: %q", errb.String())
	}
}
