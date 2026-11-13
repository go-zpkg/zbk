package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOrder(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "order.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runOrder(t *testing.T, pan, overrides, path string, roots ...string) (int, string, string) {
	t.Helper()
	args := []string{"--pantry", pan, "--platform", "linux/x86-64", "--build", "--check-order", path}
	if overrides != "" {
		args = append(args, "--overrides", overrides)
	}
	var out, errb bytes.Buffer
	code := runClosure(append(args, roots...), &out, &errb)
	return code, out.String(), errb.String()
}

// TestCheckOrderSeparatesTheMistakeFromTheChoice. An order over a graph with
// cycles is a topological sort of everything else PLUS a choice of which edges
// to give up on — what Debian's bootstrap tooling calls a feedback arc set. The
// two are different in kind and this is the whole point of the command: inside
// a cycle there is no alternative, outside one there is no excuse.
//
// Measured on the s390x seed's hand-tuned order.txt, 2026-09-28: 19 edges given
// up inside cycles, and TWO outside any — rust-lang.org and
// rust-lang.org/cargo both built before llvm.org, which is in a different
// component. That is the failure the run reported as
// `cargo: resolve deps: GET .../llvm.org/linux/s390x/versions.txt: Not Found`.
func TestCheckOrderSeparatesTheMistakeFromTheChoice(t *testing.T) {
	pan := cyclePantry(t) // curl.org <-> certs.org, gcc.org self, lib.org free
	// lib.org is in NO cycle and curl.org needs it: putting it last is a
	// mistake with no excuse.
	bad := writeOrder(t, "gcc.org", "certs.org", "curl.org", "lib.org")
	code, out, errb := runOrder(t, pan, "", bad, "curl.org", "gcc.org")
	if code != 1 {
		t.Fatalf("code = %d, want 1\n%s%s", code, out, errb)
	}
	if !strings.Contains(errb, "OUTSIDE any cycle") || !strings.Contains(errb, "curl.org") {
		t.Errorf("stderr:\n%s", errb)
	}
	// And the cycle's own edge is reported as a CHOICE, on stdout, not as a
	// fault: certs.org before curl.org gives up curl.org -> certs.org.
	if !strings.Contains(out, "gives up on") {
		t.Errorf("stdout:\n%s", out)
	}

	// lib.org first and the same cycle: no mistake left, and the choice stays.
	good := writeOrder(t, "lib.org", "gcc.org", "certs.org", "curl.org")
	code, out, errb = runOrder(t, pan, "", good, "curl.org", "gcc.org")
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s%s", code, out, errb)
	}
	if !strings.Contains(out, "gives up on") {
		t.Errorf("the choice must still be named:\n%s", out)
	}
	if strings.Contains(errb, "OUTSIDE") {
		t.Errorf("stderr:\n%s", errb)
	}
}

// A project the closure needs and the order does not name is a hole: the build
// reaches it with nothing published, which is the same failure as bad ordering
// and looks nothing like it in the log.
func TestCheckOrderReportsWhatTheOrderOmits(t *testing.T) {
	pan := cyclePantry(t)
	p := writeOrder(t, "curl.org", "certs.org") // lib.org missing
	code, _, errb := runOrder(t, pan, "", p, "curl.org")
	if code != 1 {
		t.Fatalf("code = %d, want 1: %s", code, errb)
	}
	if !strings.Contains(errb, "does not name") || !strings.Contains(errb, "lib.org") {
		t.Errorf("stderr:\n%s", errb)
	}
}

func TestReadOrder(t *testing.T) {
	// Comments, blanks, and the `project@constraint` word a dispatch uses —
	// the seed pins tcl-lang.org@=9.0.4 and the order still names tcl-lang.org.
	p := writeOrder(t, "# a note", "", "  lib.org  ", "tcl-lang.org@=9.0.4", "")
	got, err := readOrder(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "lib.org" || got[1] != "tcl-lang.org" {
		t.Errorf("got %q", got)
	}

	// An order with nothing in it agrees with every graph, which is the
	// "a scan that could not read reported zero" shape.
	empty := writeOrder(t, "# only a comment")
	if _, err := readOrder(empty); err == nil {
		t.Error("an empty order must be refused, not accepted as agreement")
	}
	if _, err := readOrder(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing file must be an error")
	}
}

// The command reports the file it cannot read, rather than walking the pantry
// for minutes first and failing at the end.
func TestCheckOrderOnAnUnreadableFile(t *testing.T) {
	pan := cyclePantry(t)
	code, _, errb := runOrder(t, pan, "", filepath.Join(t.TempDir(), "absent"), "curl.org")
	if code != 2 {
		t.Fatalf("code = %d, want 2: %s", code, errb)
	}
}

// A line longer than bufio's 64 KiB buffer stops the scanner. Reporting it
// beats reading the first half of an order file and calling that the order:
// the projects past the long line would be missing, and a missing project
// reads as "nothing needs it".
func TestReadOrderRefusesAFileItCannotScan(t *testing.T) {
	p := filepath.Join(t.TempDir(), "order.txt")
	if err := os.WriteFile(p, []byte("lib.org\n"+strings.Repeat("x", 70*1024)+"\ngcc.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readOrder(p)
	if err == nil {
		t.Fatalf("want an error, got %d project(s)", len(got))
	}
}
