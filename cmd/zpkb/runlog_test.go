package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A log in the shape a GitHub job emits it: an RFC3339 stamp on every line,
// ANSI on the echoed commands, and the verdict lines among a great deal of
// compiler noise.
const sampleLog = `2026-10-05T07:46:28.3702112Z [36;1mecho building[0m
2026-10-05T07:46:29.0000000Z ✅ OK lz4.org 1.10.0 linux/s390x
2026-10-05T07:46:30.0000000Z clang -O2 -c foo.c
2026-10-05T07:46:31.0000000Z ❌ BUILD FAIL zlib.net 1.3.2: run: exit status 2
2026-10-05T07:46:32.0000000Z ✅ OK gnu.org/bash 5.3 linux/s390x
2026-10-05T07:46:33.0000000Z ❌ PUBLISH FAIL gnu.org/m4 1.4.21: push layer: 500
2026-10-05T07:46:34.0000000Z PASS lz4.org 1.10.0
2026-10-05T07:46:35.0000000Z FAIL gnu.org/bash 5.3: exit status 1
2026-10-05T07:46:36.0000000Z === summary (linux/s390x): 2 built, 0 skipped, 2 failed ===
2026-10-05T07:46:37.0000000Z === tests (linux/s390x): 1 passed, 1 failed, 0 with no test, 3 not run ===
`

// A FACTORY log, where the test verdicts carry the 🧪 prefix the factory
// prints and the inner `bk test` lines appear beside them for the same
// package. Counting both doubles; counting only the bare form undercounts.
const factoryLog = `2026-10-05T07:46:29.0000000Z ✅ OK lz4.org 1.10.0 linux/s390x
2026-10-05T07:46:30.0000000Z ✅ OK gnu.org/bash 5.3 linux/s390x
2026-10-05T07:46:31.0000000Z ❌ BUILD FAIL zlib.net 1.3.2: run: exit status 2
2026-10-05T07:46:32.0000000Z PASS lz4.org 1.10.0
2026-10-05T07:46:33.0000000Z 🧪 TEST PASS lz4.org 1.10.0
2026-10-05T07:46:34.0000000Z 🧪 TEST PASS gnu.org/bash 5.3
2026-10-05T07:46:35.0000000Z 🧪 TEST FAIL gnu.org/m4 1.4.21: exit status 1 (recorded, the build stands)
2026-10-05T07:46:36.0000000Z 🧪 TEST NONE gnu.org/sed 4.10 — the recipe declares no test
2026-10-05T07:46:37.0000000Z 🧪 TEST NOT-RUN cmake.org 4.4.4: the test environment failed
2026-10-05T07:46:38.0000000Z === summary (linux/s390x): 2 built, 0 skipped, 1 failed ===
2026-10-05T07:46:39.0000000Z === tests (linux/s390x): 2 passed, 1 failed, 1 with no test, 1 not run ===
`

// THE SECOND DEFECT THIS COMMAND FOUND, on its first two real runs, through
// its own cross-check: two layers print a test verdict and I was counting
// the wrong one. 47 counted against 50 reported, and 29 against 30.
func TestTheFactorysOwnTestVerdictsAreTheOnesItCounts(t *testing.T) {
	l := parseRunLog(strings.NewReader(factoryLog))
	if d := l.disagreements(); len(d) != 0 {
		t.Fatalf("the factory's own log disagrees with itself: %v", d)
	}
	p, f := l.testVerdicts()
	if len(p) != 2 || len(f) != 1 {
		t.Errorf("verdicts = %d passed, %d failed", len(p), len(f))
	}
	// lz4.org appears BOTH ways. It must be counted once.
	n := 0
	for _, v := range p {
		if v.Project == "lz4.org" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("lz4.org counted %d times — the two layers were added together", n)
	}
	if len(l.NoTestBlock) != 1 || len(l.NotRun) != 1 {
		t.Errorf("none=%v notrun=%v", l.NoTestBlock, l.NotRun)
	}
	// And a log with ONLY the inner form still works: `bk test` on its own
	// prints no 🧪 line at all.
	q, _ := parseRunLog(strings.NewReader(sampleLog)).testVerdicts()
	if len(q) != 1 {
		t.Errorf("a standalone bk test log gave %d passes", len(q))
	}
}

func TestParseRunLog(t *testing.T) {
	l := parseRunLog(strings.NewReader(sampleLog))
	if len(l.Built) != 2 || l.Built[0].Project != "lz4.org" || l.Built[0].Version != "1.10.0" {
		t.Errorf("built = %+v", l.Built)
	}
	if len(l.Passed) != 1 || len(l.TestFail) != 1 {
		t.Errorf("tests: passed %+v failed %+v", l.Passed, l.TestFail)
	}
	if l.TestFail[0].Detail != "exit status 1" {
		t.Errorf("the failure's message was lost: %q", l.TestFail[0].Detail)
	}
	if l.Platform != "linux/s390x" {
		t.Errorf("platform = %q", l.Platform)
	}
	if !l.HasSummary || !l.HasTests {
		t.Error("the summary lines were not read")
	}
	if l.SummaryBuilt != 2 || l.SummaryFailed != 2 || l.TestsNotRun != 3 {
		t.Errorf("summary = %+v", l)
	}
}

// THE DEFECT THIS COMMAND EXISTS FOR. The factory writes a failure as
// `❌ <STAGE> FAIL`, with the stage upper-cased from a variable. A parser
// that matched `^FAIL ` — which is what I wrote by hand, eight times, one
// of them published — sees NONE of them, and a parser that matched
// `❌ BUILD FAIL` sees only one stage.
func TestAFailureIsMatchedByItsShapeNotByOneStage(t *testing.T) {
	l := parseRunLog(strings.NewReader(sampleLog))
	if len(l.Failed) != 2 {
		t.Fatalf("expected a BUILD and a PUBLISH failure, got %+v", l.Failed)
	}
	st := l.byStage()
	if len(st["BUILD"]) != 1 || len(st["PUBLISH"]) != 1 {
		t.Errorf("stages = %v", st)
	}
	if st["BUILD"][0].Project != "zlib.net" || st["BUILD"][0].Detail != "run: exit status 2" {
		t.Errorf("build failure = %+v", st["BUILD"][0])
	}
	// And a build failure must NOT be counted as a test failure, which is
	// the other half of the same confusion: `❌ BUILD FAIL x 1: …` contains
	// the substring `FAIL x 1: …`.
	for _, v := range l.TestFail {
		if v.Project == "zlib.net" {
			t.Error("a BUILD failure was counted among the test failures")
		}
	}
}

// bk's totals are an independent witness, and the command's job is to say
// when they disagree — without deciding which side is wrong, because the
// first real run proved the parser can be the right one.
func TestDisagreementIsReportedAndNotAdjudicated(t *testing.T) {
	l := parseRunLog(strings.NewReader(sampleLog))
	if d := l.disagreements(); len(d) != 0 {
		t.Fatalf("a consistent log reported %v", d)
	}

	// One PASS line removed, the summary left saying 1.
	short := strings.Replace(sampleLog, "2026-10-05T07:46:34.0000000Z PASS lz4.org 1.10.0\n", "", 1)
	d := parseRunLog(strings.NewReader(short)).disagreements()
	if len(d) != 1 || !strings.Contains(d[0], "tests passed: counted 0, bk reported 1") {
		t.Errorf("disagreements = %v", d)
	}

	// And it is loud on stderr, and it FAILS, so a script cannot publish a
	// number that is in dispute.
	var out, errb bytes.Buffer
	if code := runlogOn(t, short, &out, &errb); code != 1 {
		t.Errorf("a disagreement exited %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "DISAGREES") {
		t.Errorf("stderr = %q", errb.String())
	}
	// It must not tell the reader which side to believe.
	if strings.Contains(errb.String(), "trust them over this parse") {
		t.Error("it adjudicates; the first real run showed the parser can be right")
	}
}

// runlogOn runs the command over a literal log through a temp file.
func runlogOn(t *testing.T, body string, out, errb *bytes.Buffer) int {
	t.Helper()
	p := filepath.Join(t.TempDir(), "job.log")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return runRunlog([]string{p}, out, errb)
}

func TestRunlogReportsTheCounts(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runlogOn(t, sampleLog, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	for _, want := range []string{
		"platform: linux/s390x",
		"builds:   2 ok, 2 failed",
		"tests:    1 passed, 1 failed",
		"zpkb said:  2 built, 0 skipped, 2 failed",
		"by stage: build 1, publish 1",
		"test failures after a successful build: 1 of 1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

// --failures lists them, grouped, with the message that says what happened.
func TestRunlogListsFailures(t *testing.T) {
	p := filepath.Join(t.TempDir(), "job.log")
	if err := os.WriteFile(p, []byte(sampleLog), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runRunlog([]string{"--failures", p}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	for _, want := range []string{"BUILD FAIL (1):", "PUBLISH FAIL (1):", "zlib.net", "run: exit status 2", "test failures (1):"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

// A test failure on a package that BUILT is a different thing from one on a
// package that did not, and the first time I asked this the set had already
// been filtered by a broken pattern so it could only answer "all of them".
func TestAfterASuccessfulBuild(t *testing.T) {
	l := parseRunLog(strings.NewReader(sampleLog +
		"FAIL never.built 9.9: exit status 3\n"))
	yes, no := l.afterASuccessfulBuild()
	if strings.Join(yes, " ") != "gnu.org/bash" {
		t.Errorf("after a build = %v", yes)
	}
	if strings.Join(no, " ") != "never.built" {
		t.Errorf("without a build = %v", no)
	}
}

// Nothing recognised is NOT an empty run. A log fetched from the wrong job,
// or a 404 body saved to a file, reads exactly like a run where nothing
// happened — and reporting zeros would be a lie nearly every time.
func TestRunlogRefusesWhatIsNotAJobLog(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runlogOn(t, "{\n  \"message\": \"Not Found\",\n  \"status\": \"404\"\n}\n", &out, &errb); code != 1 {
		t.Errorf("a 404 body exited %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "not a factory job log") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestRunlogArgumentsAndStdin(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runRunlog([]string{"a", "b"}, &out, &errb); code != 2 {
		t.Errorf("two files exited %d, want 2", code)
	}
	if code := runRunlog([]string{"--nope"}, &out, &errb); code != 2 {
		t.Errorf("a bad flag exited %d, want 2", code)
	}
	if code := runRunlog([]string{filepath.Join(t.TempDir(), "absent")}, &out, &errb); code != 2 {
		t.Errorf("a missing file exited %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "runlog:") {
		t.Errorf("stderr = %q", errb.String())
	}

	// stdin, which is how it is piped from `gh run view --log`.
	prev := osOpen
	osOpen = func(string) (io.ReadCloser, error) { return nil, errors.New("unused") }
	t.Cleanup(func() { osOpen = prev })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin })
	go func() { _, _ = w.WriteString(sampleLog); _ = w.Close() }()
	out.Reset()
	errb.Reset()
	if code := runRunlog(nil, &out, &errb); code != 0 {
		t.Fatalf("stdin: code=%d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "builds:   2 ok, 2 failed") {
		t.Errorf("stdin out = %q", out.String())
	}
}

// A line longer than bufio's default is ordinary here: one `clang` command
// in a build log can run to tens of kilobytes, and a scanner that stopped
// there would silently drop every verdict after it.
func TestALongLineDoesNotStopTheScan(t *testing.T) {
	long := "2026-10-05T07:46:30.0000000Z clang " + strings.Repeat("-I/very/long/path ", 20000) + "\n"
	l := parseRunLog(strings.NewReader(long + sampleLog))
	if len(l.Built) != 2 {
		t.Errorf("a long line truncated the scan: built = %d", len(l.Built))
	}
}

// TestRunlogDispatch covers the main-loop route.
func TestRunlogDispatch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "job.log")
	if err := os.WriteFile(p, []byte(sampleLog), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run2(t, "runlog", p)
	if code != 0 {
		t.Fatalf("code=%d %s", code, errs)
	}
	if !strings.Contains(out, "builds:   2 ok") {
		t.Errorf("out = %q", out)
	}
}
