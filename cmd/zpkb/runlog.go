package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Reading a factory run's log, in Go, because reading it in awk cost a
// published falsehood.
//
// # WHY THIS EXISTS
//
// Over one day I wrote this parser eight times as a throwaway `python3 -c`,
// and the seventh was wrong. It matched `^FAIL ` for failures; the factory
// writes a BUILD failure as `❌ BUILD FAIL`, so fourteen of them went
// through the net and I reported "0 build failures" on an issue. The
// cross-check I offered alongside — "every failure came after a successful
// build" — could not have failed, because the set it checked had already
// been filtered by the same broken pattern.
//
// Two things make that mistake hard to repeat here, and neither is care:
//
//	the SHAPE, not an instance   the factory prints `❌ <STAGE> FAIL …` with
//	                             the stage upper-cased from a variable, so
//	                             BUILD is one of several and a parser that
//	                             names it is wrong the moment a PUBLISH
//	                             failure happens. This matches the shape and
//	                             reports the stages it found.
//	an INDEPENDENT witness       bk prints its own totals. This parses them
//	                             too and says so when they disagree with the
//	                             count — a check whose answer does not come
//	                             from the thing being checked.
type runLog struct {
	Built  []verdict // ✅ OK
	Failed []verdict // ❌ <STAGE> FAIL

	// The FACTORY's own test verdicts, which is what its tallies count.
	FactoryPassed   []verdict // 🧪 TEST PASS
	FactoryTestFail []verdict // 🧪 TEST FAIL
	NoTestBlock     []verdict // 🧪 TEST NONE
	NotRun          []verdict // 🧪 TEST NOT-RUN

	// The INNER `bk test`'s, which appear only when it was run as its own
	// command — or alongside, which is why they are kept apart. Counting
	// the two together double-counts; counting only these undercounts.
	Passed   []verdict // PASS
	TestFail []verdict // FAIL

	// What bk said about itself, -1 when the line was absent.
	SummaryBuilt, SummarySkipped, SummaryFailed        int
	TestsPassed, TestsFailed, TestsNoTest, TestsNotRun int
	HasSummary, HasTests                               bool
	Platform                                           string
}

// verdict is one line's worth: who, which version, and for a failure the
// stage and the message.
type verdict struct {
	Project, Version, Stage, Detail string
}

var (
	// The factory's own formats, as factory.go and test.go write them:
	//
	//	fmt.Fprintf(f.stdout, "✅ OK %s %s %s\n", proj, tag, platform)
	//	fmt.Fprintf(f.stdout, "❌ %s FAIL %s %s: %v\n", STAGE, proj, ver, err)
	//	fmt.Fprintf(stdout, "PASS %s %s\n", project, ver)
	//	fmt.Fprintf(stderr, "FAIL %s %s: %v\n", project, ver, err)
	reOK   = regexp.MustCompile(`^✅ OK (\S+) (\S+)(?: (\S+))?$`)
	reFail = regexp.MustCompile(`^❌ ([A-Z][A-Z ]*?) FAIL (\S+) (\S+): (.*)$`)
	rePass = regexp.MustCompile(`^PASS (\S+) (\S+)$`)
	reTF   = regexp.MustCompile(`^FAIL (\S+) (\S+): (.*)$`)

	// TWO LAYERS PRINT A TEST VERDICT, and counting the wrong one undercounts.
	//
	//	bk test      PASS zlib.net 1.3.2
	//	bk factory   🧪 TEST PASS zlib.net 1.3.2
	//
	// The factory runs the test and prints its OWN line; the inner `bk test`
	// line is not always there. Counting only the bare form gave 47 where the
	// factory's counter said 50 on run 37301639438, and 29 against 30 on
	// 37279391375 — found by this command's cross-check, on its first two
	// runs, which is the whole reason the cross-check exists.
	reFPass = regexp.MustCompile(`^🧪 TEST PASS (\S+) (\S+)$`)
	reFFail = regexp.MustCompile(`^🧪 TEST FAIL (\S+) (\S+): (.*)$`)
	reFNone = regexp.MustCompile(`^🧪 TEST NONE (\S+) (\S+)`)
	reFSkip = regexp.MustCompile(`^🧪 TEST NOT-RUN (\S+) (\S+): (.*)$`)

	reSummary = regexp.MustCompile(`^=== summary \(([^)]*)\): (\d+) built, (\d+) skipped, (\d+) failed ===$`)
	reTests   = regexp.MustCompile(`^=== tests \(([^)]*)\): (\d+) passed, (\d+) failed, (\d+) with no test, (\d+) not run ===$`)

	// A GitHub job log prefixes every line with an RFC3339 timestamp, and
	// the setup steps wrap their echoes in ANSI colour. Both are noise the
	// caller should not have to strip before asking a question.
	reStamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T[0-9:.]+Z `)
	reANSI  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

// parseRunLog reads a factory job log.
//
// Tolerant of what wraps the lines and strict about the lines themselves: a
// log fetched from the GitHub API, piped through `gh run view --log`, or
// produced locally all parse, and a verdict line that does not match its
// format is not silently counted as something else.
func parseRunLog(r io.Reader) runLog {
	out := runLog{SummaryBuilt: -1, SummaryFailed: -1}
	sc := bufio.NewScanner(r)
	// A single build line can carry a whole compiler invocation.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(reANSI.ReplaceAllString(reStamp.ReplaceAllString(sc.Text(), ""), ""), "\r\n")
		switch {
		case reOK.MatchString(line):
			m := reOK.FindStringSubmatch(line)
			out.Built = append(out.Built, verdict{Project: m[1], Version: m[2]})
		case reFail.MatchString(line):
			m := reFail.FindStringSubmatch(line)
			out.Failed = append(out.Failed, verdict{Stage: m[1], Project: m[2], Version: m[3], Detail: m[4]})
		case reFPass.MatchString(line):
			m := reFPass.FindStringSubmatch(line)
			out.FactoryPassed = append(out.FactoryPassed, verdict{Project: m[1], Version: m[2]})
		case reFFail.MatchString(line):
			m := reFFail.FindStringSubmatch(line)
			out.FactoryTestFail = append(out.FactoryTestFail, verdict{Project: m[1], Version: m[2], Detail: m[3]})
		case reFNone.MatchString(line):
			m := reFNone.FindStringSubmatch(line)
			out.NoTestBlock = append(out.NoTestBlock, verdict{Project: m[1], Version: m[2]})
		case reFSkip.MatchString(line):
			m := reFSkip.FindStringSubmatch(line)
			out.NotRun = append(out.NotRun, verdict{Project: m[1], Version: m[2], Detail: m[3]})
		case rePass.MatchString(line):
			m := rePass.FindStringSubmatch(line)
			out.Passed = append(out.Passed, verdict{Project: m[1], Version: m[2]})
		case reTF.MatchString(line):
			m := reTF.FindStringSubmatch(line)
			out.TestFail = append(out.TestFail, verdict{Project: m[1], Version: m[2], Detail: m[3]})
		case reSummary.MatchString(line):
			m := reSummary.FindStringSubmatch(line)
			out.Platform = m[1]
			out.SummaryBuilt, _ = strconv.Atoi(m[2])
			out.SummarySkipped, _ = strconv.Atoi(m[3])
			out.SummaryFailed, _ = strconv.Atoi(m[4])
			out.HasSummary = true
		case reTests.MatchString(line):
			m := reTests.FindStringSubmatch(line)
			out.Platform = m[1]
			out.TestsPassed, _ = strconv.Atoi(m[2])
			out.TestsFailed, _ = strconv.Atoi(m[3])
			out.TestsNoTest, _ = strconv.Atoi(m[4])
			out.TestsNotRun, _ = strconv.Atoi(m[5])
			out.HasTests = true
		}
	}
	return out
}

// disagreements compares what was counted with what bk reported.
//
// THE POINT OF THE WHOLE COMMAND. A parser cannot check itself: the set it
// produces is the set it would check against. bk's own totals come from
// counters incremented at the point of decision, so they are an independent
// witness.
//
// WHICH SIDE IS WRONG IS NOT DECIDED HERE, and the first real run is why.
// Against run 37279391375 this reported "tests passed: counted 29, bk
// reported 30" — and the log holds exactly 29 lines beginning `PASS`. The
// parser was right; the factory increments a counter somewhere it does not
// print a line. Had this message said "trust bk", it would have sent its
// reader to fix the parser.
func (l runLog) disagreements() []string {
	var out []string
	cmp := func(what string, counted, reported int) {
		if counted != reported {
			out = append(out, fmt.Sprintf("%s: counted %d, bk reported %d", what, counted, reported))
		}
	}
	if l.HasSummary {
		cmp("built", len(l.Built), l.SummaryBuilt)
		cmp("failed", len(l.Failed), l.SummaryFailed)
	}
	if l.HasTests {
		p, f := l.testVerdicts()
		cmp("tests passed", len(p), l.TestsPassed)
		cmp("tests failed", len(f), l.TestsFailed)
		// Only the FACTORY prints a line for these two, so they can be
		// compared only against a factory log. A standalone `bk test` log
		// has no such line and counting zero against the summary would be
		// comparing one layer's silence with another layer's tally —
		// exactly the across-layers mistake this whole check exists to
		// catch, made by the check itself.
		if l.sawFactoryVerdicts() {
			cmp("tests with no block", len(l.NoTestBlock), l.TestsNoTest)
			cmp("tests not run", len(l.NotRun), l.TestsNotRun)
		}
	}
	return out
}

// testVerdicts picks the layer that actually reported.
//
// The factory's own lines when it printed any, the inner `bk test`'s
// otherwise. Never both: a factory log contains both forms for the same
// package, and adding them says every test ran twice.
func (l runLog) testVerdicts() (passed, failed []verdict) {
	if l.sawFactoryVerdicts() {
		return l.FactoryPassed, l.FactoryTestFail
	}
	return l.Passed, l.TestFail
}

// sawFactoryVerdicts reports whether the factory printed its own test
// lines, which is what decides WHICH layer's numbers mean anything.
func (l runLog) sawFactoryVerdicts() bool {
	return len(l.FactoryPassed)+len(l.FactoryTestFail)+len(l.NoTestBlock)+len(l.NotRun) > 0
}

// byStage groups failures, because "15 failed" says nothing about whether
// the factory cannot build or cannot publish.
func (l runLog) byStage() map[string][]verdict {
	m := map[string][]verdict{}
	for _, v := range l.Failed {
		m[v.Stage] = append(m[v.Stage], v)
	}
	return m
}

// afterASuccessfulBuild reports which test failures follow a build that
// succeeded. Worth naming because the answer changes what the failure means:
// a test that failed on a package that built is a test problem, and the
// first time I asked this question the set I asked it of had already been
// filtered by a broken pattern, so it could only answer "all of them".
func (l runLog) afterASuccessfulBuild() (yes, no []string) {
	built := map[string]bool{}
	for _, v := range l.Built {
		built[v.Project] = true
	}
	_, failed := l.testVerdicts()
	for _, v := range failed {
		if built[v.Project] {
			yes = append(yes, v.Project)
		} else {
			no = append(no, v.Project)
		}
	}
	sort.Strings(yes)
	sort.Strings(no)
	return yes, no
}

func runRunlog(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runlog", flag.ContinueOnError)
	fs.SetOutput(stderr)
	failures := fs.Bool("failures", false, "list every failure, grouped by stage")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var r io.Reader = os.Stdin
	switch fs.NArg() {
	case 0:
	case 1:
		f, err := osOpen(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, "runlog:", err)
			return 2
		}
		defer f.Close()
		r = f
	default:
		fmt.Fprintln(stderr, "runlog: usage: zpkb runlog [--failures] [log]  (or on stdin)")
		return 2
	}

	l := parseRunLog(r)
	tPass, tFail := l.testVerdicts()
	if len(l.Built)+len(l.Failed)+len(tPass)+len(tFail) == 0 && !l.HasSummary {
		// Nothing recognised is not an empty run. A log fetched from the
		// wrong job, or a 404 body saved to a file, reads exactly like a
		// run where nothing happened — and the second is so rare that
		// reporting zeros would be a lie nearly every time.
		fmt.Fprintln(stderr, "runlog: no verdict line and no summary — this is not a factory job log")
		return 1
	}

	if l.Platform != "" {
		fmt.Fprintf(stdout, "platform: %s\n", l.Platform)
	}
	fmt.Fprintf(stdout, "builds:   %d ok, %d failed\n", len(l.Built), len(l.Failed))
	fmt.Fprintf(stdout, "tests:    %d passed, %d failed\n", len(tPass), len(tFail))
	if l.HasSummary {
		fmt.Fprintf(stdout, "zpkb said:  %d built, %d skipped, %d failed\n", l.SummaryBuilt, l.SummarySkipped, l.SummaryFailed)
	}
	if l.HasTests {
		fmt.Fprintf(stdout, "zpkb said:  %d passed, %d failed, %d with no test, %d not run\n",
			l.TestsPassed, l.TestsFailed, l.TestsNoTest, l.TestsNotRun)
	}
	if st := l.byStage(); len(st) > 0 {
		var names []string
		for s := range st {
			names = append(names, fmt.Sprintf("%s %d", strings.ToLower(s), len(st[s])))
		}
		sort.Strings(names)
		fmt.Fprintf(stdout, "by stage: %s\n", strings.Join(names, ", "))
	}
	if yes, no := l.afterASuccessfulBuild(); len(tFail) > 0 {
		fmt.Fprintf(stdout, "test failures after a successful build: %d of %d\n", len(yes), len(yes)+len(no))
	}

	// Loudly, and last, so it is the thing left on screen.
	if d := l.disagreements(); len(d) > 0 {
		fmt.Fprintln(stderr, "runlog: THIS PARSE DISAGREES WITH BK'S OWN TOTALS —")
		for _, s := range d {
			fmt.Fprintln(stderr, "  "+s)
		}
		fmt.Fprintln(stderr, "  Either side can be the wrong one: zpkb counts where the decision is made and this")
		fmt.Fprintln(stderr, "  counts what it printed, so a difference is a line that was never written just as")
		fmt.Fprintln(stderr, "  often as a line that was not read. Do not publish a number until it is resolved.")
		return 1
	}

	if *failures {
		st := l.byStage()
		var stages []string
		for s := range st {
			stages = append(stages, s)
		}
		sort.Strings(stages)
		for _, s := range stages {
			fmt.Fprintf(stdout, "\n%s FAIL (%d):\n", s, len(st[s]))
			for _, v := range st[s] {
				fmt.Fprintf(stdout, "  %-34s %-12s %s\n", v.Project, v.Version, v.Detail)
			}
		}
		if len(tFail) > 0 {
			fmt.Fprintf(stdout, "\ntest failures (%d):\n", len(tFail))
			for _, v := range tFail {
				fmt.Fprintf(stdout, "  %-34s %-12s %s\n", v.Project, v.Version, v.Detail)
			}
		}
	}
	return 0
}

// osOpen is a seam.
var osOpen = func(name string) (io.ReadCloser, error) { return os.Open(name) }
