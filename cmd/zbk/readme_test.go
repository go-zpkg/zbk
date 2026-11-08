package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// numberWords is as far as this needs to count.
//
// It used to stop at twenty-nine, with "a subcommand list that grew past
// twenty-nine would want a different sentence anyway" — and `bk attest` made
// it thirty, so that prediction has come true rather than been avoided. The
// table is extended rather than the sentence rewritten: deciding that a prose
// list of thirty names should become a table is a call about the README, not
// about this guard, and making it silently here would hide it.
var numberWords = map[int]string{
	18: "eighteen", 19: "nineteen", 20: "twenty", 21: "twenty-one",
	22: "twenty-two", 23: "twenty-three", 24: "twenty-four", 25: "twenty-five",
	26: "twenty-six", 27: "twenty-seven", 28: "twenty-eight", 29: "twenty-nine",
	30: "thirty", 31: "thirty-one", 32: "thirty-two", 33: "thirty-three",
	34: "thirty-four", 35: "thirty-five", 36: "thirty-six",
	37: "thirty-seven", 38: "thirty-eight",
}

// The README says how many subcommands bk has and names them. Both drifted:
// `bk lock` shipped in #295 and the line still said "twenty-one subcommands"
// and did not list it.
//
// A guard rather than a correction, because the correction is what rots. It
// reads the DISPATCH SWITCH, which is the only place that decides what `bk
// <word>` does, so nothing can be added without this test seeing it.
//
// Scoped to the one table row, not to the whole file: a search of the whole
// README would find `lock` in prose somewhere and pass while the row stayed
// wrong.
func TestTheREADMECountsTheSubcommandsItHas(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	// Every `case "x":` and `case "x", "y":` in the dispatch.
	var names []string
	for _, m := range regexp.MustCompile(`(?m)^\tcase ("(?:[a-z0-9-]+)"(?:, "[a-z0-9-]+")*):`).FindAllStringSubmatch(string(src), -1) {
		for _, q := range regexp.MustCompile(`"([a-z0-9-]+)"`).FindAllStringSubmatch(m[1], -1) {
			names = append(names, q[1])
		}
	}
	if len(names) < 18 {
		t.Fatalf("only %d dispatch cases found — this test stopped reading main.go rather than main.go shrinking: %v", len(names), names)
	}

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, line := range strings.Split(string(readme), "\n") {
		// `cmd/zbk` since the rename — the directory really is called that.
		if strings.HasPrefix(line, "| `cmd/zbk` |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("the README has no `cmd/zbk` row — if the table moved, move this guard with it")
	}

	want, ok := numberWords[len(names)]
	if !ok {
		t.Fatalf("%d subcommands, and numberWords does not spell that", len(names))
	}
	if !strings.Contains(row, want+" subcommands") {
		t.Errorf("main.go dispatches %d subcommands; the README row does not say %q:\n%s", len(names), want+" subcommands", row)
	}
	// And each one is named somewhere in that row. A count alone would pass
	// with the wrong names in it.
	for _, n := range names {
		if !strings.Contains(row, "`"+n+"`") {
			t.Errorf("`bk %s` dispatches and the README row does not name it", n)
		}
	}
}
