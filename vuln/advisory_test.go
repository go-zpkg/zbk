package vuln

import (
	"strings"
	"testing"
)

// A file shaped like the curl one Wolfi publishes: an id, the aliases that map
// it across databases, and one dated event.
const oneFixed = `schema-version: 1
project: curl.se
advisories:
  - id: CVE-2023-46219
    aliases:
      - GHSA-fj44-3xpp-9cx2
    events:
      - timestamp: 2024-03-31T02:11:27Z
        type: fixed
        fixed-version: 8.5.0
`

func TestParseOneFixedAdvisory(t *testing.T) {
	f, err := ParseAdvisories([]byte(oneFixed))
	if err != nil {
		t.Fatalf("ParseAdvisories: %v", err)
	}
	if f.Project != "curl.se" || len(f.Advisories) != 1 {
		t.Fatalf("file = %+v", f)
	}
	a := f.Advisories[0]
	if a.ID != "CVE-2023-46219" || len(a.Aliases) != 1 {
		t.Errorf("advisory = %+v", a)
	}
	v, ok := a.Fixes()
	if !ok || v != "8.5.0" {
		t.Errorf("Fixes() = %q, %v", v, ok)
	}
}

// The LAST event in time decides, whatever order the file lists them in. A
// record whose current state depended on file order could be changed by a
// rebase that reordered two appends.
func TestLatestIsTheLastInTimeNotInTheFile(t *testing.T) {
	const y = `schema-version: 1
project: curl.se
advisories:
  - id: CVE-1
    events:
      - timestamp: 2024-05-01T00:00:00Z
        type: fixed
        fixed-version: 8.8.0
      - timestamp: 2024-01-01T00:00:00Z
        type: detection
`
	f, err := ParseAdvisories([]byte(y))
	if err != nil {
		t.Fatalf("ParseAdvisories: %v", err)
	}
	e := f.Advisories[0].Latest()
	if e.Type != EventFixed {
		t.Errorf("Latest().Type = %q, want the May event", e.Type)
	}
	// And the earlier one is still there: the history is the record.
	if len(f.Advisories[0].Events) != 2 || f.Advisories[0].Events[0].Type != EventDetection {
		t.Errorf("events = %+v, want detection then fixed", f.Advisories[0].Events)
	}
}

// A determination that SUPERSEDES a fix is the case a `status:` field could not
// express at all.
func TestAFalsePositiveAfterAFixDecides(t *testing.T) {
	const y = `schema-version: 1
project: curl.se
advisories:
  - id: CVE-1
    events:
      - timestamp: 2024-01-01T00:00:00Z
        type: fixed
        fixed-version: 8.8.0
      - timestamp: 2024-06-01T00:00:00Z
        type: false-positive-determination
        justification: vulnerable_code_not_present
        note: built without the TLS backend the advisory concerns
`
	f, err := ParseAdvisories([]byte(y))
	if err != nil {
		t.Fatalf("ParseAdvisories: %v", err)
	}
	a := f.Advisories[0]
	if _, ok := a.Fixes(); ok {
		t.Error("a superseded fix must not still be reported as the fix")
	}
	if a.FixedBy("9.0.0") {
		t.Error("FixedBy must follow the latest event, not any fix ever recorded")
	}
}

// ⛔ THE REBUILD IS THE POINT. An advisory fixed in 3.5.8_1 is NOT satisfied by
// 3.5.8: they are different artifacts and only one has the fix. This is the
// comparison the whole rebuild counter exists for.
func TestFixedByReadsTheRebuild(t *testing.T) {
	const y = `schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2026-0001
    events:
      - timestamp: 2026-10-11T00:00:00Z
        type: fixed
        fixed-version: 3.5.8_1
`
	f, err := ParseAdvisories([]byte(y))
	if err != nil {
		t.Fatalf("ParseAdvisories: %v", err)
	}
	a := f.Advisories[0]
	for _, c := range []struct {
		version string
		want    bool
	}{
		{"3.5.8", false},   // the unpublished build: same source, no fix
		{"3.5.8_1", true},  // the rebuild that carries it
		{"3.5.8_2", true},  // a later rebuild still carries it
		{"3.5.9", true},    // a later release
		{"3.5.7_9", false}, // a rebuild of an EARLIER version does not
	} {
		if got := a.FixedBy(c.version); got != c.want {
			t.Errorf("FixedBy(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

func TestFixedByIsFalseWhenNothingIsFixed(t *testing.T) {
	const y = `schema-version: 1
project: curl.se
advisories:
  - id: CVE-1
    events:
      - timestamp: 2024-01-01T00:00:00Z
        type: detection
`
	f, err := ParseAdvisories([]byte(y))
	if err != nil {
		t.Fatalf("ParseAdvisories: %v", err)
	}
	if f.Advisories[0].FixedBy("99.0") {
		t.Error("a detected-only advisory is not fixed by any version")
	}
}

func TestParseAdvisoriesRefusals(t *testing.T) {
	const head = "schema-version: 1\nproject: p\nadvisories:\n"
	cases := []struct {
		name, yaml, want string
	}{
		{
			"unknown schema version",
			"schema-version: 2\nproject: p\nadvisories: []\n",
			"schema-version 2",
		},
		{
			"no project",
			"schema-version: 1\nadvisories: []\n",
			"no project named",
		},
		{
			"an empty file",
			"schema-version: 1\nproject: p\nadvisories: []\n",
			"delete the file",
		},
		{
			"an advisory with no id",
			head + "  - events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: detection\n",
			"has no id",
		},
		{
			"the same id twice",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: detection\n" +
				"  - id: CVE-1\n    events:\n      - timestamp: 2024-02-01T00:00:00Z\n        type: detection\n",
			"appears twice",
		},
		{
			"an advisory with no events",
			head + "  - id: CVE-1\n    events: []\n",
			"has no events",
		},
		{
			// OpenVEX makes timestamp a required field, and the reason is
			// that two contradictory statements cannot otherwise be ordered.
			"an event with no timestamp",
			head + "  - id: CVE-1\n    events:\n      - type: detection\n",
			"has no timestamp",
		},
		{
			"an unknown event type",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: probably-fine\n",
			"unknown event type",
		},
		{
			"a fix that names no version",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: fixed\n",
			"must name the fixed-version",
		},
		{
			"a false positive with no justification",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: false-positive-determination\n",
			"must carry a justification",
		},
		{
			// A reason no scanner can read is a reason that will be
			// re-triaged by hand forever.
			"a justification outside OpenVEX's labels",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: false-positive-determination\n        justification: looked-fine-to-me\n",
			"not one of OpenVEX's labels",
		},
		{
			// The Debian/Alpine spelling of a rebuild, which artifact would
			// read as no rebuild at all.
			"a Debian-style revision",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: fixed\n        fixed-version: 3.5.8-1\n",
			"rebuild is spelled 3.5.8_1 here",
		},
		{
			"a fixed-version that is not a version",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: fixed\n        fixed-version: latest\n",
			"does not start with a digit",
		},
		{
			"a padded fixed-version",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: fixed\n        fixed-version: \" 3.5.8\"\n",
			"empty or padded",
		},
		{
			"a non-fix event carrying a fixed-version",
			head + "  - id: CVE-1\n    events:\n      - timestamp: 2024-01-01T00:00:00Z\n        type: detection\n        fixed-version: 3.5.8\n",
			"must not name a fixed-version",
		},
		{
			"not YAML at all",
			"\tnope\n",
			"vuln: advisories:",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseAdvisories([]byte(c.yaml))
			if err == nil {
				t.Fatalf("accepted:\n%s", c.yaml)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// A dash tail that is NOT a revision must still be accepted: this fleet already
// publishes flavoured versions like `8.20-glibc2.27.0`, and refusing every dash
// would refuse them.
func TestAFlavouredVersionIsNotARevision(t *testing.T) {
	const y = `schema-version: 1
project: curl.se
advisories:
  - id: CVE-1
    events:
      - timestamp: 2024-01-01T00:00:00Z
        type: fixed
        fixed-version: 8.20-glibc2.27.0
`
	if _, err := ParseAdvisories([]byte(y)); err != nil {
		t.Errorf("refused a flavoured version: %v", err)
	}
}

// A trailing dash with nothing after it is not a Debian revision, and this
// check does not pretend to be a version validator — it refuses the ONE
// spelling artifact would misread. Pinned so the next person widening the guard
// sees what it was scoped to.
func TestATrailingDashIsNotARevision(t *testing.T) {
	const y = `schema-version: 1
project: curl.se
advisories:
  - id: CVE-1
    events:
      - timestamp: 2024-01-01T00:00:00Z
        type: fixed
        fixed-version: 3.5.8-
`
	if _, err := ParseAdvisories([]byte(y)); err != nil {
		t.Errorf("refused a trailing dash as if it were a revision: %v", err)
	}
}

// Every event type the vocabulary defines parses, so adding one to the
// allowlist without handling its required data cannot pass unnoticed.
func TestEveryEventTypeParses(t *testing.T) {
	bodies := map[string]string{
		EventDetection:          "",
		EventTruePositive:       "",
		EventFixNotPlanned:      "",
		EventPendingUpstreamFix: "",
		EventFixed:              "        fixed-version: 1.2.3\n",
		EventFalsePositive:      "        justification: component_not_present\n",
	}
	if len(bodies) != len(eventTypes) {
		t.Fatalf("%d event types are defined and %d are exercised here", len(eventTypes), len(bodies))
	}
	for typ, extra := range bodies {
		y := "schema-version: 1\nproject: p\nadvisories:\n  - id: CVE-1\n    events:\n" +
			"      - timestamp: 2024-01-01T00:00:00Z\n        type: " + typ + "\n" + extra
		if _, err := ParseAdvisories([]byte(y)); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
}
