package vuln

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-zpkg/artifact"
	"gopkg.in/yaml.v3"
)

// An advisory file is the other half of this package: not which NAME to ask a
// database under (that is Table), but what the answer was and what we decided
// about it.
//
// # The shape is Wolfi's, and the reason is that a state is not enough
//
// Wolfi keeps one `<package>.advisories.yaml` per package, and each advisory in
// it is an ordered list of TIMESTAMPED EVENTS rather than a current state:
// `detection`, then `fixed` carrying the version that fixed it, or
// `false-positive-determination` carrying why. The measured curl file holds 59
// advisories and 71 events — so most have one event and some have three, which
// is precisely the history a single `status:` field would have thrown away.
//
// OpenVEX says the same thing from the other end: `timestamp` is a REQUIRED
// field of a document and the statement's own timestamp is "the time at which
// the information expressed in the Statement was known to be true". A statement
// about a vulnerability with no time on it cannot be superseded, because
// nothing says which of two contradictory statements is the later one.
//
// So: events, each with a timestamp, and the LAST one decides. An advisory with
// no events is refused rather than read as "nothing is known": that is what the
// `detection` event is for, and it is one line.
//
// # Why not in the recipe
//
// Yocto does put the identity in the recipe (`CVE_PRODUCT`) and this fleet
// follows it for identity. The FINDINGS are different: they change without the
// recipe changing, they arrive from a database rather than from upstream, and
// there are many per project. A table naming 1908 projects, edited on every
// triage, is a merge conflict generator; and this repository's own override
// mechanism is a set of `git diff` patches against upstream recipes, of which 3
// of 231 had silently stopped applying when last measured.

// AdvisoryVersion is the only advisory-file schema version ParseAdvisories
// accepts. Refused rather than best-effort, for the reason TableVersion is.
const AdvisoryVersion = 1

// Event types, Wolfi's vocabulary. Each maps onto a VEX status, which is the
// point of keeping the vocabulary rather than inventing one: a record that
// cannot be emitted as VEX is a record only this fleet can read.
const (
	// EventDetection: a database matched this project. Says nothing about
	// whether the match is real.
	EventDetection = "detection"
	// EventTruePositive: it really does affect us.
	EventTruePositive = "true-positive-determination"
	// EventFalsePositive: it does not, and `justification` says why in the
	// vocabulary VEX defines.
	EventFalsePositive = "false-positive-determination"
	// EventFixed: a version of OUR package fixes it. `fixed-version` names it,
	// and that version may be a rebuild (`3.5.8_1`) rather than a new upstream
	// release — which is the whole reason the rebuild counter exists.
	EventFixed = "fixed"
	// EventFixNotPlanned: known, and not going to be fixed. Wolfi reserves
	// this for end-of-life packages and says it "should never be used on
	// supported software".
	EventFixNotPlanned = "fix-not-planned"
	// EventPendingUpstreamFix: cannot be fixed here without upstream work.
	EventPendingUpstreamFix = "pending-upstream-fix"
)

// eventTypes is an allowlist for the same reason knownDBs is: a misspelled
// event type must not read as a different decision, and "not one of the ones I
// listed as bad" is not a check.
var eventTypes = map[string]bool{
	EventDetection:          true,
	EventTruePositive:       true,
	EventFalsePositive:      true,
	EventFixed:              true,
	EventFixNotPlanned:      true,
	EventPendingUpstreamFix: true,
}

// vexJustifications is OpenVEX's fixed label set for a `not_affected` status,
// copied from the spec's Status Justifications table as read on 2026-10-11.
//
// A false-positive determination MUST carry one. OpenVEX allows a free-form
// `impact_statement` instead and then says the machine-readable label is what
// issuers SHOULD use, because the text form "breaks VEX automation and
// interoperability". A record whose reason no scanner can read is a record that
// will be re-triaged by hand forever, so the label is required here and the
// prose goes in `note` alongside it.
var vexJustifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

// Event is one dated thing that happened to one advisory.
type Event struct {
	// Timestamp is required. See the package comment: without it two
	// contradictory events cannot be ordered, so neither can be believed.
	Timestamp time.Time `yaml:"timestamp"`
	Type      string    `yaml:"type"`
	// FixedVersion is required by, and only meaningful for, EventFixed.
	FixedVersion string `yaml:"fixed-version,omitempty"`
	// DetectedVersion is the version OF OURS this event speaks about: for a
	// detection, the version the database was asked about; for any other
	// event, the version the decision was made for.
	//
	// It keeps the name it was given when only detections carried it, rather
	// than gaining a second key meaning the same thing in a file that would
	// then have two ways to say one fact.
	//
	// ⛔ WITHOUT IT A DECISION OUTLIVES ITS SUBJECT. A purl names a version,
	// so the OpenVEX document we publish is a statement ABOUT a version —
	// while a `false-positive-determination` carries none and therefore
	// reads as "not affected, full stop". Determine that for 1.0.0, publish
	// 2.0.0, and the same record re-emits `not_affected` about a version
	// nobody examined. Practitioner guidance on VEX is explicit that a
	// "not affected" goes stale when the component changes and that a gate
	// should re-check rather than treat it as permanent; an unjustified or
	// stale one is worse than issuing nothing, because it stops the reader
	// looking. See go-zpkg/bk#340.
	//
	// ⛔ A RECORD THAT NAMES NO VERSION NOW REACHES NOTHING. The emitter
	// refuses to restate `not_affected` or `fixed` — the two statuses that
	// tell a reader to stop looking — about a version no event here names,
	// and downgrades the statement to `under_investigation` instead. So
	// leaving this empty is not neutral: it is the difference between a
	// determination that travels with the artifact and one that does not. See
	// scopedTo in openvex.go.
	DetectedVersion string `yaml:"detected-version,omitempty"`
	// Justification is required by, and only meaningful for,
	// EventFalsePositive. One of vexJustifications.
	Justification string `yaml:"justification,omitempty"`
	// Note is free prose for a person. Never load-bearing.
	Note string `yaml:"note,omitempty"`
}

// Advisory is one vulnerability as it concerns one project.
type Advisory struct {
	// ID is the identifier this record is filed under: a CVE, a GHSA, a GO-
	// id. Whichever one we were told first.
	ID string `yaml:"id"`
	// Aliases are the same vulnerability's other names. OSV's `aliases` is
	// symmetric and transitive between DATABASES — it is not a place to put a
	// downstream or upstream package's own id.
	Aliases []string `yaml:"aliases,omitempty"`
	Events  []Event  `yaml:"events"`
}

// AdvisoryFile is one project's advisories.
type AdvisoryFile struct {
	SchemaVersion int `yaml:"schema-version"`
	// Project is the pkgx project, spelled as the pantry spells it
	// ("openssl.org", "x.org/protocol/xcb") — not a distro package name. It is
	// in the file as well as in the filename because a project name contains
	// slashes and a filename cannot carry them unambiguously.
	Project    string     `yaml:"project"`
	Advisories []Advisory `yaml:"advisories"`
}

// ParseAdvisories reads one project's advisory file, refusing anything it
// cannot act on. Events are returned in chronological order whatever order the
// file lists them in, because Latest must not depend on file order.
func ParseAdvisories(data []byte) (*AdvisoryFile, error) {
	var f AdvisoryFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("vuln: advisories: %w", err)
	}
	if f.SchemaVersion != AdvisoryVersion {
		return nil, fmt.Errorf("vuln: advisories: schema-version %d, want %d", f.SchemaVersion, AdvisoryVersion)
	}
	if strings.TrimSpace(f.Project) == "" {
		return nil, fmt.Errorf("vuln: advisories: no project named")
	}
	if len(f.Advisories) == 0 {
		return nil, fmt.Errorf("vuln: advisories: %s has none — delete the file rather than keeping an empty one", f.Project)
	}
	seen := map[string]bool{}
	for i := range f.Advisories {
		a := &f.Advisories[i]
		if strings.TrimSpace(a.ID) == "" {
			return nil, fmt.Errorf("vuln: advisories: %s: an advisory has no id", f.Project)
		}
		// A duplicated id is two histories for one vulnerability, and Latest
		// would silently answer from whichever came first.
		if seen[a.ID] {
			return nil, fmt.Errorf("vuln: advisories: %s: %s appears twice", f.Project, a.ID)
		}
		seen[a.ID] = true
		if len(a.Events) == 0 {
			return nil, fmt.Errorf("vuln: advisories: %s: %s has no events — `detection` is one line", f.Project, a.ID)
		}
		for _, e := range a.Events {
			if err := checkEvent(e); err != nil {
				return nil, fmt.Errorf("vuln: advisories: %s: %s: %w", f.Project, a.ID, err)
			}
		}
		sort.SliceStable(a.Events, func(x, y int) bool {
			return a.Events[x].Timestamp.Before(a.Events[y].Timestamp)
		})
	}
	return &f, nil
}

func checkEvent(e Event) error {
	if !eventTypes[e.Type] {
		return fmt.Errorf("unknown event type %q", e.Type)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("the %s event has no timestamp", e.Type)
	}
	switch e.Type {
	case EventFixed:
		if e.FixedVersion == "" {
			return fmt.Errorf("a fixed event must name the fixed-version")
		}
		if err := checkFixedVersion(e.FixedVersion); err != nil {
			return err
		}
	case EventFalsePositive:
		if e.Justification == "" {
			return fmt.Errorf("a false-positive-determination must carry a justification")
		}
		if !vexJustifications[e.Justification] {
			return fmt.Errorf("justification %q is not one of OpenVEX's labels", e.Justification)
		}
	default:
		// The other four carry no required data. `note` is for a person and
		// is never read by anything.
		if e.FixedVersion != "" {
			return fmt.Errorf("a %s event must not name a fixed-version", e.Type)
		}
	}
	return nil
}

// checkFixedVersion refuses a version string this fleet would misread.
//
// The one that matters is a DASH-numeric tail. `3.5.8-1` is how Debian and
// Alpine spell "the first rebuild of 3.5.8", and it is the spelling a person
// coming from either will write. Here the rebuild separator is `_`
// (artifact.splitRebuild splits on the last one), so `3.5.8-1` parses as a
// version with no rebuild at all — and the advisory would then claim that
// plain `3.5.8` carries the fix, which is the one unpublished build.
func checkFixedVersion(v string) error {
	if strings.TrimSpace(v) != v || v == "" {
		return fmt.Errorf("fixed-version %q is empty or padded", v)
	}
	if v[0] < '0' || v[0] > '9' {
		return fmt.Errorf("fixed-version %q does not start with a digit", v)
	}
	if i := strings.LastIndex(v, "-"); i >= 0 && allDigits(v[i+1:]) {
		return fmt.Errorf("fixed-version %q looks like a Debian revision — a rebuild is spelled %s_%s here",
			v, v[:i], v[i+1:])
	}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Latest returns the event that decides this advisory's current state: the last
// one in time. Events are sorted by ParseAdvisories, so this does not depend on
// how the file was written.
//
// It is only reachable on a parsed advisory, which is guaranteed to have at
// least one event.
func (a Advisory) Latest() Event {
	return a.Events[len(a.Events)-1]
}

// Fixes reports the version that fixed this advisory, if one has.
func (a Advisory) Fixes() (string, bool) {
	e := a.Latest()
	if e.Type != EventFixed {
		return "", false
	}
	return e.FixedVersion, true
}

// FixedBy reports whether a given version of this project carries the fix.
//
// It asks ARTIFACT, through the constraint language the resolver already uses,
// rather than comparing the strings here. The comparison that matters is the
// REBUILD: `3.5.8` must not satisfy an advisory fixed in `3.5.8_1`, because
// those are different artifacts and only one of them has the fix. artifact.Ver
// carries the rebuild and its comparator reads it; a second implementation
// here would be a second place for that rule to be wrong.
func (a Advisory) FixedBy(version string) bool {
	fixed, ok := a.Fixes()
	if !ok {
		return false
	}
	return artifact.ParseVer(version).Satisfies(">=" + fixed)
}
