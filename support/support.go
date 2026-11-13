// Package support answers a question a vulnerability database cannot: is the
// version we publish on an upstream release line that is still supported?
//
// ⛔ END-OF-LIFE IS NOT A CVE, AND THAT IS THE WHOLE REASON THIS EXISTS. OSV
// answers "what is known to be wrong with this version". A line that upstream
// has stopped supporting has, by definition, nothing known about it yet — and
// never will, because nobody is looking and no fix is coming. `bk vulnfetch`
// and the daily sweep are structurally blind to it: they can return a clean
// zero for a package whose upstream stopped issuing fixes years ago.
//
// Measured 2026-10-29 against the registry: it publishes openssl 3.2, 3.3,
// 3.4, 3.5, 3.6 and 4.0. Of those, 3.2 and 3.3 were already out of support,
// 3.4 went out on 2026-10-22 — a week earlier — and 3.6 goes out on
// 2026-11-01. A `^3` constraint takes the newest 3.x, which is 3.6: so the
// default resolution was three days from an unsupported line while 3.5, the
// LTS supported to 2030, sat in the registry unused. Nothing in the CVE lane
// could say so.
//
// # The source, and the field that lies
//
// endoflife.date's v1 API (schema 1.2.1) returns, per product, a list of
// release cycles. The fields that matter are `isEol` and `eolFrom`.
//
// ⛔ `isMaintained` IS NOT THE ANSWER, and reading it would invert the
// verdict on the worst case. From the live response for openssl:
//
//	{"name":"1.1.1","isEol":true,"eolFrom":"2023-09-11","isMaintained":true}
//	{"name":"3.0",  "isEol":true,"eolFrom":"2026-09-07","isMaintained":true}
//
// Both lines have been out of support for a while, and both say
// `isMaintained: true` — it reflects the PAID extended support openssl sells
// (the product's own labels call it "Premium support"). A check reading that
// field would report 1.1.1 as healthy, which is exactly the artifact this fleet
// has 32 of.
//
// ⛔ AN ABSENT DATE IS NOT A DISTANT ONE. A cycle may carry `eolFrom: null`,
// which means nobody has published a date — not that the line is supported
// forever. It is reported as UNKNOWN and never as healthy, because the
// alternative is a silence that reads like an answer.
//
// # How the others do it
//
// Yocto has no equivalent: its CVE handling is identity plus a database, which
// is the half this complements. Wolfi gets closest with the
// `fix-not-planned` event, which its own documentation reserves for
// end-of-life packages and says "should never be used on supported software" —
// but that is a decision recorded per advisory, after somebody noticed. This
// asks the question before there is an advisory to decide about.
package support

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Release is one upstream release line, as endoflife.date reports it.
type Release struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	IsLTS   bool   `json:"isLts"`
	IsEOL   bool   `json:"isEol"`
	EOLFrom string `json:"eolFrom"`
	// ⛔ Deliberately NOT decoded: `isMaintained`. It is true for lines that
	// have been end-of-life for years, because it reflects paid extended
	// support. Leaving it out of the type means no later reader can reach for
	// it by accident.
	Latest struct {
		Name string `json:"name"`
	} `json:"latest"`
}

// Product is one product's release lines.
type Product struct {
	Name     string
	Label    string
	Policy   string
	Releases []Release
}

// ParseProduct reads an endoflife.date v1 product response.
func ParseProduct(data []byte) (*Product, error) {
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Result        struct {
			Name  string `json:"name"`
			Label string `json:"label"`
			Links struct {
				ReleasePolicy string `json:"releasePolicy"`
			} `json:"links"`
			Releases []Release `json:"releases"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("endoflife.date response: %w", err)
	}
	// ⛔ A RESPONSE THAT PARSED AND SAID NOTHING IS A FAILURE. A 200 carrying
	// an empty object decodes without error, and a product with no release
	// lines would then report every version as UNKNOWN — a wall of shrugs
	// that reads like a completed check.
	if len(doc.Result.Releases) == 0 {
		return nil, fmt.Errorf("endoflife.date returned no release line at all (schema %q): a parse that says nothing is not an answer", doc.SchemaVersion)
	}
	return &Product{
		Name:     doc.Result.Name,
		Label:    doc.Result.Label,
		Policy:   doc.Result.Links.ReleasePolicy,
		Releases: doc.Result.Releases,
	}, nil
}

// CycleFor is the release line a version belongs to: the LONGEST cycle name
// that prefixes it on a component boundary.
//
// ⛔ THE BOUNDARY IS THE POINT. A plain string prefix puts `3.60` in line
// `3.6`, and the longest-match rule is what keeps openssl's `1.1.1w` out of
// line `1.1.0`'s neighbour `1.1`: it belongs to `1.1.1`. The character after
// the match may be a separator or a patch letter — openssl spells its patch
// releases `1.1.1w` — but it may never be another digit, which would mean a
// different line entirely.
func CycleFor(version string, releases []Release) (Release, bool) {
	best, found := Release{}, false
	for _, r := range releases {
		if r.Name == "" || !strings.HasPrefix(version, r.Name) {
			continue
		}
		if rest := version[len(r.Name):]; rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			continue // 3.60 is not in line 3.6
		}
		if !found || len(r.Name) > len(best.Name) {
			best, found = r, true
		}
	}
	return best, found
}

// State is what a version's line is worth.
type State int

const (
	// StateUnknown: no line claims this version, or the line publishes no
	// date. Never reported as healthy.
	StateUnknown State = iota
	// StateSupported: the line is current and no end date is near.
	StateSupported
	// StateExpiring: the line has an end date inside the window asked for.
	StateExpiring
	// StateEOL: the line is past its end date.
	StateEOL
)

func (s State) String() string {
	switch s {
	case StateSupported:
		return "supported"
	case StateExpiring:
		return "expiring"
	case StateEOL:
		return "end-of-life"
	default:
		return "unknown"
	}
}

// Verdict is one version judged against its release line.
type Verdict struct {
	Version string
	Cycle   Release
	State   State
	// EOL is the line's end date, zero when it publishes none.
	EOL time.Time
	// Why says, in one line, what was read and what it means.
	Why string
}

// Judge places a version on its line and says what that line is worth as of
// `now`, treating an end date within `within` as expiring.
//
// ⛔ IT READS `isEol` AND THE DATE, NOT ONE OR THE OTHER. The flag is how
// upstream states a decision and the date is when it takes effect, and they
// disagree for a day or two around a transition — openssl 3.6 carried
// `isEol:false` with `eolFrom:2026-11-01` three days before that date. Either
// one alone answers late.
func Judge(version string, p *Product, now time.Time, within time.Duration) Verdict {
	cycle, ok := CycleFor(version, p.Releases)
	if !ok {
		return Verdict{
			Version: version,
			State:   StateUnknown,
			Why:     fmt.Sprintf("no %s release line claims %s", p.Name, version),
		}
	}
	v := Verdict{Version: version, Cycle: cycle}

	eol, hasDate := parseDate(cycle.EOLFrom)
	v.EOL = eol
	switch {
	case cycle.IsEOL || (hasDate && !eol.After(now)):
		v.State = StateEOL
		v.Why = fmt.Sprintf("line %s ended %s", cycle.Name, cycle.EOLFrom)
	case !hasDate:
		// ⛔ NOT "supported": nobody published a date, which is a different
		// thing from a date far away.
		v.State = StateUnknown
		v.Why = fmt.Sprintf("line %s publishes no end date", cycle.Name)
	case eol.Sub(now) <= within:
		v.State = StateExpiring
		v.Why = fmt.Sprintf("line %s ends %s", cycle.Name, cycle.EOLFrom)
	default:
		v.State = StateSupported
		v.Why = fmt.Sprintf("line %s supported until %s", cycle.Name, cycle.EOLFrom)
	}
	if cycle.IsLTS {
		v.Why += " (LTS)"
	}
	return v
}

// BestLine is the line a reader should move to: the longest-supported one,
// preferring an LTS when two end on the same day.
//
// It exists so a finding can name a destination. "openssl 3.6 ends on Sunday"
// is a problem; "and 3.5 is supported to 2030" is the next step, and leaving
// the reader to find it is how a report becomes a chore.
func BestLine(p *Product, now time.Time) (Release, bool) {
	best, found := Release{}, false
	var bestEOL time.Time
	for _, r := range p.Releases {
		if r.IsEOL {
			continue
		}
		eol, ok := parseDate(r.EOLFrom)
		if !ok || !eol.After(now) {
			continue
		}
		switch {
		case !found, eol.After(bestEOL), eol.Equal(bestEOL) && r.IsLTS && !best.IsLTS:
			best, bestEOL, found = r, eol, true
		}
	}
	return best, found
}

func parseDate(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
