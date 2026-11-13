package support

import (
	"strings"
	"testing"
	"time"
)

// The real openssl response, trimmed to the lines that matter and kept
// VERBATIM in shape — including `isMaintained: true` on two lines that have
// been end-of-life for years, which is the field this package refuses to read.
const opensslJSON = `{
 "schema_version":"1.2.1",
 "result":{
  "name":"openssl","label":"OpenSSL",
  "links":{"releasePolicy":"https://openssl-library.org/policies/releasestrat/index.html"},
  "releases":[
   {"name":"4.1","label":"4.1","isLts":false,"isEol":false,"eolFrom":"2027-11-30","isMaintained":true,"latest":{"name":"4.1.0"}},
   {"name":"4.0","label":"4.0","isLts":false,"isEol":false,"eolFrom":"2027-05-14","isMaintained":true,"latest":{"name":"4.0.3"}},
   {"name":"3.6","label":"3.6","isLts":false,"isEol":false,"eolFrom":"2026-11-01","isMaintained":true,"latest":{"name":"3.6.5"}},
   {"name":"3.5","label":"3.5 (LTS)","isLts":true,"isEol":false,"eolFrom":"2030-04-08","isMaintained":true,"latest":{"name":"3.5.9"}},
   {"name":"3.4","label":"3.4","isLts":false,"isEol":true,"eolFrom":"2026-10-22","isMaintained":false,"latest":{"name":"3.4.8"}},
   {"name":"3.0","label":"3.0 (LTS)","isLts":true,"isEol":true,"eolFrom":"2026-09-07","isMaintained":true,"latest":{"name":"3.0.22"}},
   {"name":"1.1.1","label":"1.1.1 (LTS)","isLts":true,"isEol":true,"eolFrom":"2023-09-11","isMaintained":true,"latest":{"name":"1.1.1w"}},
   {"name":"1.1.0","label":"1.1.0","isLts":false,"isEol":true,"eolFrom":"2019-09-11","isMaintained":false,"latest":{"name":"1.1.0l"}}
  ]}}`

func openssl(t *testing.T) *Product {
	t.Helper()
	p, err := ParseProduct([]byte(opensslJSON))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseProductReadsTheV1Shape(t *testing.T) {
	p := openssl(t)
	if p.Name != "openssl" || p.Label != "OpenSSL" {
		t.Errorf("got %q/%q", p.Name, p.Label)
	}
	if len(p.Releases) != 8 {
		t.Fatalf("want 8 release lines, got %d", len(p.Releases))
	}
	if !strings.Contains(p.Policy, "releasestrat") {
		t.Errorf("the release policy link was dropped: %q", p.Policy)
	}
}

// ⛔ A 200 THAT SAYS NOTHING IS A FAILURE, not a product with no lines: every
// version would then report UNKNOWN, a wall of shrugs that reads like a
// completed check.
func TestAProductWithNoReleaseLinesIsAnError(t *testing.T) {
	for _, body := range []string{`{"result":{"name":"x","releases":[]}}`, `{}`} {
		if _, err := ParseProduct([]byte(body)); err == nil {
			t.Errorf("%s: want an error", body)
		}
	}
	if _, err := ParseProduct([]byte("not json")); err == nil {
		t.Error("want an error for a body that is not JSON")
	}
}

// ⛔ THE FIELD THAT WOULD HAVE INVERTED THE VERDICT. openssl 1.1.1 and 3.0 are
// both end-of-life and both carry `isMaintained: true`, because openssl sells
// extended support for them. This fleet publishes 32 artifacts linking 1.1.1; a
// check reading that field would have called every one of them healthy.
func TestAnEOLLineIsNotRescuedByIsMaintained(t *testing.T) {
	p := openssl(t)
	now := day("2026-10-29")
	for _, version := range []string{"1.1.1w", "1.1.1", "3.0.22"} {
		got := Judge(version, p, now, 30*24*time.Hour)
		if got.State != StateEOL {
			t.Errorf("%s: state %v, want end-of-life (%s)", version, got.State, got.Why)
		}
	}
}

// The three verdicts the registry's own openssl versions earn today.
func TestItJudgesTheVersionsTheRegistryActuallyPublishes(t *testing.T) {
	p := openssl(t)
	now := day("2026-10-29")
	const within = 30 * 24 * time.Hour

	for _, c := range []struct {
		version string
		want    State
		cycle   string
	}{
		{"3.4.7", StateEOL, "3.4"},       // ended a week ago
		{"3.6.4", StateExpiring, "3.6"},  // ends 2026-11-01, three days out
		{"3.5.8", StateSupported, "3.5"}, // the LTS, 2030
		{"4.0.2", StateSupported, "4.0"},
	} {
		got := Judge(c.version, p, now, within)
		if got.State != c.want {
			t.Errorf("%s: state %v, want %v (%s)", c.version, got.State, c.want, got.Why)
		}
		if got.Cycle.Name != c.cycle {
			t.Errorf("%s: cycle %q, want %q", c.version, got.Cycle.Name, c.cycle)
		}
	}
}

// ⛔ `isEol` AND THE DATE, NOT ONE OR THE OTHER. openssl 3.6 carried
// `isEol:false` with `eolFrom:2026-11-01` days before that date; either signal
// alone answers late.
func TestADateThatHasPassedIsEOLEvenWhenTheFlagHasNotCaughtUp(t *testing.T) {
	p := openssl(t)
	// 3.6 still says isEol:false in this fixture.
	if got := Judge("3.6.4", p, day("2026-11-02"), 0); got.State != StateEOL {
		t.Errorf("state %v, want end-of-life once the date has passed (%s)", got.State, got.Why)
	}
	// And the flag alone is enough before any date arithmetic: 3.4's own
	// isEol is true.
	if got := Judge("3.4.7", p, day("2026-10-01"), 0); got.State != StateEOL {
		t.Errorf("state %v, want end-of-life from the flag (%s)", got.State, got.Why)
	}
}

// ⛔ AN ABSENT DATE IS NOT A DISTANT ONE.
func TestALineWithNoPublishedDateIsUnknownNotSupported(t *testing.T) {
	p, err := ParseProduct([]byte(`{"result":{"name":"x","releases":[
	 {"name":"2","isEol":false,"eolFrom":null},
	 {"name":"1","isEol":true,"eolFrom":"2020-01-01"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := Judge("2.3.4", p, day("2026-10-29"), 0)
	if got.State != StateUnknown {
		t.Errorf("state %v, want unknown (%s)", got.State, got.Why)
	}
	if !strings.Contains(got.Why, "no end date") {
		t.Errorf("the reason was not stated: %s", got.Why)
	}
}

// ⛔ THE BOUNDARY, which a plain string prefix gets wrong.
func TestCycleForMatchesOnAComponentBoundaryAndTakesTheLongest(t *testing.T) {
	p := openssl(t)
	for _, c := range []struct {
		version, cycle string
		ok             bool
	}{
		{"3.6.4", "3.6", true},
		{"3.6", "3.6", true},
		{"1.1.1w", "1.1.1", true}, // the patch LETTER is not a new line…
		{"1.1.0l", "1.1.0", true},
		{"3.60.1", "", false}, // …but another DIGIT is a different line
		{"3.55", "", false},
		{"2.9.9", "", false},
	} {
		got, ok := CycleFor(c.version, p.Releases)
		if ok != c.ok || got.Name != c.cycle {
			t.Errorf("%s -> %q/%v, want %q/%v", c.version, got.Name, ok, c.cycle, c.ok)
		}
	}
	if got := Judge("3.60.1", p, day("2026-10-29"), 0); got.State != StateUnknown {
		t.Errorf("an unclaimed version: state %v, want unknown (%s)", got.State, got.Why)
	}
}

// A finding that names no destination is a chore.
//
// ⛔ THE ANSWER IS 3.5, NOT THE NEWEST LINE, and this test asserted 4.1 until
// the code disagreed and turned out to be right. 4.1 is newer — released
// 2026-10-23 — but it is supported only to 2027-11-30, while 3.5 LTS runs to
// 2030-04-08. "Where to go" means the line that will still be getting fixes
// longest, which is what LTS is for; recommending the newest would move a
// consumer to a shorter runway and need doing again in a year.
func TestBestLineNamesWhereToGo(t *testing.T) {
	p := openssl(t)
	got, ok := BestLine(p, day("2026-10-29"))
	if !ok || got.Name != "3.5" {
		t.Fatalf("best line %q/%v, want 3.5 (LTS to 2030, longer than 4.1's 2027)", got.Name, ok)
	}
	if !got.IsLTS {
		t.Errorf("3.5 is the LTS and the verdict should carry that")
	}

	// ⛔ A LINE WITH NO USABLE DATE IS NOT A DESTINATION. `isEol:false` with
	// no `eolFrom`, or a date already past, says nobody has committed to
	// supporting it — sending somebody there would be inventing a promise.
	vague, err := ParseProduct([]byte(`{"result":{"name":"x","releases":[
	 {"name":"3","isEol":false,"eolFrom":null},
	 {"name":"2","isEol":false,"eolFrom":"2001-01-01"},
	 {"name":"1","isEol":false,"eolFrom":"2031-01-01"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := BestLine(vague, day("2026-10-29")); !ok || got.Name != "1" {
		t.Errorf("best line %q/%v, want 1 — a dateless or past line is no destination", got.Name, ok)
	}

	tie, err := ParseProduct([]byte(`{"result":{"name":"x","releases":[
	 {"name":"9","isEol":false,"eolFrom":"2030-01-01","isLts":false},
	 {"name":"8","isEol":false,"eolFrom":"2030-01-01","isLts":true}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := BestLine(tie, day("2026-10-29")); !ok || got.Name != "8" {
		t.Errorf("on a tie the LTS must win, got %q", got.Name)
	}

	// Everything already over: there is no destination, and saying so beats
	// naming the least-dead line.
	dead, err := ParseProduct([]byte(`{"result":{"name":"x","releases":[
	 {"name":"1","isEol":true,"eolFrom":"2020-01-01"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := BestLine(dead, day("2026-10-29")); ok {
		t.Error("want no destination when every line has ended")
	}
}

func TestStateNamesItself(t *testing.T) {
	for s, want := range map[State]string{
		StateSupported: "supported",
		StateExpiring:  "expiring",
		StateEOL:       "end-of-life",
		StateUnknown:   "unknown",
		State(99):      "unknown",
	} {
		if got := s.String(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// An LTS line says so in the reason, because "supported until 2030" and
// "supported until 2030 (LTS)" are different invitations.
func TestAnLTSLineSaysSo(t *testing.T) {
	got := Judge("3.5.8", openssl(t), day("2026-10-29"), 0)
	if !strings.Contains(got.Why, "(LTS)") {
		t.Errorf("the LTS was not stated: %s", got.Why)
	}
}

func TestAMalformedDateIsNotADate(t *testing.T) {
	if _, ok := parseDate("not-a-date"); ok {
		t.Error("want false")
	}
	if _, ok := parseDate(""); ok {
		t.Error("want false for an empty date")
	}
}
