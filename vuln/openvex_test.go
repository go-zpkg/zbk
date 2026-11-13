package vuln

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, y string) *AdvisoryFile {
	t.Helper()
	f, err := ParseAdvisories([]byte(y))
	if err != nil {
		t.Fatalf("ParseAdvisories: %v", err)
	}
	return f
}

func opts(subjects ...Subject) VEXOptions {
	return VEXOptions{
		ID:        "https://go-zpkg.github.io/vex/1",
		Author:    "https://github.com/go-zpkg",
		Timestamp: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC),
		Version:   1,
		Subjects:  subjects,
	}
}

const product = "pkg:oci/openssl@sha256:abc?repository_url=ghcr.io/go-zpkg/openssl.org&tag=3.5.8_1--linux-x86-64"

// productVersion is the version `product` is an artifact of. It is a constant
// rather than a literal in each fixture because the scoping rule compares it
// against what a record names, and two spellings of "the version under test"
// would make a failure look like a disagreement about the rule.
const productVersion = "3.5.8_1"

// prod is the one-product case, named only so the tests that do not care about
// identifiers or hashes stay about what they test.
func prod(id string) []Product { return []Product{{ID: id, Version: productVersion}} }

// The document carries the five fields the spec marks required, and the
// context names the VERSION — the spec says an omitted version defaults to
// v0.0.1, so leaving it off is not a shorthand.
func TestVEXDocumentHasTheRequiredFields(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2026-0001
    aliases: [GHSA-xxxx]
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: fixed
        fixed-version: 3.5.8_1
`)
	b, err := EncodeVEX(opts(Subject{File: f, Products: prod(product)}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("the document is not JSON: %v", err)
	}
	for _, k := range []string{"@context", "@id", "author", "timestamp", "version", "statements"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("required field %q is absent", k)
		}
	}
	if doc["@context"] != VEXContext || !strings.Contains(VEXContext, "v0.2.0") {
		t.Errorf("@context = %v, want a versioned context", doc["@context"])
	}
	sts, _ := doc["statements"].([]any)
	if len(sts) != 1 {
		t.Fatalf("statements = %v", sts)
	}
	st := sts[0].(map[string]any)
	if st["status"] != VEXFixed {
		t.Errorf("status = %v, want fixed", st["status"])
	}
	// ⛔ The STATEMENT's timestamp is when the event was known to be true, not
	// when the document was written. Dating every finding to the last publish
	// would make the whole history look like it was discovered at once.
	if st["timestamp"] != "2026-10-10T12:00:00Z" {
		t.Errorf("statement timestamp = %v, want the event's", st["timestamp"])
	}
	if doc["timestamp"] != "2026-10-11T09:00:00Z" {
		t.Errorf("document timestamp = %v, want the issue time", doc["timestamp"])
	}
	v := st["vulnerability"].(map[string]any)
	if v["name"] != "CVE-2026-0001" {
		t.Errorf("vulnerability = %v", v)
	}
	if al, _ := v["aliases"].([]any); len(al) != 1 {
		t.Errorf("aliases = %v, want the GHSA carried through", v["aliases"])
	}
	prods := st["products"].([]any)
	if len(prods) != 1 || prods[0].(map[string]any)["@id"] != product {
		t.Errorf("products = %v", prods)
	}
}

// The hash and the purl are what make a statement checkable rather than
// plausible — and the hash key's spelling is a trap: OpenVEX's table says
// `sha-256` while sha1 in the same table is `sha1`. `hashes` is a free-form
// map, so the wrong key is a digest nobody reads and no error.
func TestAProductCarriesItsPurlAndItsDigest(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2026-0001
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: fixed
        fixed-version: 3.5.8_1
`)
	b, err := EncodeVEX(opts(Subject{File: f, Products: []Product{{
		ID:      "pkg:pkgx/openssl.org@3.5.8_1",
		Version: productVersion,
		PURL:    "pkg:pkgx/openssl.org@3.5.8_1",
		SHA256:  "deadbeef",
	}}}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	var doc struct {
		Statements []struct {
			Products []struct {
				ID          string            `json:"@id"`
				Identifiers map[string]string `json:"identifiers"`
				Hashes      map[string]string `json:"hashes"`
			} `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Statements[0].Products[0]
	if p.ID != "pkg:pkgx/openssl.org@3.5.8_1" {
		t.Errorf("@id = %q", p.ID)
	}
	if p.Identifiers["purl"] != "pkg:pkgx/openssl.org@3.5.8_1" {
		t.Errorf("identifiers = %v, want a purl", p.Identifiers)
	}
	if p.Hashes["sha-256"] != "deadbeef" {
		t.Errorf("hashes = %v, want the digest under %q", p.Hashes, "sha-256")
	}
	// And under NO other spelling, so a consumer cannot find it by accident.
	if _, ok := p.Hashes["sha256"]; ok {
		t.Errorf("the digest is also under %q: %v", "sha256", p.Hashes)
	}
}

// Both maps are omitted when there is nothing to put in them — a product
// carrying `"hashes": {}` claims to be hashed and is not.
func TestAProductWithoutIdentifiersOmitsTheMaps(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: p
advisories:
  - id: CVE-1
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
`)
	b, err := EncodeVEX(opts(Subject{File: f, Products: prod(product)}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "identifiers") || strings.Contains(string(b), "hashes") {
		t.Errorf("empty maps were emitted:\n%s", b)
	}
}

// A product with no @id is refused: the spec allows it, this does not, because
// a statement whose subject cannot be named is one nobody can look up.
func TestAProductWithoutAnIDIsRefused(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: p
advisories:
  - id: CVE-1
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
`)
	_, err := EncodeVEX(opts(Subject{File: f, Products: []Product{{SHA256: "deadbeef"}}}))
	if err == nil || !strings.Contains(err.Error(), "no @id") {
		t.Errorf("err = %v", err)
	}
}

// not_affected MUST carry a justification label. A document without one is
// rejected by consumers, and the prose form "breaks VEX automation".
func TestNotAffectedCarriesItsJustification(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2026-0002
    events:
      - timestamp: 2026-10-10T11:00:00Z
        type: detection
        detected-version: 3.5.8_1
      - timestamp: 2026-10-10T12:00:00Z
        type: false-positive-determination
        justification: vulnerable_code_not_present
        note: built without the affected backend
`)
	b, err := EncodeVEX(opts(Subject{File: f, Products: prod(product)}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	var doc struct {
		Statements []struct {
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Statements[0]
	if s.Status != VEXNotAffected || s.Justification != "vulnerable_code_not_present" {
		t.Errorf("statement = %+v", s)
	}
	// The prose rides ALONGSIDE the label, never instead of it.
	if s.ImpactStatement != "built without the affected backend" {
		t.Errorf("impact_statement = %q", s.ImpactStatement)
	}
}

// Each event type that becomes `affected` means something different to a
// reader, so each carries its own action statement.
func TestAffectedStatusesCarryDistinctActions(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range []struct{ typ, body string }{
		{EventTruePositive, ""},
		{EventFixNotPlanned, ""},
		{EventPendingUpstreamFix, ""},
	} {
		y := "schema-version: 1\nproject: p\nadvisories:\n  - id: CVE-1\n    events:\n" +
			"      - timestamp: 2026-10-10T12:00:00Z\n        type: " + c.typ + "\n" + c.body
		b, err := EncodeVEX(opts(Subject{File: mustParse(t, y), Products: prod(product)}))
		if err != nil {
			t.Fatalf("%s: %v", c.typ, err)
		}
		var doc struct {
			Statements []struct {
				Status          string `json:"status"`
				ActionStatement string `json:"action_statement"`
			} `json:"statements"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		s := doc.Statements[0]
		if s.Status != VEXAffected {
			t.Errorf("%s: status = %q, want affected", c.typ, s.Status)
		}
		if s.ActionStatement == "" {
			t.Errorf("%s: an affected statement with no action", c.typ)
		}
		if seen[s.ActionStatement] {
			t.Errorf("%s: shares its action statement with another event type", c.typ)
		}
		seen[s.ActionStatement] = true
	}
}

// A detection is a NAME match, not a finding. This fleet measured what a bare
// CPE match is worth — 27 records for openssl, four from 2009 — so emitting
// detections as `affected` would publish false alarms under our signature.
func TestDetectionIsUnderInvestigation(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2009-0590
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: detection
        note: matched by a bare CPE query, not yet triaged
`)
	b, err := EncodeVEX(opts(Subject{File: f, Products: prod(product)}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	var doc struct {
		Statements []struct {
			Status      string `json:"status"`
			StatusNotes string `json:"status_notes"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Statements[0].Status != VEXUnderInvestigation {
		t.Errorf("status = %q, want under_investigation", doc.Statements[0].Status)
	}
	if doc.Statements[0].StatusNotes == "" {
		t.Error("the note is the only thing saying why it is undecided")
	}
}

// Every event type the parser accepts must map to a status. An unmapped one
// would silently drop its statement from the document.
func TestEveryEventTypeMapsToAStatus(t *testing.T) {
	if len(statusFor) != len(eventTypes) {
		t.Fatalf("%d event types, %d mapped to a VEX status", len(eventTypes), len(statusFor))
	}
	for typ := range eventTypes {
		if statusFor[typ] == "" {
			t.Errorf("%q maps to no status", typ)
		}
	}
	// And every status that requires an action statement has one.
	for typ, status := range statusFor {
		if status == VEXAffected && actionFor[typ] == "" {
			t.Errorf("%q is affected and has no action statement", typ)
		}
	}
}

// The same records produce the same bytes, whatever order they are handed in.
// A document that differed run to run could not be attached to an artifact and
// compared with the one already there.
func TestEncodingIsDeterministic(t *testing.T) {
	a := mustParse(t, `schema-version: 1
project: a.org
advisories:
  - id: CVE-2
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
  - id: CVE-1
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
`)
	b := mustParse(t, `schema-version: 1
project: b.org
advisories:
  - id: CVE-3
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
`)
	one, err := EncodeVEX(opts(
		Subject{File: b, Products: prod("pkg:oci/b@sha256:1")},
		Subject{File: a, Products: prod("pkg:oci/a@sha256:2")},
	))
	if err != nil {
		t.Fatal(err)
	}
	two, err := EncodeVEX(opts(
		Subject{File: a, Products: prod("pkg:oci/a@sha256:2")},
		Subject{File: b, Products: prod("pkg:oci/b@sha256:1")},
	))
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Errorf("the order the subjects were handed in changed the document:\n%s\n---\n%s", one, two)
	}
	// Ordered by project, then by vulnerability id within it.
	i1, i2, i3 := strings.Index(string(one), "CVE-1"), strings.Index(string(one), "CVE-2"), strings.Index(string(one), "CVE-3")
	if !(i1 < i2 && i2 < i3) {
		t.Errorf("statements are not ordered by project then id: %d %d %d", i1, i2, i3)
	}
}

// Sorting must not reorder the CALLER's slices: a function that sorts its
// input in place changes a value the caller still holds.
func TestEncodingDoesNotReorderTheCallersData(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: a.org
advisories:
  - id: CVE-2
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
  - id: CVE-1
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
`)
	subjects := []Subject{{File: f, Products: prod("pkg:oci/a@sha256:2")}}
	if _, err := EncodeVEX(opts(subjects...)); err != nil {
		t.Fatal(err)
	}
	if f.Advisories[0].ID != "CVE-2" {
		t.Errorf("the advisory file was reordered under the caller: %s", f.Advisories[0].ID)
	}
}

func TestEncodeVEXRefusals(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: p
advisories:
  - id: CVE-1
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
`)
	good := Subject{File: f, Products: prod(product)}
	cases := []struct {
		name string
		mut  func(*VEXOptions)
		want string
	}{
		{"no @id", func(o *VEXOptions) { o.ID = " " }, "no @id"},
		{"no author", func(o *VEXOptions) { o.Author = "" }, "no author"},
		{"no timestamp", func(o *VEXOptions) { o.Timestamp = time.Time{} }, "no timestamp"},
		{"version zero", func(o *VEXOptions) { o.Version = 0 }, "it starts at 1"},
		{"no subjects", func(o *VEXOptions) { o.Subjects = nil }, "no subjects"},
		{"a subject with no file", func(o *VEXOptions) { o.Subjects = []Subject{{Products: prod(product)}} }, "no advisory file"},
		{"a subject with no product", func(o *VEXOptions) { o.Subjects = []Subject{{File: f}} }, "names no product"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := opts(good)
			c.mut(&o)
			_, err := EncodeVEX(o)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// An event type the parser allows but this file does not map is refused loudly
// rather than dropped. Reached by hand, because the parser and the mapping are
// kept level by TestEveryEventTypeMapsToAStatus — which is exactly why the
// error arm needs its own way in.
func TestAnUnmappedEventTypeIsRefused(t *testing.T) {
	a := Advisory{
		ID:     "CVE-1",
		Events: []Event{{Timestamp: time.Now(), Type: "invented-later"}},
	}
	if _, err := statementsFor(a, prod(product)); err == nil || !strings.Contains(err.Error(), "maps to no VEX status") {
		t.Errorf("err = %v", err)
	}
}

// And the refusal reaches the caller of EncodeVEX, naming the project and the
// advisory. AdvisoryFile is an exported struct, so a caller really can build
// one without going through the parser — which is the only way an unmapped
// event type gets this far.
func TestAnUnmappedEventTypeFailsTheWholeDocument(t *testing.T) {
	f := &AdvisoryFile{
		SchemaVersion: AdvisoryVersion,
		Project:       "openssl.org",
		Advisories: []Advisory{{
			ID:     "CVE-1",
			Events: []Event{{Timestamp: time.Now(), Type: "invented-later"}},
		}},
	}
	_, err := EncodeVEX(opts(Subject{File: f, Products: prod(product)}))
	if err == nil {
		t.Fatal("emitted a document with a statement it could not write")
	}
	for _, want := range []string{"openssl.org", "CVE-1", "maps to no VEX status"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// The optional document fields appear when set and are absent when not — a
// consumer reading `"role": ""` sees a document asserting an empty role.
func TestOptionalDocumentFieldsAreOmittedWhenUnset(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: p
advisories:
  - id: CVE-1
    events: [{timestamp: 2026-10-10T12:00:00Z, type: detection}]
`)
	o := opts(Subject{File: f, Products: prod(product)})
	bare, err := EncodeVEX(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bare), "\"role\"") || strings.Contains(string(bare), "\"tooling\"") {
		t.Errorf("unset optional fields were emitted:\n%s", bare)
	}
	o.Role = "Document Creator"
	o.Tooling = "bk"
	full, err := EncodeVEX(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), "Document Creator") || !strings.Contains(string(full), "\"tooling\": \"bk\"") {
		t.Errorf("set optional fields were dropped:\n%s", full)
	}
}

// --- #340: a statement names a version, so a decision about one version is
// not restated about another ---

// vexStatements decodes the fields the scoping tests care about, in order.
func vexStatements(t *testing.T, b []byte) []struct {
	Status          string `json:"status"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement"`
	StatusNotes     string `json:"status_notes"`
	Products        []struct {
		ID string `json:"@id"`
	} `json:"products"`
} {
	t.Helper()
	var doc struct {
		Statements []struct {
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			StatusNotes     string `json:"status_notes"`
			Products        []struct {
				ID string `json:"@id"`
			} `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("the document is not JSON: %v\n%s", err, b)
	}
	return doc.Statements
}

// determined is a record whose false-positive determination follows a
// detection taken at `at`.
func determined(t *testing.T, at string) *AdvisoryFile {
	t.Helper()
	return mustParse(t, `schema-version: 1
project: demo
advisories:
  - id: CVE-2026-0001
    events:
      - timestamp: 2026-10-10T11:00:00Z
        type: detection
        detected-version: `+at+`
      - timestamp: 2026-10-10T12:00:00Z
        type: false-positive-determination
        justification: component_not_present
        note: the affected release was withdrawn upstream
`)
}

func at(version string) []Product {
	return []Product{{ID: "pkg:pkgx/demo@" + version, Version: version}}
}

// The version that WAS examined keeps its determination, justification and
// prose. This is the row that makes the next test mean something: without it,
// a rule that downgraded everything would pass just as well.
func TestADeterminationHoldsForTheVersionItWasMadeAbout(t *testing.T) {
	b, err := EncodeVEX(opts(Subject{File: determined(t, "1.0.0"), Products: at("1.0.0")}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	sts := vexStatements(t, b)
	if len(sts) != 1 {
		t.Fatalf("%d statement(s), want 1:\n%s", len(sts), b)
	}
	if sts[0].Status != VEXNotAffected {
		t.Errorf("status = %q, want %q", sts[0].Status, VEXNotAffected)
	}
	if sts[0].Justification != "component_not_present" {
		t.Errorf("justification = %q", sts[0].Justification)
	}
	if sts[0].StatusNotes != "" {
		t.Errorf("an undowngraded statement carries a downgrade note: %q", sts[0].StatusNotes)
	}
}

// ⛔ THE DEFECT. A determination made about 1.0.0 must not reach 2.0.0 — and
// neither must the justification or the prose, which are the two fields that
// would put the reassurance back in by the side door.
func TestADeterminationDoesNotReachAVersionNobodyExamined(t *testing.T) {
	b, err := EncodeVEX(opts(Subject{File: determined(t, "1.0.0"), Products: at("2.0.0")}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	sts := vexStatements(t, b)
	if len(sts) != 1 {
		t.Fatalf("%d statement(s), want 1:\n%s", len(sts), b)
	}
	s := sts[0]
	if s.Status != VEXUnderInvestigation {
		t.Errorf("status = %q, want %q — 2.0.0 was never examined", s.Status, VEXUnderInvestigation)
	}
	if s.Justification != "" || s.ImpactStatement != "" {
		t.Errorf("the determination's reasoning travelled onto an unexamined version: %+v", s)
	}
	// The note has to say what WAS examined, or "under investigation" reads
	// as "nobody has got to it yet" — which is not what happened.
	for _, want := range []string{"1.0.0", "2.0.0", "not_affected"} {
		if !strings.Contains(s.StatusNotes, want) {
			t.Errorf("status_notes %q does not mention %q", s.StatusNotes, want)
		}
	}
}

// A record that names no version anywhere says nothing about the artefact in
// hand. Silence is not consent: every record written before detections
// carried versions is in exactly this state.
func TestADeterminationWithNoVersionAnywhereReachesNothing(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: demo
advisories:
  - id: CVE-2026-0001
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: false-positive-determination
        justification: component_not_present
`)
	b, err := EncodeVEX(opts(Subject{File: f, Products: at("1.0.0")}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	sts := vexStatements(t, b)
	if sts[0].Status != VEXUnderInvestigation {
		t.Errorf("status = %q, want %q", sts[0].Status, VEXUnderInvestigation)
	}
	if !strings.Contains(sts[0].StatusNotes, "no event in it names a version") {
		t.Errorf("status_notes = %q", sts[0].StatusNotes)
	}
}

// `fixed` is silenced for the same reason `not_affected` is: it tells a reader
// this artefact carries the fix, and saying that about a version nobody
// examined is the same false reassurance in a different word.
func TestFixedDoesNotReachAVersionNobodyExamined(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: demo
advisories:
  - id: CVE-2026-0001
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: fixed
        fixed-version: 1.0.0_1
`)
	// The version the fix landed in keeps its statement...
	b, err := EncodeVEX(opts(Subject{File: f, Products: at("1.0.0_1")}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	if got := vexStatements(t, b)[0].Status; got != VEXFixed {
		t.Errorf("status for the fixed version = %q, want %q", got, VEXFixed)
	}
	// ...and a different one does not.
	b, err = EncodeVEX(opts(Subject{File: f, Products: at("0.9.0")}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	if got := vexStatements(t, b)[0].Status; got != VEXUnderInvestigation {
		t.Errorf("status for an unexamined version = %q, want %q", got, VEXUnderInvestigation)
	}
}

// ⛔ THE CONTROL IN THE OTHER DIRECTION. `affected` is NOT downgraded.
// Restating it for an unexamined version over-warns; downgrading it would
// turn a warning into "we are looking into it", and nothing should ever move
// that way by itself.
func TestAffectedIsNotDowngradedForAnUnexaminedVersion(t *testing.T) {
	f := mustParse(t, `schema-version: 1
project: demo
advisories:
  - id: CVE-2026-0001
    events:
      - timestamp: 2026-10-10T11:00:00Z
        type: detection
        detected-version: 1.0.0
      - timestamp: 2026-10-10T12:00:00Z
        type: true-positive-determination
`)
	b, err := EncodeVEX(opts(Subject{File: f, Products: at("2.0.0")}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	s := vexStatements(t, b)[0]
	if s.Status != VEXAffected {
		t.Errorf("status = %q, want %q — a warning must not weaken on its own", s.Status, VEXAffected)
	}
}

// Two products of different versions under one record cannot share one
// status. Before #340 this function returned a single statement, which is
// what made the wrong answer unavoidable rather than merely possible.
func TestTwoVersionsUnderOneRecordGetTwoStatements(t *testing.T) {
	b, err := EncodeVEX(opts(Subject{
		File: determined(t, "1.0.0"),
		Products: []Product{
			{ID: "pkg:pkgx/demo@1.0.0", Version: "1.0.0"},
			{ID: "pkg:pkgx/demo@2.0.0", Version: "2.0.0"},
		},
	}))
	if err != nil {
		t.Fatalf("EncodeVEX: %v", err)
	}
	sts := vexStatements(t, b)
	if len(sts) != 2 {
		t.Fatalf("%d statement(s), want 2:\n%s", len(sts), b)
	}
	if sts[0].Status != VEXNotAffected || len(sts[0].Products) != 1 || sts[0].Products[0].ID != "pkg:pkgx/demo@1.0.0" {
		t.Errorf("first statement = %+v", sts[0])
	}
	if sts[1].Status != VEXUnderInvestigation || len(sts[1].Products) != 1 || sts[1].Products[0].ID != "pkg:pkgx/demo@2.0.0" {
		t.Errorf("second statement = %+v", sts[1])
	}
}

// A product with no version is refused, not assumed. The alternatives were to
// assert anyway — the defect — or to downgrade silently, which would empty
// the documents of a caller that had merely not been updated.
func TestAProductWithNoVersionIsRefused(t *testing.T) {
	_, err := EncodeVEX(opts(Subject{
		File:     determined(t, "1.0.0"),
		Products: []Product{{ID: "pkg:pkgx/demo@1.0.0"}},
	}))
	if err == nil {
		t.Fatal("accepted a product with no version")
	}
	for _, want := range []string{"demo", "pkg:pkgx/demo@1.0.0", "no version"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// Splitting one record into two statements must not cost determinism: the
// same input still has to produce the same bytes, or a re-push of an
// unchanged artifact would attach a second referrer beside the first.
func TestASplitDocumentIsStillByteStable(t *testing.T) {
	mk := func() ([]byte, error) {
		return EncodeVEX(opts(Subject{
			File: determined(t, "1.0.0"),
			Products: []Product{
				{ID: "pkg:pkgx/demo@1.0.0", Version: "1.0.0"},
				{ID: "pkg:pkgx/demo@2.0.0", Version: "2.0.0"},
			},
		}))
	}
	one, err := mk()
	if err != nil {
		t.Fatal(err)
	}
	two, err := mk()
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Errorf("two encodings of one input differ:\n%s\n%s", one, two)
	}
}
