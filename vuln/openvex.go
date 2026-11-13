package vuln

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OpenVEX emission: the advisory records above, said in the one format a
// scanner already reads.
//
// Why bother, when the records are already structured? Because a record only
// this fleet can read is a record that costs every consumer a re-triage. VEX
// exists so that "we are not affected, and here is the machine-readable reason"
// travels with the artefact. The spec is explicit about the cost of the prose
// alternative: an `impact_statement` "breaks VEX automation and
// interoperability", so the label is what gets emitted and the prose rides
// along beside it.
//
// Field names, requiredness and the two fixed vocabularies are from
// openvex/spec OPENVEX-SPEC.md as read on 2026-10-11.

// VEXContext is the context URL for the spec version this encoder writes. The
// spec says an omitted version "defaults to v0.0.1", so writing it explicitly
// is not decoration: without it a consumer reads a v0.2.0 document as the
// oldest one.
const VEXContext = "https://openvex.dev/ns/v0.2.0"

// VEX status labels.
const (
	VEXNotAffected        = "not_affected"
	VEXAffected           = "affected"
	VEXFixed              = "fixed"
	VEXUnderInvestigation = "under_investigation"
)

// Product is the artefact a statement is about.
//
// Choosing it is the CALLER's job and it is not cosmetic: a `fixed` statement
// asserts that THESE versions contain the fix, so naming an artifact that does not
// is a false claim. Advisory.FixedBy is the check.
//
// The hash is what makes the statement checkable rather than merely plausible.
// A purl names a version; a digest names the bytes, and it is the same digest
// the artifact's SBOM, its SLSA provenance and its cosign payload are bound to —
// so all four attestations speak about one artefact instead of four
// descriptions that happen to agree.
type Product struct {
	// ID is the IRI identifying the product. Optional in the spec; required
	// here, because a statement whose subject cannot be named is not usable.
	ID string
	// Version is the version of OURS this product is, spelled as the artifact
	// tag spells it — "3.5.8_1", rebuild counter included.
	//
	// ⛔ REQUIRED, although the spec asks for no such field, because without
	// it this encoder cannot tell whether the record it is reading has
	// anything to say about THIS artefact. A purl already carries the
	// version, but only as text inside an identifier nobody here parses, and
	// a check that depends on parsing a string the caller built is a check
	// that stops working the day the caller spells it differently. See
	// scopedTo and go-zpkg/bk#340.
	Version string
	// PURL goes into `identifiers`, whose label for a Package URL is "purl"
	// (OpenVEX "favors the use of purl"). Optional.
	PURL string
	// SHA256 is the hex digest, no "sha256:" prefix. Optional.
	SHA256 string
}

// hashLabelSHA256 is the key a sha-256 digest goes under in `hashes`.
//
// ⛔ THE HYPHEN IS NOT OPTIONAL AND NOT CONSISTENT. OpenVEX's hash table
// spells it `sha-256` while sha1 in the same table is `sha1`. Writing
// `sha256`, which is what every other part of this repository calls it, puts
// the digest under a key no consumer looks at — and nothing complains, because
// `hashes` is a free-form map.
const hashLabelSHA256 = "sha-256"

// identifierLabelPURL is the key a Package URL goes under in `identifiers`,
// from the spec's Software Identifier Types table.
const identifierLabelPURL = "purl"

// Subject is one project's advisories together with the artefacts they are
// being asserted about.
type Subject struct {
	File     *AdvisoryFile
	Products []Product
}

// VEXOptions is the document metadata. Every field here is required by the
// spec, and EncodeVEX refuses a document missing any of them rather than
// emitting one a consumer will reject — or worse, accept with a default.
type VEXOptions struct {
	// ID is the IRI identifying this document.
	ID string
	// Author identifies who is asserting this. The spec asks for a machine
	// readable identifier and says the identity SHOULD be cryptographically
	// associated with the document's signature — which, here, is the cosign
	// signature the artifact already carries.
	Author string
	// Role is optional.
	Role string
	// Timestamp is when the document was issued.
	Timestamp time.Time
	// Version must be incremented whenever any content changes. It starts at
	// 1; a zero version is refused, because "unset" and "the first version"
	// are different things and only one of them is a document.
	Version int
	// Tooling is optional and says what generated this.
	Tooling  string
	Subjects []Subject
}

// vexDocument, vexStatement and the two structs below mirror the spec's field
// names exactly. `omitempty` on every optional field, because a VEX consumer
// reading `"justification": ""` on a not_affected statement sees a document
// that violates the one rule the spec is strict about.
type vexDocument struct {
	Context     string         `json:"@context"`
	ID          string         `json:"@id"`
	Author      string         `json:"author"`
	Role        string         `json:"role,omitempty"`
	Timestamp   string         `json:"timestamp"`
	Version     int            `json:"version"`
	Tooling     string         `json:"tooling,omitempty"`
	LastUpdated string         `json:"last_updated,omitempty"`
	Statements  []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexVulnerability `json:"vulnerability"`
	Timestamp       string           `json:"timestamp"`
	Products        []vexProduct     `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
	StatusNotes     string           `json:"status_notes,omitempty"`
}

type vexVulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type vexProduct struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
	Hashes      map[string]string `json:"hashes,omitempty"`
}

// statusFor maps one of our event types onto a VEX status.
//
// The mapping is the whole design decision in this file, so it is a table and
// not a chain of ifs:
//
//	detection                    under_investigation  a match, not a finding
//	true-positive-determination  affected             it does affect us
//	false-positive-determination not_affected         + the justification label
//	fixed                        fixed                a version of ours has it
//	fix-not-planned              affected             + why nothing is coming
//	pending-upstream-fix         affected             + what is being waited on
//
// `detection` becoming `under_investigation` rather than `affected` is the one
// worth defending: a detection is a database saying our NAME matched, and this
// fleet measured what that is worth — a bare CPE query for openssl returned 27
// records, four of them from 2009. Emitting those as `affected` would publish
// 23 false alarms with our signature on them.
var statusFor = map[string]string{
	EventDetection:          VEXUnderInvestigation,
	EventTruePositive:       VEXAffected,
	EventFalsePositive:      VEXNotAffected,
	EventFixed:              VEXFixed,
	EventFixNotPlanned:      VEXAffected,
	EventPendingUpstreamFix: VEXAffected,
}

// silencing are the two statuses that tell a reader to STOP LOOKING, and they
// are the two this encoder refuses to assert about a version nobody examined.
//
// `affected` is deliberately absent. Restating it for an unexamined version
// over-warns, which costs noise; restating `not_affected` or `fixed`
// under-warns, which costs the reader the habit of checking. Those are not the
// same mistake, and a rule that treated them alike would turn a stale warning
// into silence — exactly the direction nothing should ever move on its own.
var silencing = map[string]bool{
	VEXNotAffected: true,
	VEXFixed:       true,
}

// versionsNamed is every version of OURS the record actually speaks about:
// the versions detections were taken at, and the versions `fixed` events name
// as carrying a fix.
//
// Both, not just detections, because `fixed-version: 3.5.8_1` is as explicit a
// statement about 3.5.8_1 as a detection recorded against it.
//
// ⛔ EVERY event, which is only safe because Latest is the LAST one: no event
// can be dated after the decision being emitted, so none of them can widen
// its scope behind its back. Were Latest ever to mean "the last
// determination" instead, a detection recorded afterwards would silently
// extend an older `not_affected` onto the version it detected.
func versionsNamed(a Advisory) map[string]bool {
	seen := map[string]bool{}
	for _, e := range a.Events {
		if e.DetectedVersion != "" {
			seen[e.DetectedVersion] = true
		}
		if e.FixedVersion != "" {
			seen[e.FixedVersion] = true
		}
	}
	return seen
}

// scopedTo reports whether this record has anything to say about version v,
// and lists what it does name.
//
// An EMPTY list is "no", not "yes". A record written before versions were
// recorded at all says nothing about any version, and reading that silence as
// consent is precisely the defect: it is the state every record in the fleet
// was in when #340 was filed.
func scopedTo(a Advisory, v string) (bool, []string) {
	named := versionsNamed(a)
	versions := make([]string, 0, len(named))
	for s := range named {
		versions = append(versions, s)
	}
	sort.Strings(versions)
	return named[v], versions
}

// unexaminedNote is the `status_notes` on a statement that was downgraded. It
// says which versions WERE examined, because "under investigation" with no
// reason reads as "we have not got to it yet" — and the truth is better than
// that: somebody did the work, for a different artefact.
func unexaminedNote(status, version string, examined []string) string {
	if len(examined) == 0 {
		return fmt.Sprintf("This record reaches %q, but no event in it names a version, so nothing here was examined at %s. "+
			"A VEX statement names a version and this one is not restated for an artefact nobody looked at (go-zpkg/bk#340).",
			status, version)
	}
	return fmt.Sprintf("This record reaches %q for %s, and %s was not examined. "+
		"A VEX statement names a version and this one is not restated for an artefact nobody looked at (go-zpkg/bk#340).",
		status, strings.Join(examined, ", "), version)
}

// actionFor is the action statement an `affected` status must carry. The spec
// says a statement with affected status "MUST include a statement that SHOULD
// describe actions to remediate or mitigate", and the three event types that
// become `affected` mean quite different things to someone reading it.
var actionFor = map[string]string{
	EventTruePositive:       "Upgrade to a version that carries the fix once one is published.",
	EventFixNotPlanned:      "No fix is planned for this package; use a maintained alternative.",
	EventPendingUpstreamFix: "A fix requires work upstream; no action here will remove the exposure.",
}

// EncodeVEX writes an OpenVEX document for the given subjects, indented.
//
// Statements are ordered by vulnerability id within each subject, and subjects
// by project, so the same records produce the same bytes — a document that
// differed run to run could not be attached to an artifact and compared.
func EncodeVEX(o VEXOptions) ([]byte, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	doc := vexDocument{
		Context:   VEXContext,
		ID:        o.ID,
		Author:    o.Author,
		Role:      o.Role,
		Timestamp: o.Timestamp.UTC().Format(time.RFC3339),
		Version:   o.Version,
		Tooling:   o.Tooling,
	}
	subjects := make([]Subject, len(o.Subjects))
	copy(subjects, o.Subjects)
	sort.SliceStable(subjects, func(i, j int) bool {
		return subjects[i].File.Project < subjects[j].File.Project
	})
	for _, s := range subjects {
		advisories := make([]Advisory, len(s.File.Advisories))
		copy(advisories, s.File.Advisories)
		sort.SliceStable(advisories, func(i, j int) bool { return advisories[i].ID < advisories[j].ID })
		for _, a := range advisories {
			sts, err := statementsFor(a, s.Products)
			if err != nil {
				return nil, fmt.Errorf("vuln: vex: %s: %s: %w", s.File.Project, a.ID, err)
			}
			doc.Statements = append(doc.Statements, sts...)
		}
	}
	return json.MarshalIndent(doc, "", "  ")
}

func (o VEXOptions) check() error {
	switch {
	case strings.TrimSpace(o.ID) == "":
		return fmt.Errorf("vuln: vex: no @id — the spec requires an IRI identifying the document")
	case strings.TrimSpace(o.Author) == "":
		return fmt.Errorf("vuln: vex: no author — a statement nobody is asserting is not a statement")
	case o.Timestamp.IsZero():
		return fmt.Errorf("vuln: vex: no timestamp — nothing can supersede an undated document")
	case o.Version < 1:
		return fmt.Errorf("vuln: vex: version %d — it starts at 1, and unset is not a version", o.Version)
	case len(o.Subjects) == 0:
		return fmt.Errorf("vuln: vex: no subjects — an empty document asserts nothing")
	}
	for _, s := range o.Subjects {
		if s.File == nil {
			return fmt.Errorf("vuln: vex: a subject has no advisory file")
		}
		// No products means the statement inherits them from the document,
		// and this encoder sets none at document level — so it would assert
		// something about nothing at all.
		if len(s.Products) == 0 {
			return fmt.Errorf("vuln: vex: %s names no product", s.File.Project)
		}
		for _, p := range s.Products {
			// The spec makes @id optional and lets a product be identified by
			// its `identifiers` alone. Required here: a statement whose
			// subject has no name is one nobody can look up, and the caller
			// always has one — the artifact's purl.
			if strings.TrimSpace(p.ID) == "" {
				return fmt.Errorf("vuln: vex: %s: a product has no @id", s.File.Project)
			}
			// ⛔ REFUSED RATHER THAN ASSUMED. Without the version this
			// encoder cannot tell whether a `not_affected` in the record is
			// about this artefact, and the only two ways to carry on are to
			// assert it anyway — the defect #340 is about — or to downgrade
			// every statement, which would quietly empty the documents of
			// every caller that simply had not been updated. A refusal names
			// the one line that has to change.
			if strings.TrimSpace(p.Version) == "" {
				return fmt.Errorf("vuln: vex: %s: product %s has no version — a statement names a version, so one cannot be written for an artefact that has none", s.File.Project, p.ID)
			}
		}
	}
	return nil
}

// statementsFor is the statements one advisory produces for one subject's
// products — usually ONE, and two when the record's conclusion does not reach
// every product it was handed.
//
// ⛔ A LIST, not a statement. Before #340 this returned exactly one statement
// covering every product, which is only correct while every product is the
// same version. The moment a determination made about 1.0.0 meets an artifact of
// 2.0.0, one status cannot be right for both, and the shape of the function
// was what made the wrong one unavoidable.
func statementsFor(a Advisory, products []Product) ([]vexStatement, error) {
	e := a.Latest()
	status, ok := statusFor[e.Type]
	if !ok {
		// Reachable only if an event type is added to the parser's allowlist
		// without being mapped here. That is exactly the silent half-change
		// worth refusing: the alternative is a document missing statements.
		return nil, fmt.Errorf("event type %q maps to no VEX status", e.Type)
	}
	if !silencing[status] {
		return []vexStatement{statement(a, e, status, products, "")}, nil
	}
	var covered, unexamined []Product
	var examined []string
	for _, p := range products {
		in, versions := scopedTo(a, p.Version)
		examined = versions
		if in {
			covered = append(covered, p)
		} else {
			unexamined = append(unexamined, p)
		}
	}
	var out []vexStatement
	if len(covered) > 0 {
		out = append(out, statement(a, e, status, covered, ""))
	}
	if len(unexamined) > 0 {
		// One statement for all of them even when their versions differ: the
		// note names the version it is about, and products that share a
		// statement here share the only thing that matters about them, which
		// is that nothing in the record reaches them.
		out = append(out, statement(a, e, VEXUnderInvestigation, unexamined,
			unexaminedNote(status, unexamined[0].Version, examined)))
	}
	return out, nil
}

// statement renders one event as one VEX statement about the given products.
// downgradeNote is empty for a statement that says what the record says, and
// carries the explanation for one that does not.
func statement(a Advisory, e Event, status string, products []Product, downgradeNote string) vexStatement {
	st := vexStatement{
		Vulnerability: vexVulnerability{Name: a.ID, Aliases: a.Aliases},
		// The statement's own timestamp is "the time at which the information
		// expressed in the Statement was known to be true" — which is when the
		// event happened, NOT when the document was written. Using the
		// document's time would date every finding to the last publish.
		Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
		Status:    status,
	}
	for _, p := range products {
		vp := vexProduct{ID: p.ID}
		if p.PURL != "" {
			vp.Identifiers = map[string]string{identifierLabelPURL: p.PURL}
		}
		if p.SHA256 != "" {
			vp.Hashes = map[string]string{hashLabelSHA256: p.SHA256}
		}
		st.Products = append(st.Products, vp)
	}
	if downgradeNote != "" {
		// ⛔ NEITHER the justification NOR the impact statement travels onto a
		// downgraded statement. A justification is only valid on
		// `not_affected`, and the record's prose was written about a version
		// this statement is not about — carrying it over would put the
		// reassurance back in the document by the side door, in the one field
		// a human actually reads.
		st.StatusNotes = downgradeNote
		return st
	}
	switch status {
	case VEXNotAffected:
		// Guaranteed non-empty and in the vocabulary by ParseAdvisories; set
		// here because the spec makes it mandatory for this status and a
		// consumer rejects the statement without it.
		st.Justification = e.Justification
		st.ImpactStatement = e.Note
	case VEXAffected:
		st.ActionStatement = actionFor[e.Type]
		st.StatusNotes = e.Note
	default:
		st.StatusNotes = e.Note
	}
	return st
}
