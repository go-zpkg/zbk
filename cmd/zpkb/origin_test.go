package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/build"
)

// originRefs builds a real provenance referrer through the production path, so
// these tests read what `bk publish` actually writes rather than a fixture
// somebody has to remember to update.
func originRefs(t *testing.T, o provOrigin) []bottle.Referrer {
	t.Helper()
	refs, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "s390x",
		[]byte("tarball"), build.SourceRef{}, nil, time.Unix(0, 0).UTC(), nil, o)
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

// ⛔ TestAnUnstatedOriginIsNotPromotable is the whole point of the tri-state.
// A `bool` would have made this case indistinguishable from "not a
// bootstrap", so every bottle published before the field existed would have
// claimed to be promotable — and the failure directions are not symmetric:
// refusing a good bottle costs a rebuild, promoting a host-built one puts an
// unpinned Ubuntu compiler's output in the production registry under our
// signature.
func TestAnUnstatedOriginIsNotPromotable(t *testing.T) {
	_, err := originAttestedBy(originRefs(t, provOrigin{}))
	if err == nil {
		t.Fatal("a provenance that says nothing about the origin read as an answer")
	}
	if !strings.Contains(err.Error(), "no build origin") {
		t.Errorf("the error does not say the origin is absent: %v", err)
	}
}

// ⛔ TestABootstrapBuildSaysSoAndIsRefused: this is the bottle that must never
// be promoted, and the recording is what makes refusing it possible at all.
func TestABootstrapBuildSaysSoAndIsRefused(t *testing.T) {
	o, err := originAttestedBy(originRefs(t, provOrigin{Bootstrap: "1", Dist: "oci://127.0.0.1:5000/seed"}))
	if err != nil {
		t.Fatal(err)
	}
	if o.Bootstrap != "1" {
		t.Errorf("Bootstrap = %q, want 1", o.Bootstrap)
	}
	if o.Dist != "oci://127.0.0.1:5000/seed" {
		t.Errorf("Dist = %q, want the loopback seed registry", o.Dist)
	}
	// And the refusal has to say WHY, naming the host distribution: "not
	// promotable" alone sends the reader back to the code.
	if why := o.why(); !strings.Contains(why, "bootstrap") || !strings.Contains(why, "host") {
		t.Errorf("why() = %q, want it to name --bootstrap and the host", why)
	}
}

// TestASovereignBuildIsPromotable: the positive case, which has to work or the
// gate refuses everything and nothing is ever promoted.
func TestASovereignBuildIsPromotable(t *testing.T) {
	o, err := originAttestedBy(originRefs(t, provOrigin{Bootstrap: "0", Dist: "oci://ghcr.io/go-zpkg/packages"}))
	if err != nil {
		t.Fatal(err)
	}
	if o.Bootstrap != "0" {
		t.Fatalf("Bootstrap = %q, want 0", o.Bootstrap)
	}
}

// ⛔ TestTheDistAloneIsNotAVerdict. A mirrored bottle records where it was PUT
// and nothing about who compiled it, so `Dist` is readable while `Bootstrap`
// stays empty — and that must NOT pass the gate. Recording a field is not the
// same as answering the question the gate asks.
func TestTheDistAloneIsNotAVerdict(t *testing.T) {
	o, err := originAttestedBy(originRefs(t, provOrigin{Dist: "oci://ghcr.io/go-zpkg/packages"}))
	if err != nil {
		t.Fatalf("a recorded dist should still parse: %v", err)
	}
	if o.Bootstrap == "0" {
		t.Fatal("an unrecorded bootstrap read as 0, which would promote a mirrored bottle")
	}
	if why := o.why(); !strings.Contains(why, "not say") {
		t.Errorf("why() = %q, want it to say the provenance is silent", why)
	}
}

// TestTheOriginKeysAreAbsentWhenUnstated. The provenance block already carries
// the lesson that a field which is always empty teaches readers to ignore it,
// so an unstated origin must emit no key at all rather than an empty one.
func TestTheOriginKeysAreAbsentWhenUnstated(t *testing.T) {
	ext := externalParamsOf(t, originRefs(t, provOrigin{}))
	for _, k := range []string{"bootstrap", "inputs-from"} {
		if v, ok := ext[k]; ok {
			t.Errorf("externalParameters[%q] = %q, want the key absent", k, v)
		}
	}
	// The pre-existing keys must survive: this change adds to the block and
	// does not rewrite it.
	for _, k := range []string{"project", "version", "platform"} {
		if _, ok := ext[k]; !ok {
			t.Errorf("externalParameters lost %q", k)
		}
	}
}

// TestAStatedOriginReachesTheAttestation, read out of the signed document
// rather than out of the struct that produced it.
func TestAStatedOriginReachesTheAttestation(t *testing.T) {
	ext := externalParamsOf(t, originRefs(t, provOrigin{Bootstrap: "0", Dist: "oci://ghcr.io/go-zpkg/packages"}))
	for k, want := range map[string]string{
		"bootstrap":   "0",
		"inputs-from": "oci://ghcr.io/go-zpkg/packages",
	} {
		if got := ext[k]; got != want {
			t.Errorf("externalParameters[%q] = %q, want %q", k, got, want)
		}
	}
}

// TestBoolParamIsTheTwoKnownStates, and neither of them is the empty string —
// which is what keeps "unknown" a third thing.
func TestBoolParamIsTheTwoKnownStates(t *testing.T) {
	if got := boolParam(true); got != "1" {
		t.Errorf("boolParam(true) = %q, want 1", got)
	}
	if got := boolParam(false); got != "0" {
		t.Errorf("boolParam(false) = %q, want 0", got)
	}
}

// externalParamsOf digs the externalParameters block out of an in-toto
// referrer.
func externalParamsOf(t *testing.T, refs []bottle.Referrer) map[string]string {
	t.Helper()
	var raw []byte
	for _, r := range refs {
		if r.ArtifactType == artifactInToto {
			raw = r.Blob
			break
		}
	}
	if raw == nil {
		t.Fatal("no in-toto referrer was produced")
	}
	var stmt struct {
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters map[string]string `json:"externalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatal(err)
	}
	return stmt.Predicate.BuildDefinition.ExternalParameters
}

// TestOriginRefusesWithoutBothArguments: a project with no version would
// otherwise read the newest, and "the newest" is not the bottle somebody is
// deciding whether to promote.
func TestOriginRefusesWithoutBothArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runOrigin([]string{"acme.org/tool"}, &out, &errOut); code != 2 {
		t.Errorf("runOrigin with one argument = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "usage:") {
		t.Errorf("it does not print a usage line: %q", errOut.String())
	}
}

// stubAttestations points the registry read at a fixed answer for one test.
func stubAttestations(t *testing.T, refs []bottle.Referrer, err error) {
	t.Helper()
	old := sourceAttestations
	t.Cleanup(func() { sourceAttestations = old })
	sourceAttestations = func(_, _, _, _, _ string) ([]bottle.Referrer, error) { return refs, err }
}

// ⛔ originArgs NAMES THE PLATFORM, and that is not decoration. Without
// `--platform` these tests resolve the HOST's, which depends on ambient state
// another test in this package can leave behind — they passed under a `-run`
// filter and every one of them failed in the full suite with `runOrigin = 2`,
// the exit code for "could not work out the platform". A test that reads the
// machine is a test whose result depends on what ran before it.
//
// linux/s390x because it is the platform the whole feature exists for.
func originArgs(extra ...string) []string {
	return append(append([]string{"--platform", "linux/s390x"}, extra...), "acme.org/tool", "1.2.3")
}

// TestOriginReportsEachOfTheThreeStates end to end, through the command, since
// the wording is the whole product for a human reader.
func TestOriginReportsEachOfTheThreeStates(t *testing.T) {
	for _, c := range []struct {
		name   string
		origin provOrigin
		want   []string
	}{
		{
			name:   "sovereign",
			origin: provOrigin{Bootstrap: "0", Dist: "oci://ghcr.io/go-zpkg/packages"},
			want:   []string{"no — built from bottles", "oci://ghcr.io/go-zpkg/packages"},
		},
		{
			name:   "bootstrap",
			origin: provOrigin{Bootstrap: "1", Dist: "oci://127.0.0.1:5000/seed"},
			want:   []string{"yes", "NOT promotable", "oci://127.0.0.1:5000/seed"},
		},
		{
			// A dist with no verdict: the line about the registry has to
			// appear AND the bootstrap line has to say it is unrecorded,
			// or a reader sees a filled-in report and assumes an answer.
			name:   "dist only",
			origin: provOrigin{Dist: "oci://ghcr.io/go-zpkg/packages"},
			want:   []string{"not recorded"},
		},
		{
			// A value that is neither 0 nor 1 — a future bk, or a tampered
			// document. It must not be silently read as either.
			name:   "unreadable value",
			origin: provOrigin{Bootstrap: "yes", Dist: "oci://x/y"},
			want:   []string{"unreadable value yes"},
		},
		{
			// The inverse of "dist only": a verdict with no registry behind
			// it. The report must still say which part is missing, because
			// "promotable" and "we know where it came from" are two
			// different claims and only one of them is being made.
			name:   "verdict only",
			origin: provOrigin{Bootstrap: "0"},
			want:   []string{"no — built from bottles", "inputs resolved from: not recorded"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			stubAttestations(t, originRefs(t, c.origin), nil)
			var out, errOut bytes.Buffer
			if code := runOrigin(originArgs(), &out, &errOut); code != 0 {
				t.Fatalf("runOrigin = %d, stderr %q", code, errOut.String())
			}
			for _, want := range c.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output does not contain %q:\n%s", want, out.String())
				}
			}
		})
	}
}

// ⛔ TestPromotableIsSilentOnYesAndLoudOnNo. A gate's output is its exit
// status; printing a reassurance on success would make a script that ignores
// the status look like it checked something.
func TestPromotableIsSilentOnYesAndLoudOnNo(t *testing.T) {
	t.Run("yes", func(t *testing.T) {
		stubAttestations(t, originRefs(t, provOrigin{Bootstrap: "0", Dist: "oci://ghcr.io/go-zpkg/packages"}), nil)
		var out, errOut bytes.Buffer
		if code := runOrigin(originArgs("--promotable"), &out, &errOut); code != 0 {
			t.Fatalf("a sovereign bottle was refused: %d %q", code, errOut.String())
		}
		if out.Len() != 0 || errOut.Len() != 0 {
			t.Errorf("the gate printed something on success: out=%q err=%q", out.String(), errOut.String())
		}
	})
	for _, c := range []struct{ name, bootstrap, want string }{
		{"bootstrap", "1", "--bootstrap"},
		{"unreadable", "maybe", "neither 0 nor 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			stubAttestations(t, originRefs(t, provOrigin{Bootstrap: c.bootstrap, Dist: "oci://x/y"}), nil)
			var out, errOut bytes.Buffer
			if code := runOrigin(originArgs("--promotable"), &out, &errOut); code != 1 {
				t.Fatalf("runOrigin = %d, want 1", code)
			}
			if !strings.Contains(errOut.String(), c.want) {
				t.Errorf("the refusal does not say %q: %q", c.want, errOut.String())
			}
		})
	}
}

// ⛔ TestAnUnreadableRegistryIsNotAnAbsence: a registry that could not be
// reached has told us nothing, and reporting it as "records no origin" would
// be the same defect as a census that could not read reporting zero.
func TestAnUnreadableRegistryIsNotAnAbsence(t *testing.T) {
	stubAttestations(t, nil, errors.New("dial tcp: connection refused"))
	var out, errOut bytes.Buffer
	if code := runOrigin(originArgs(), &out, &errOut); code != 1 {
		t.Fatalf("runOrigin = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "connection refused") {
		t.Errorf("the error does not carry the registry's reason: %q", errOut.String())
	}
}

// TestOriginRefusesABadPlatformAndABadFlag, the two argument errors that must
// not reach the network.
func TestOriginRefusesABadPlatformAndABadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runOrigin([]string{"--platform", "linux", "acme.org/tool", "1.2.3"}, &out, &errOut); code != 2 {
		t.Errorf("a platform with no slash = %d, want 2", code)
	}
	out.Reset()
	errOut.Reset()
	if code := runOrigin([]string{"--nope"}, &out, &errOut); code != 2 {
		t.Errorf("an unknown flag = %d, want 2", code)
	}
}

// TestOriginReportsAProvenancelessBottle: a bottle with no in-toto referrer at
// all, which is a different silence from one whose provenance omits the
// origin, and is reported as its own error.
func TestOriginReportsAProvenancelessBottle(t *testing.T) {
	stubAttestations(t, []bottle.Referrer{{ArtifactType: artifactCycloneDX, Blob: []byte("{}")}}, nil)
	var out, errOut bytes.Buffer
	if code := runOrigin(originArgs(), &out, &errOut); code != 1 {
		t.Fatalf("runOrigin = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "no provenance") {
		t.Errorf("it does not distinguish a missing attestation: %q", errOut.String())
	}
}

// TestOriginIsReachableFromTheCommandLine. The subcommand table is the one
// place where a working implementation and an unreachable one look identical:
// every test above calls runOrigin directly, and would pass unchanged if
// `bk origin` dispatched to nothing.
func TestOriginIsReachableFromTheCommandLine(t *testing.T) {
	stubAttestations(t, originRefs(t, provOrigin{Bootstrap: "0", Dist: "oci://ghcr.io/go-zpkg/packages"}), nil)
	code, out, errb := run2(t, "origin", "--platform", "linux/s390x", "acme.org/tool", "1.2.3")
	if code != 0 {
		t.Fatalf("bk origin = %d, stderr %q", code, errb)
	}
	if !strings.Contains(out, "built from bottles") {
		t.Errorf("bk origin printed nothing recognisable:\n%s", out)
	}
}

// TestOriginRejectsAnUnparsableProvenance: a referrer that is present and is
// not JSON is a broken document, not an absent field.
func TestOriginRejectsAnUnparsableProvenance(t *testing.T) {
	if _, err := originAttestedBy([]bottle.Referrer{{ArtifactType: artifactInToto, Blob: []byte("not json")}}); err == nil {
		t.Error("an unparsable provenance read as an answer")
	} else if !strings.Contains(err.Error(), "provenance") {
		t.Errorf("the error does not name the document: %v", err)
	}
}
