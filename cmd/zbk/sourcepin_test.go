package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/go-zpkg/zbk/fetch"
)

func sourcePin(t *testing.T, digest string, size int64, ferr error, args ...string) (int, string, string) {
	t.Helper()
	was := fetchDigest
	fetchDigest = func(string) (string, int64, error) { return digest, size, ferr }
	t.Cleanup(func() { fetchDigest = was })
	var out, errb bytes.Buffer
	rc := runSourcePin(args, &out, &errb)
	return rc, out.String(), errb.String()
}

const aDigest = "02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584"

// Both forms, because the keyed one is what a recipe almost always wants: the
// url interpolates {{version.raw}}, so a scalar serves exactly one of the
// versions the recipe can resolve.
func TestSourcePinPrintsBothFormsWithoutAVersion(t *testing.T) {
	rc, out, errb := sourcePin(t, aDigest, 1507140, nil, "https://x/y.tar.gz")
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	for _, want := range []string{
		"sha256 = \"" + aDigest + "\"",
		"sha256 = { \"<version>\" = \"" + aDigest + "\" }",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not offer %q:\n%s", want, out)
		}
	}
}

// ⛔ THE SIZE IS PRINTED BESIDE THE DIGEST ON PURPOSE. The incident this
// command exists for produced a digest of 92 bytes of error page; a hex string
// hides that and a byte count does not.
func TestSourcePinReportsTheSize(t *testing.T) {
	_, out, _ := sourcePin(t, aDigest, 92, nil, "https://x/y.tar.gz")
	if !strings.Contains(out, "92 bytes") {
		t.Errorf("the size has to be visible:\n%s", out)
	}
}

func TestSourcePinWithAVersionPrintsOnlyTheKeyedForm(t *testing.T) {
	rc, out, errb := sourcePin(t, aDigest, 10, nil, "--version", "5.8.4", "https://x/y.tar.gz")
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	if !strings.Contains(out, "\"5.8.4\" = \""+aDigest+"\"") {
		t.Errorf("want the keyed form for 5.8.4:\n%s", out)
	}
	if strings.Contains(out, "<version>") {
		t.Errorf("a stated version must not leave the placeholder behind:\n%s", out)
	}
}

// ⛔⛔ A FAILED FETCH PRINTS NO DIGEST AT ALL. Anything else invites pasting a
// pin that was never verified, and a pinned recipe is fail-closed: a wrong pin
// breaks every later build of that version while looking authoritative.
func TestSourcePinPrintsNothingPinnableOnFailure(t *testing.T) {
	rc, out, errb := sourcePin(t, "", 0, errors.New("fetch: GET https://x/y.tar.gz: 504 Gateway Timeout"),
		"https://x/y.tar.gz")
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if strings.Contains(out, "sha256") {
		t.Errorf("no sha256 line may be printed on failure:\n%s", out)
	}
	if !strings.Contains(errb, "504") {
		t.Errorf("the refusal must say what the host said: %q", errb)
	}
}

func TestSourcePinUsage(t *testing.T) {
	if rc, _, errb := sourcePin(t, aDigest, 1, nil); rc != 2 || !strings.Contains(errb, "usage:") {
		t.Errorf("no URL is a usage error: rc=%d %q", rc, errb)
	}
	if rc, _, _ := sourcePin(t, aDigest, 1, nil, "a", "b"); rc != 2 {
		t.Error("two URLs is a usage error")
	}
	if rc, _, _ := sourcePin(t, aDigest, 1, nil, "--nope"); rc != 2 {
		t.Error("an unknown flag is a usage error")
	}
}

// signedPin drives the --sig path with both seams stubbed: the key file and the
// verifier.
func signedPin(t *testing.T, pin fetch.SourcePin, verr error, key []byte, kerr error, args ...string) (int, string, string) {
	t.Helper()
	wasV, wasK := fetchVerified, readKeyFile
	fetchVerified = func(string, []string, []byte, string) (fetch.SourcePin, error) { return pin, verr }
	readKeyFile = func(string) ([]byte, error) { return key, kerr }
	t.Cleanup(func() { fetchVerified, readKeyFile = wasV, wasK })
	var out, errb bytes.Buffer
	rc := runSourcePin(args, &out, &errb)
	return rc, out.String(), errb.String()
}

var aPin = fetch.SourcePin{
	SHA256:      aDigest,
	Size:        1507140,
	SigURL:      "https://x/y.tar.gz.asc",
	Fingerprint: "DB1F68E7D0B30EA7C41D1B3E3B7C5B4E9A0F1D2C",
	Identity:    "Upstream Author <author@upstream.example>",
	KeysRead:    1,
}

// ⛔⛔ --sig WITHOUT --key OR --key-source IS A USAGE ERROR, NOT A FALLBACK.
// A flag that silently does nothing is worse than a missing one, and the
// something it would silently not do here is the verification: the digest would
// print and look checked.
func TestSourcePinSigNeedsAKeyAndItsProvenance(t *testing.T) {
	for _, args := range [][]string{
		{"--sig", "auto", "https://x/y.tar.gz"},
		{"--sig", "auto", "--key", "k.asc", "https://x/y.tar.gz"},
		{"--sig", "auto", "--key-source", "their release page", "https://x/y.tar.gz"},
	} {
		rc, out, errb := signedPin(t, aPin, nil, []byte("key"), nil, args...)
		if rc != 2 {
			t.Errorf("%v: rc = %d, want 2", args, rc)
		}
		if strings.Contains(out, "sha256") {
			t.Errorf("%v: a digest was printed anyway:\n%s", args, out)
		}
		if !strings.Contains(errb, "keyserver") || !strings.Contains(errb, "key-source") {
			t.Errorf("%v: the refusal must say why both are required: %q", args, errb)
		}
	}
}

// And the inverse: a key with no --sig verifies nothing, so saying so beats
// accepting it and ignoring it.
func TestSourcePinKeyWithoutSigIsAUsageError(t *testing.T) {
	for _, args := range [][]string{
		{"--key", "k.asc", "https://x/y.tar.gz"},
		{"--key-source", "their page", "https://x/y.tar.gz"},
		{"--fingerprint", "ABCD", "https://x/y.tar.gz"},
	} {
		if rc, _, errb := signedPin(t, aPin, nil, []byte("key"), nil, args...); rc != 2 ||
			!strings.Contains(errb, "only mean something with --sig") {
			t.Errorf("%v: rc=%d %q", args, rc, errb)
		}
	}
}

// TestSourcePinSignedPrintsTheProvenanceToPaste: the fingerprint, the identity,
// the signature URL that ANSWERED, and where the author's trust in that key
// came from — the last being the one thing none of Gentoo, Arch, Debian or Guix
// records.
func TestSourcePinSignedPrintsTheProvenanceToPaste(t *testing.T) {
	rc, out, errb := signedPin(t, aPin, nil, []byte("key"), nil,
		"--sig", "auto", "--key", "upstream.asc", "--key-source", "https://upstream.example/keys",
		"--version", "5.8.4", "https://x/y.tar.gz")
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	for _, want := range []string{
		aPin.Fingerprint,
		aPin.Identity,
		`sig    = "https://x/y.tar.gz.asc"`,
		`"5.8.4" = "` + aDigest + `"`,
		"provenance {",
		"fingerprint came from: https://upstream.example/keys",
		"no keyserver was asked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not carry %q:\n%s", want, out)
		}
	}
}

// Without --version the signed path still offers the keyed placeholder, because
// the keyed form is what a recipe wants either way.
func TestSourcePinSignedWithoutAVersion(t *testing.T) {
	_, out, _ := signedPin(t, aPin, nil, []byte("key"), nil,
		"--sig", "https://x/y.tar.gz.asc", "--key", "k.asc", "--key-source", "a page", "https://x/y.tar.gz")
	if !strings.Contains(out, `sha256 = { "<version>" = "`+aDigest+`" }`) {
		t.Errorf("want the placeholder form:\n%s", out)
	}
}

// ⛔⛔ A FAILED VERIFICATION PRINTS NO DIGEST. The verifier's own message
// already carries the digest so the author can see the bytes arrived intact;
// what must not appear is a `sha256 =` line ready to paste.
func TestSourcePinSignedPrintsNothingPinnableWhenTheSignatureFails(t *testing.T) {
	rc, out, errb := signedPin(t, fetch.SourcePin{}, errors.New("not vouched for by the key you passed"),
		[]byte("key"), nil,
		"--sig", "auto", "--key", "k.asc", "--key-source", "a page", "https://x/y.tar.gz")
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if strings.Contains(out, "sha256") || strings.Contains(out, "provenance") {
		t.Errorf("nothing pinnable may be printed:\n%s", out)
	}
	if !strings.Contains(errb, "not vouched for") {
		t.Errorf("stderr = %q", errb)
	}
}

func TestSourcePinSignedWhenTheKeyFileCannotBeRead(t *testing.T) {
	rc, out, errb := signedPin(t, aPin, nil, nil, errors.New("open k.asc: no such file or directory"),
		"--sig", "auto", "--key", "k.asc", "--key-source", "a page", "https://x/y.tar.gz")
	if rc != 1 || strings.Contains(out, "sha256") || !strings.Contains(errb, "no such file") {
		t.Errorf("rc=%d out=%q err=%q", rc, out, errb)
	}
}

// TestSourcePinAutoTriesBothNames: `auto` is Debian's Pgp-Mode shape, and the
// two candidates are the two spellings in the wild.
func TestSourcePinAutoTriesBothNames(t *testing.T) {
	var got []string
	wasV, wasK := fetchVerified, readKeyFile
	fetchVerified = func(_ string, cands []string, _ []byte, _ string) (fetch.SourcePin, error) {
		got = cands
		return aPin, nil
	}
	readKeyFile = func(string) ([]byte, error) { return []byte("key"), nil }
	t.Cleanup(func() { fetchVerified, readKeyFile = wasV, wasK })
	var out, errb bytes.Buffer
	if rc := runSourcePin([]string{"--sig", "auto", "--key", "k.asc", "--key-source", "p",
		"https://x/y.tar.gz"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d: %q", rc, errb.String())
	}
	want := []string{"https://x/y.tar.gz.asc", "https://x/y.tar.gz.sig"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("candidates = %v, want %v", got, want)
	}
}

// TestSourcePinPassesTheFingerprintThrough, because a flag the verifier never
// receives is a flag that reads as enforced and is not.
func TestSourcePinPassesTheFingerprintThrough(t *testing.T) {
	var got string
	wasV, wasK := fetchVerified, readKeyFile
	fetchVerified = func(_ string, _ []string, _ []byte, fpr string) (fetch.SourcePin, error) {
		got = fpr
		return aPin, nil
	}
	readKeyFile = func(string) ([]byte, error) { return []byte("key"), nil }
	t.Cleanup(func() { fetchVerified, readKeyFile = wasV, wasK })
	var out, errb bytes.Buffer
	if rc := runSourcePin([]string{"--sig", "auto", "--key", "k.asc", "--key-source", "p",
		"--fingerprint", "155D 3FC5 00C8", "https://x/y.tar.gz"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d: %q", rc, errb.String())
	}
	// Passed VERBATIM: the spaces a person pastes are the verifier's business,
	// and normalising here would mean two notions of "same fingerprint".
	if got != "155D 3FC5 00C8" {
		t.Errorf("fingerprint reached the verifier as %q", got)
	}
}

// ⛔⛔ TestSourcePinWarnsWhenAKeyringIsASet. A file holding many keys and no
// --fingerprint answers "somebody in that file signed it", which is the
// degradation Guix's --key-download=always produces in CI. Measured: the real
// GNU keyring holds 326+ primary keys.
func TestSourcePinWarnsWhenAKeyringIsASet(t *testing.T) {
	many := aPin
	many.KeysRead = 326
	_, out, _ := signedPin(t, many, nil, []byte("key"), nil,
		"--sig", "auto", "--key", "gnu-keyring.gpg", "--key-source", "p", "https://x/y.tar.gz")
	for _, want := range []string{"326 key(s) read", "somebody in that", "--fingerprint " + aPin.Fingerprint} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not warn with %q:\n%s", want, out)
		}
	}

	// One key is already a choice: no warning.
	_, out, _ = signedPin(t, aPin, nil, []byte("key"), nil,
		"--sig", "auto", "--key", "one.asc", "--key-source", "p", "https://x/y.tar.gz")
	if strings.Contains(out, "somebody in that") {
		t.Errorf("a one-key file needs no warning:\n%s", out)
	}

	// And with a fingerprint named, the narrowing is reported instead.
	narrowed := aPin
	narrowed.KeysScanned = 326
	_, out, _ = signedPin(t, narrowed, nil, []byte("key"), nil,
		"--sig", "auto", "--key", "gnu-keyring.gpg", "--key-source", "p",
		"--fingerprint", aPin.Fingerprint, "https://x/y.tar.gz")
	if !strings.Contains(out, "walking 326 primary key(s)") {
		t.Errorf("the narrowed read must say how far it walked:\n%s", out)
	}
	if strings.Contains(out, "somebody in that") {
		t.Errorf("a named fingerprint needs no warning:\n%s", out)
	}
}

// An explicit --sig URL is passed through unchanged: `auto` is a convenience,
// not a rewrite of whatever the author typed.
func TestSourcePinExplicitSigURLIsNotRewritten(t *testing.T) {
	var got []string
	wasV, wasK := fetchVerified, readKeyFile
	fetchVerified = func(_ string, cands []string, _ []byte, _ string) (fetch.SourcePin, error) {
		got = cands
		return aPin, nil
	}
	readKeyFile = func(string) ([]byte, error) { return []byte("key"), nil }
	t.Cleanup(func() { fetchVerified, readKeyFile = wasV, wasK })
	var out, errb bytes.Buffer
	runSourcePin([]string{"--sig", "https://elsewhere/sigs/y.sign", "--key", "k.asc",
		"--key-source", "p", "https://x/y.tar.gz"}, &out, &errb)
	if len(got) != 1 || got[0] != "https://elsewhere/sigs/y.sign" {
		t.Errorf("candidates = %v", got)
	}
}

// ⛔ THE UNSIGNED PATH SAYS SO, EVERY TIME. 1 upstream recipe in 904 pins a
// checksum and exactly one names a `sig:` (go-zpkg/zbk#282): an author who
// never hears that a signature might exist will not look for one.
func TestSourcePinUnsignedSaysWhatIsMissing(t *testing.T) {
	_, out, _ := sourcePin(t, aDigest, 10, nil, "https://x/y.tar.gz")
	if !strings.Contains(out, "Nothing says WHO produced these bytes") {
		t.Errorf("the unsigned path must name what it cannot tell you:\n%s", out)
	}
}

// Through the top-level dispatch, which is the only thing anybody types.
func TestSourcePinDispatch(t *testing.T) {
	was := fetchDigest
	fetchDigest = func(string) (string, int64, error) { return aDigest, 7, nil }
	t.Cleanup(func() { fetchDigest = was })
	var out, errb bytes.Buffer
	if code := run([]string{"sourcepin", "--version", "1.0", "https://x/y.tar.gz"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), aDigest) {
		t.Errorf("want the digest on stdout:\n%s", out.String())
	}
}
