package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
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
