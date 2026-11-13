package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
	"github.com/go-zpkg/bottle"
)

// signHarness points the registry seams at memory and returns what was
// attached.
type signHarness struct {
	published string
	attached  []bottle.Referrer
	digestErr error
	attachErr error
}

func (h *signHarness) install(t *testing.T) {
	t.Helper()
	oldD, oldA := ociBottleDigest, ociAttach
	ociBottleDigest = func(_, _, _, _, _ string) (string, error) {
		return h.published, h.digestErr
	}
	ociAttach = func(_, _, _, _, _ string, rf bottle.Referrer) error {
		if h.attachErr != nil {
			return h.attachErr
		}
		h.attached = append(h.attached, rf)
		return nil
	}
	t.Cleanup(func() { ociBottleDigest, ociAttach = oldD, oldA })
}

// writeKeyAndBottle lays down a secret key file and a bottle, and returns the
// two paths plus the bottle's digest.
func writeKeyAndBottle(t *testing.T, body string) (keyPath, bottlePath, digest string, kp *sign.Keypair) {
	t.Helper()
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "k.sec")
	if err := os.WriteFile(keyPath, []byte(kp.SecretKeyFile("test")), 0o600); err != nil {
		t.Fatal(err)
	}
	bottlePath = filepath.Join(dir, "b.tar.gz")
	if err := os.WriteFile(bottlePath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return keyPath, bottlePath, "sha256:" + hex.EncodeToString(sum[:]), kp
}

func TestSignAttachesToAPublishedBottle(t *testing.T) {
	key, bot, digest, kp := writeKeyAndBottle(t, "identical-bytes")
	h := &signHarness{published: digest}
	h.install(t)

	var out, errb bytes.Buffer
	code := runSign([]string{
		"-key", key, "-project", "fftw.org", "-version", "3.3.11-h27o3ysxva6swayci",
		"-os", "linux", "-arch", "x86-64", "-to", "oci://example.test/x", bot,
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if len(h.attached) != 1 {
		t.Fatalf("attached %d referrers", len(h.attached))
	}
	rf := h.attached[0]
	if rf.ArtifactType != bottle.ArtifactTypeSignature {
		t.Errorf("artifact type %q", rf.ArtifactType)
	}
	// ⛔ THE SIGNATURE MUST VERIFY AGAINST THE SIGNER'S OWN KEY AND COMMIT TO
	// THE PUBLISHED DIGEST. Checking only that "something was attached" would
	// pass for a referrer that says nothing.
	ts := bottle.TrustSet{Signers: []bottle.Signer{{Name: "alice", Key: kp.PublicKeyString()}}, Threshold: 1}
	names, untrusted, err := ts.Count(digest, []bottle.Attestation{{
		Payload: rf.Blob,
		Sig:     rf.Annotations[bottle.CosignSignatureAnnotation],
		KeyID:   rf.Annotations[bottle.SignerKeyIDAnnotation],
	}})
	if err != nil || untrusted != 0 || strings.Join(names, ",") != "alice" {
		t.Fatalf("the attached signature does not verify: names=%v untrusted=%d err=%v", names, untrusted, err)
	}
	// The key id annotation must be the signer's, or it is worse than absent.
	id, _, err := sign.ParsePublicKey(kp.PublicKeyString())
	if err != nil {
		t.Fatal(err)
	}
	if got := rf.Annotations[bottle.SignerKeyIDAnnotation]; got != hex.EncodeToString(id[:]) {
		t.Errorf("key id annotation = %q", got)
	}
	// No name on the artefact: the reader's trust set names the signer.
	for k := range rf.Annotations {
		if strings.Contains(k, "name") {
			t.Errorf("the referrer carries a name annotation %q", k)
		}
	}
	if !strings.Contains(out.String(), "ZPKG_EXTRA_TRUSTED_KEYS") {
		t.Errorf("output should say how to trust this key:\n%s", out.String())
	}
}

// ⛔⛔ A DIVERGENCE IS THE FINDING, NOT A HICCUP. Signing a bottle this build
// did not produce is the one claim the threshold must never be able to make,
// so the refusal is the default and both digests are printed — "they differ"
// is not something anybody can act on.
func TestSignRefusesADifferentBuild(t *testing.T) {
	key, bot, mine, _ := writeKeyAndBottle(t, "my-bytes")
	const theirs = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	h := &signHarness{published: theirs}
	h.install(t)

	var out, errb bytes.Buffer
	code := runSign([]string{
		"-key", key, "-project", "fftw.org", "-version", "3.3.11",
		"-os", "linux", "-arch", "x86-64", bot,
	}, &out, &errb)
	if code == 0 {
		t.Fatal("a divergent rebuild was signed")
	}
	if len(h.attached) != 0 {
		t.Error("a signature was attached despite the refusal")
	}
	for _, want := range []string{theirs, mine, "zpkb reproduce", "-force"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("the refusal should mention %q:\n%s", want, errb.String())
		}
	}

	// -force signs the PUBLISHED bytes, and says so.
	out.Reset()
	errb.Reset()
	code = runSign([]string{
		"-key", key, "-project", "fftw.org", "-version", "3.3.11",
		"-os", "linux", "-arch", "x86-64", "-force", bot,
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("-force exit %d: %s", code, errb.String())
	}
	if len(h.attached) != 1 {
		t.Fatalf("-force attached %d referrers", len(h.attached))
	}
	if !strings.Contains(errb.String(), "-force given") {
		t.Errorf("-force should say it is overriding:\n%s", errb.String())
	}
}

// ⛔ THE DISPATCH IS ITS OWN FACT. `runSign` working says nothing about
// `zpkb sign` working: the switch in main.go is the only place that decides
// what a word on the command line does, and a subcommand that is implemented
// and not wired is invisible.
func TestSignIsWiredIntoTheDispatch(t *testing.T) {
	code, _, errb := run2(t, "sign")
	if code != 2 {
		t.Fatalf("`zpkb sign` with no arguments: code=%d err=%q", code, errb)
	}
	if !strings.Contains(errb, "usage: zpkb sign") {
		t.Errorf("the dispatch did not reach runSign: %q", errb)
	}
	if strings.Contains(errb, "unknown command") {
		t.Errorf("`sign` is not dispatched at all: %q", errb)
	}
}

// With no -os/-arch the host's platform is used — the common case, since a
// rebuilder is checking their own machine's output.
func TestSignDefaultsToThisHost(t *testing.T) {
	key, bot, digest, _ := writeKeyAndBottle(t, "host-default")
	h := &signHarness{published: digest}
	h.install(t)

	var out, errb bytes.Buffer
	code := runSign([]string{"-key", key, "-project", "p", "-version", "1", bot}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	wantOS, wantArch := bottle.HostSlug()
	if !strings.Contains(out.String(), "("+wantOS+"/"+wantArch+")") {
		t.Errorf("output does not name the host platform %s/%s:\n%s", wantOS, wantArch, out.String())
	}
}

// A payload that cannot be built is exit 1 with a message, never a silent
// success — the signature would otherwise be over nothing.
func TestSignReportsAPayloadFailure(t *testing.T) {
	key, bot, digest, _ := writeKeyAndBottle(t, "payload-fail")
	h := &signHarness{published: digest}
	h.install(t)
	old := simpleSigning
	simpleSigning = func(string, string) ([]byte, error) { return nil, os.ErrInvalid }
	t.Cleanup(func() { simpleSigning = old })

	var out, errb bytes.Buffer
	if code := runSign([]string{
		"-key", key, "-project", "p", "-version", "1", "-os", "linux", "-arch", "x86-64", bot,
	}, &out, &errb); code != 1 {
		t.Errorf("a failed payload = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "zpkb sign:") {
		t.Errorf("no message: %q", errb.String())
	}
}

// ⛔ THE SEAMS' REAL BODIES ARE EXERCISED TOO. A seam that only ever runs its
// test double is code nobody has executed — and these two are the ones that
// talk to the registry, so a typo in them fails only in production.
func TestSignSeamsRejectABadDist(t *testing.T) {
	if _, err := ociBottleDigest("https://not-oci", "p", "1", "linux", "x86-64"); err == nil {
		t.Error("ociBottleDigest accepted a non-oci dist")
	}
	if err := ociAttach("https://not-oci", "p", "1", "linux", "x86-64", bottle.Referrer{}); err == nil {
		t.Error("ociAttach accepted a non-oci dist")
	}
	// And a WELL-FORMED oci:// dist, so the call each seam exists to make is
	// actually made. A blackhole: the client builds, the request is refused
	// at once, and no test waits on DNS or reaches a real registry.
	const blackhole = "oci://127.0.0.1:1/nothing"
	if _, err := ociBottleDigest(blackhole, "p", "1", "linux", "x86-64"); err == nil {
		t.Error("ociBottleDigest reported success against a dead registry")
	}
	if err := ociAttach(blackhole, "p", "1", "linux", "x86-64", bottle.Referrer{}); err == nil {
		t.Error("ociAttach reported success against a dead registry")
	}
}

func TestSignUsageAndFailures(t *testing.T) {
	key, bot, digest, _ := writeKeyAndBottle(t, "x")

	// Missing required flags, and an unknown one, → usage, exit 2.
	for _, args := range [][]string{
		{},
		{"-no-such-flag"},
		{"-key", key, bot},
		{"-key", key, "-project", "p", bot},
		{"-key", key, "-project", "p", "-version", "1", bot, "extra"},
	} {
		var out, errb bytes.Buffer
		if code := runSign(args, &out, &errb); code != 2 {
			t.Errorf("runSign(%v) = %d, want 2", args, code)
		}
	}

	base := []string{"-key", key, "-project", "p", "-version", "1", "-os", "linux", "-arch", "x86-64"}

	// A missing key file, a missing bottle, a registry that will not answer,
	// and an attach that fails are all exit 1 with a message — never a
	// silent success.
	h := &signHarness{published: digest}
	h.install(t)
	var out, errb bytes.Buffer
	absentKey := append([]string{"-key", filepath.Join(t.TempDir(), "absent")}, base[2:]...)
	if code := runSign(append(absentKey, bot), &out, &errb); code != 1 {
		t.Errorf("missing key = %d, want 1", code)
	}
	errb.Reset()
	if code := runSign(append(append([]string{}, base...), filepath.Join(t.TempDir(), "absent.tar.gz")), &out, &errb); code != 1 {
		t.Errorf("missing bottle = %d, want 1", code)
	}

	h.digestErr = os.ErrNotExist
	errb.Reset()
	if code := runSign(append(append([]string{}, base...), bot), &out, &errb); code != 1 {
		t.Errorf("unreachable registry = %d, want 1", code)
	}
	h.digestErr = nil
	h.attachErr = os.ErrPermission
	errb.Reset()
	if code := runSign(append(append([]string{}, base...), bot), &out, &errb); code != 1 {
		t.Errorf("failed attach = %d, want 1", code)
	}
}
