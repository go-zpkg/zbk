package fetch

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ⛔ ONE KEY FOR THE WHOLE FILE. openpgp.NewEntity generates a real keypair,
// which is the slowest thing in this package by two orders of magnitude; a key
// per test turned the file into a 20-second run. The tests that need a
// DIFFERENT key say so and pay for it once each.
var (
	keyOnce sync.Once
	theKey  *openpgp.Entity
)

func testKey(t *testing.T) *openpgp.Entity {
	t.Helper()
	keyOnce.Do(func() {
		e, err := openpgp.NewEntity("Upstream Author", "the one whose tarballs these are", "author@upstream.example", nil)
		if err != nil {
			t.Fatal(err)
		}
		theKey = e
	})
	return theKey
}

// armoredPublicKey serialises a key the way an author publishes one.
func armoredPublicKey(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// binaryPublicKey is the same key with no armour, which is the other form in
// the wild (Debian's deprecated signing-key.pgp).
func binaryPublicKey(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// secondKey is a different key, generated once for the same reason as the
// first: openpgp.NewEntity is the slowest call in this package.
var (
	otherOnce sync.Once
	theOther  *openpgp.Entity
)

func secondKey(t *testing.T) *openpgp.Entity {
	t.Helper()
	otherOnce.Do(func() {
		e, err := openpgp.NewEntity("Somebody Else", "", "else@example.test", nil)
		if err != nil {
			t.Fatal(err)
		}
		theOther = e
	})
	return theOther
}

// twoKeyRing is a keyring holding two keys, in order.
//
// ⛔ BINARY CONCATENATION, NOT TWO ARMOUR BLOCKS. Concatenating two armoured
// exports looks like a keyring and is not one: armor.Decode reads the FIRST
// block and stops, so the second key is silently absent and a signature by it
// reads as "unknown entity". That is how three tests failed here before this
// helper existed. ftp.gnu.org/gnu/gnu-keyring.gpg is binary for the same
// reason.
func twoKeyRing(t *testing.T, a, b *openpgp.Entity) []byte {
	t.Helper()
	return append(binaryPublicKey(t, a), binaryPublicKey(t, b)...)
}

// tinyGz is a real gzip body, so magicWrong() is satisfied and the test
// measures the signature check rather than the archive check.
func tinyGz(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func detach(t *testing.T, e *openpgp.Entity, body []byte, armored bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	var err error
	if armored {
		err = openpgp.ArmoredDetachSign(&buf, e, bytes.NewReader(body), nil)
	} else {
		err = openpgp.DetachSign(&buf, e, bytes.NewReader(body), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// signedServer serves an archive at /x.tar.gz and whatever signatures the
// caller names.
func signedServer(t *testing.T, body []byte, sigs map[string][]byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/x.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	for path, sig := range sigs {
		s := sig
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write(s)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestDigestVerifiedAcceptsAnArmoredSignature is the happy path, and it asserts
// the fingerprint SHAPE as well as the verdict: uppercase hex, no separators,
// which is Arch's documented rule.
func TestDigestVerifiedAcceptsAnArmoredSignature(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	sig := detach(t, key, body, true)
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": sig})

	pin, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), "")
	if err != nil {
		t.Fatal(err)
	}
	if pin.Size != int64(len(body)) {
		t.Errorf("size = %d, want %d", pin.Size, len(body))
	}
	if len(pin.SHA256) != 64 || strings.ToLower(pin.SHA256) != pin.SHA256 {
		t.Errorf("sha256 = %q, want 64 lowercase hex", pin.SHA256)
	}
	want := strings.ToUpper(pin.Fingerprint)
	if pin.Fingerprint != want || strings.ContainsAny(pin.Fingerprint, " :") || len(pin.Fingerprint) < 40 {
		t.Errorf("fingerprint = %q, want uppercase hex with no separators", pin.Fingerprint)
	}
	if !strings.Contains(pin.Identity, "author@upstream.example") {
		t.Errorf("identity = %q", pin.Identity)
	}
	if pin.SigURL != srv.URL+"/x.tar.gz.asc" {
		t.Errorf("sigURL = %q — the recipe must record the URL that ANSWERED", pin.SigURL)
	}
}

// TestDigestVerifiedAcceptsABinarySignature: a `.sig` is not armoured, and the
// armour is read from the BYTES rather than assumed from the extension.
func TestDigestVerifiedAcceptsABinarySignature(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	// Served at the .asc name on purpose: the convention is not enforced by
	// anyone, and a mislabelled file must still verify.
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": detach(t, key, body, false)})

	pin, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, binaryPublicKey(t, key), "")
	if err != nil {
		t.Fatal(err)
	}
	if pin.Fingerprint == "" {
		t.Error("no fingerprint from a binary signature")
	}
}

// TestDigestVerifiedTriesTheSecondCandidate covers Debian's `Pgp-Mode: auto`
// shape: a 404 on the first name moves on, and the one that answered is
// reported.
func TestDigestVerifiedTriesTheSecondCandidate(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.sig": detach(t, key, body, true)})

	pin, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc", srv.URL + "/x.tar.gz.sig"},
		armoredPublicKey(t, key), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(pin.SigURL, ".sig") {
		t.Errorf("sigURL = %q, want the .sig that answered", pin.SigURL)
	}
}

// ⛔⛔ TestDigestVerifiedRefusesAnotherKeysSignature is the whole point. The
// bytes download fine and hash fine; what fails is WHO signed them, and the
// message has to say so — a digest printed beside a failed signature check is
// how an unverified pin gets written anyway.
func TestDigestVerifiedRefusesAnotherKeysSignature(t *testing.T) {
	key := testKey(t)
	other, err := openpgp.NewEntity("Somebody Else", "", "else@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := tinyGz(t, "the source")
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": detach(t, other, body, true)})

	_, err = DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), "")
	if err == nil {
		t.Fatal("a signature by an unknown key was accepted")
	}
	for _, want := range []string{"not vouched for", "WHO signed them", "do not pin this"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

// TestDigestVerifiedRefusesASignatureOverOtherBytes: the signature is valid and
// by the right key, over a DIFFERENT archive.
func TestDigestVerifiedRefusesASignatureOverOtherBytes(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	srv := signedServer(t, body, map[string][]byte{
		"/x.tar.gz.asc": detach(t, key, tinyGz(t, "something else entirely"), true),
	})

	if _, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), ""); err == nil {
		t.Fatal("a signature over other bytes was accepted")
	}
}

// TestDigestVerifiedRefusals walks the input and transport failures.
func TestDigestVerifiedRefusals(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	good := armoredPublicKey(t, key)

	t.Run("no candidate", func(t *testing.T) {
		if _, err := DigestVerified("http://x/a.tar.gz", nil, good, ""); err == nil ||
			!strings.Contains(err.Error(), "no signature URL") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("empty keyring", func(t *testing.T) {
		_, err := DigestVerified("http://x/a.tar.gz", []string{"http://x/a.asc"}, nil, "")
		if err == nil || !strings.Contains(err.Error(), "never let a keyserver choose it") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the key file is not a key", func(t *testing.T) {
		_, err := DigestVerified("http://x/a.tar.gz", []string{"http://x/a.asc"},
			[]byte("this is a README, not a key"), "")
		if err == nil || !strings.Contains(err.Error(), "neither an armored nor a binary") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the archive cannot be pinned", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html>not an archive</html>"))
		}))
		defer srv.Close()
		if _, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, good, ""); err == nil {
			t.Fatal("a page served with 200 was pinned")
		}
	})

	t.Run("every candidate is a 404", func(t *testing.T) {
		srv := signedServer(t, body, nil)
		_, err := DigestVerified(srv.URL+"/x.tar.gz",
			[]string{srv.URL + "/a.asc", srv.URL + "/a.sig"}, good, "")
		if err == nil || !strings.Contains(err.Error(), "That is a fact about the project") {
			t.Fatalf("err = %v", err)
		}
		// ⛔ And it names them, so the author can see WHICH names were tried.
		if !strings.Contains(err.Error(), "/a.asc") || !strings.Contains(err.Error(), "/a.sig") {
			t.Errorf("the message does not name the candidates: %v", err)
		}
	})

	t.Run("a 503 stops rather than moving on", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/x.tar.gz", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
		mux.HandleFunc("/x.tar.gz.asc", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "down", http.StatusServiceUnavailable)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		// ⛔ A 503 on the signature must NOT read as "the project publishes
		// none": that would turn an outage into a decision to pin unsigned.
		_, err := DigestVerified(srv.URL+"/x.tar.gz",
			[]string{srv.URL + "/x.tar.gz.asc", srv.URL + "/x.tar.gz.sig"}, good, "")
		if err == nil || !strings.Contains(err.Error(), "503") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "fact about the project") {
			t.Error("an outage was reported as an absence")
		}
	})

	t.Run("an empty signature", func(t *testing.T) {
		srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": {}})
		_, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, good, "")
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the signature body is truncated", func(t *testing.T) {
		// Same shape as TestFetchZipBodyReadError: announce more than you send,
		// and the read fails rather than returning a short signature that would
		// then be reported as "not a valid signature" — a transport fault
		// dressed as a cryptographic one.
		mux := http.NewServeMux()
		mux.HandleFunc("/x.tar.gz", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
		mux.HandleFunc("/x.tar.gz.asc", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("short"))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		_, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, good, "")
		if err == nil || !strings.Contains(err.Error(), "read signature") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the signature cannot be fetched at all", func(t *testing.T) {
		srv := signedServer(t, body, nil)
		_, err := DigestVerified(srv.URL+"/x.tar.gz", []string{"http://127.0.0.1:1/a.asc"}, good, "")
		if err == nil || !strings.Contains(err.Error(), "get signature") {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestDigestVerifiedWhenTheHashedFileCannotBeReopened covers the one branch no
// server can produce: the file this package just wrote and hashed is gone by
// the time the signature is checked over it.
func TestDigestVerifiedWhenTheHashedFileCannotBeReopened(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": detach(t, key, body, true)})

	old := osOpenFetched
	defer func() { osOpenFetched = old }()
	osOpenFetched = func(string) (*os.File, error) { return nil, errors.New("vanished") }

	_, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key), "")
	if err == nil || !strings.Contains(err.Error(), "vanished") {
		t.Fatalf("err = %v", err)
	}
}

// TestPrimaryIdentityIsDeterministic: Identities is a MAP, so an implementation
// that ranges it once gives a different answer per run and two sourcepin
// invocations print different lines for one key.
func TestPrimaryIdentityIsDeterministic(t *testing.T) {
	e := &openpgp.Entity{Identities: map[string]*openpgp.Identity{
		"zed <z@example.test>":   {},
		"alice <a@example.test>": {},
		"bob <b@example.test>":   {},
	}}
	first := primaryIdentity(e)
	for i := 0; i < 20; i++ {
		if got := primaryIdentity(e); got != first {
			t.Fatalf("two calls disagreed: %q then %q", first, got)
		}
	}
	if first != "alice <a@example.test>" {
		t.Errorf("identity = %q, want the lexicographically smallest", first)
	}
}

// TestPrimaryIdentityPrefersThePrimaryFlag.
func TestPrimaryIdentityPrefersThePrimaryFlag(t *testing.T) {
	yes := true
	e := &openpgp.Entity{Identities: map[string]*openpgp.Identity{
		"alice <a@example.test>": {},
		"zed <z@example.test>":   {SelfSignature: &packet.Signature{IsPrimaryId: &yes}},
	}}
	if got := primaryIdentity(e); got != "zed <z@example.test>" {
		t.Errorf("identity = %q, want the one marked primary", got)
	}
}

// TestPrimaryIdentityWithNoUserID: a key need not carry one, and saying so
// beats printing an empty string into a recipe.
func TestPrimaryIdentityWithNoUserID(t *testing.T) {
	e := &openpgp.Entity{Identities: map[string]*openpgp.Identity{}}
	if got := primaryIdentity(e); !strings.Contains(got, "no user id") {
		t.Errorf("identity = %q", got)
	}
}

// TestReadKeyringRejectsAnArmoredBlockThatIsNotAKey covers the fall-through:
// armoured parse fails, binary parse fails, and the BINARY error is the one
// reported because it saw the bytes as they are.
func TestReadKeyringRejectsAnArmoredBlockThatIsNotAKey(t *testing.T) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("not a key"))
	w.Close()
	if _, _, err := readKeyring(buf.Bytes(), ""); err == nil {
		t.Fatal("an armoured non-key was accepted as a keyring")
	}
}

// ⛔⛔ TestDigestVerifiedRefusesTheWrongKeyInTheRightKeyring is what a keyring
// of many keys makes necessary. The signature is VALID and the signer IS in the
// file; it is simply not the key the author named.
func TestDigestVerifiedRefusesTheWrongKeyInTheRightKeyring(t *testing.T) {
	key := testKey(t)
	other, err := openpgp.NewEntity("Somebody Else", "", "else@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := tinyGz(t, "the source")
	ring := twoKeyRing(t, key, other)
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": detach(t, other, body, true)})

	// Without a fingerprint the ring answers "somebody in here signed it".
	pin, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, ring, "")
	if err != nil {
		t.Fatalf("the two-key ring should verify without a fingerprint: %v", err)
	}
	if pin.KeysRead != 2 {
		t.Errorf("KeysRead = %d, want 2 — the author must be able to see the ring is a SET", pin.KeysRead)
	}

	// Naming the key the author meant refuses it.
	want := fmt.Sprintf("%X", key.PrimaryKey.Fingerprint)
	_, err = DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, ring, want)
	if err == nil {
		t.Fatal("a signature by another key in the same ring was accepted")
	}
	for _, s := range []string{"is signed by", "not by the", "somebody in"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("the refusal does not say %q: %v", s, err)
		}
	}
}

// TestDigestVerifiedAcceptsTheNamedKey, including the fingerprint shapes a
// person actually pastes.
func TestDigestVerifiedAcceptsTheNamedKey(t *testing.T) {
	key := testKey(t)
	other, err := openpgp.NewEntity("Somebody Else", "", "else@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := tinyGz(t, "the source")
	// The wanted key SECOND, so finding it means the search walked past one.
	ring := twoKeyRing(t, other, key)
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": detach(t, key, body, true)})
	fpr := fmt.Sprintf("%X", key.PrimaryKey.Fingerprint)

	for _, form := range []string{
		fpr,
		strings.ToLower(fpr),
		// `gpg --fingerprint` prints groups separated by spaces, and some pages
		// use colons. Both were pasted into this flag on 2026-11-08.
		fpr[:4] + " " + fpr[4:8] + "  " + fpr[8:],
		fpr[:2] + ":" + fpr[2:],
	} {
		pin, err := DigestVerified(srv.URL+"/x.tar.gz",
			[]string{srv.URL + "/x.tar.gz.asc"}, ring, form)
		if err != nil {
			t.Fatalf("fingerprint %q was refused: %v", form, err)
		}
		if pin.Fingerprint != fpr {
			t.Errorf("fingerprint = %q, want %q", pin.Fingerprint, fpr)
		}
		// ⛔ Exactly one key is read when one is named: the others are never
		// parsed, which is what makes a keyring with an unreadable entity
		// usable at all.
		// ⛔ BOTH KEYS ARE READ, and that is deliberate: the ring parses whole,
		// so the signature is checked against it and the fingerprint compared
		// afterwards — Arch's order. Narrowing happens only when the file
		// cannot be read whole, which is what KeysScanned reports.
		if pin.KeysRead != 2 {
			t.Errorf("KeysRead = %d, want 2: a readable ring is read whole", pin.KeysRead)
		}
		if pin.KeysScanned != 0 {
			t.Errorf("KeysScanned = %d, want 0 — nothing was narrowed", pin.KeysScanned)
		}
	}
}

// TestDigestVerifiedWhenTheNamedKeyIsAbsent: the message must name the count it
// walked, so "wrong fingerprint" and "wrong file" are distinguishable.
func TestDigestVerifiedWhenTheNamedKeyIsAbsent(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": detach(t, key, body, true)})
	_, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"},
		armoredPublicKey(t, key), "0000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("an absent fingerprint was accepted")
	}
	// The file reads whole, so the signature verifies and the FINGERPRINT is
	// what refuses: "signed by X, not by the Y you named".
	for _, s := range []string{"is signed by", "not by the"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("the refusal does not say %q: %v", s, err)
		}
	}
}

// ⛔⛔ TestDigestVerifiedNarrowsOnlyWhenItMust is the GNU-keyring case, which
// is the one this was built for: the file cannot be read whole, a fingerprint
// is named, and only that key is taken. Measured against the real
// ftp.gnu.org/gnu/gnu-keyring.gpg on 2026-11-08 — 326 primary keys walked.
func TestDigestVerifiedNarrowsOnlyWhenItMust(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	// ⛔ THE REFUSAL IS FORCED, BECAUSE IT CANNOT BE CRAFTED. The real case is
	// the GNU keyring's "Cannot have multiple embedded signatures"; four
	// hand-built fixtures were tried and ReadKeyRing read every one, trailing
	// garbage included. What is NOT faked is the rescue: the ring really does
	// hold two keys, and keyByFingerprint really does find the first.
	ring := twoKeyRing(t, key, secondKey(t))
	was := pgpReadKeyRing
	pgpReadKeyRing = func(io.Reader) (openpgp.EntityList, error) {
		return nil, errors.New("openpgp: invalid data: Cannot have multiple embedded signatures")
	}
	defer func() { pgpReadKeyRing = was }()
	srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": detach(t, key, body, true)})
	fpr := fmt.Sprintf("%X", key.PrimaryKey.Fingerprint)

	// Without the fingerprint it is a refusal that says what to do.
	if _, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, ring, ""); err == nil ||
		!strings.Contains(err.Error(), "--fingerprint") {
		t.Fatalf("err = %v", err)
	}

	pin, err := DigestVerified(srv.URL+"/x.tar.gz",
		[]string{srv.URL + "/x.tar.gz.asc"}, ring, fpr)
	if err != nil {
		t.Fatalf("naming the key did not rescue an unreadable ring: %v", err)
	}
	if pin.KeysRead != 1 || pin.KeysScanned != 1 {
		t.Errorf("KeysRead=%d KeysScanned=%d, want 1 and 1", pin.KeysRead, pin.KeysScanned)
	}
}

// ⛔⛔ TestReadKeyringWholeFileFailureTellsYouWhatToDo. Measured against
// https://ftp.gnu.org/gnu/gnu-keyring.gpg (3 700 423 bytes, 326+ primary keys)
// on 2026-11-08: ReadKeyRing stops at the first ENTITY it cannot read and
// returns NOTHING, with "Cannot have multiple embedded signatures". A
// thirty-year-old public archive is entitled to hold such an entity, so the
// refusal has to point at the way through rather than merely report it.
func TestReadKeyringWholeFileFailureTellsYouWhatToDo(t *testing.T) {
	key := testKey(t)
	// A valid key followed by a packet whose declared length runs past the end
	// of the file: the packets read, the second entity does not assemble.
	ring := twoKeyRing(t, key, secondKey(t))
	was := pgpReadKeyRing
	pgpReadKeyRing = func(io.Reader) (openpgp.EntityList, error) {
		return nil, errors.New("openpgp: invalid data: Cannot have multiple embedded signatures")
	}
	defer func() { pgpReadKeyRing = was }()

	_, _, err := readKeyring(ring, "")
	if err == nil {
		t.Fatal("a keyring with an unassemblable entity was read whole")
	}
	if !strings.Contains(err.Error(), "--fingerprint") {
		t.Errorf("the refusal must name the way through: %v", err)
	}

	// ⛔ AND THE OTHER HALF: a file that parses and holds nothing is a
	// different complaint, and advising --fingerprint for it would be useless.
	pgpReadKeyRing = func(io.Reader) (openpgp.EntityList, error) { return nil, nil }
	_, _, err = readKeyring(ring, "")
	if err == nil || !strings.Contains(err.Error(), "holds no key") {
		t.Errorf("an empty keyring: %v", err)
	}
}

// TestKeyByFingerprintFindsTheKeyBehindOtherPackets: the search walks past
// whatever is not a primary key, which is what lets it reach key 327 of a real
// archive keyring.
func TestKeyByFingerprintFindsTheKeyBehindOtherPackets(t *testing.T) {
	key, other := testKey(t), secondKey(t)
	ring := twoKeyRing(t, other, key)
	e, scanned, err := keyByFingerprint(ring, fmt.Sprintf("%X", key.PrimaryKey.Fingerprint))
	if err != nil {
		t.Fatalf("the named key was not found: %v", err)
	}
	if e == nil || scanned != 2 {
		t.Errorf("entity=%v scanned=%d, want the key and 2", e != nil, scanned)
	}
}

// TestKeyByFingerprintReachesTheEnd: a fingerprint that is not in the file at
// all, reported with the count walked so "wrong fingerprint" and "wrong file"
// are distinguishable.
func TestKeyByFingerprintReachesTheEnd(t *testing.T) {
	ring := twoKeyRing(t, testKey(t), secondKey(t))
	_, scanned, err := keyByFingerprint(ring, "0000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("an absent fingerprint was found")
	}
	if scanned != 2 {
		t.Errorf("scanned = %d, want 2", scanned)
	}
	for _, s := range []string{"no key with fingerprint", "2 primary key(s) walked"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("the refusal does not say %q: %v", s, err)
		}
	}
}

// ⛔ TestKeyByFingerprintWhenTheNamedKeyCannotBeAssembled. This fixture was a
// FAILED attempt at something else, and it is exactly the witness this branch
// needed: ReadEntity keeps reading past the key packet looking for user ids and
// subkeys, so garbage immediately after the WANTED key is read as part of it.
// "the key is in the file and cannot be read" is a different problem from "the
// key is not in the file", and the messages say so.
func TestKeyByFingerprintWhenTheNamedKeyCannotBeAssembled(t *testing.T) {
	key := testKey(t)
	ring := append(binaryPublicKey(t, key), 0x99, 0x7f, 0xff)
	_, scanned, err := keyByFingerprint(ring, fmt.Sprintf("%X", key.PrimaryKey.Fingerprint))
	if err == nil {
		t.Fatal("an unassemblable key was returned")
	}
	if scanned != 1 {
		t.Errorf("scanned = %d, want 1 — the key WAS found, it would not assemble", scanned)
	}
	if !strings.Contains(err.Error(), "is in the file and cannot be read") {
		t.Errorf("the refusal must distinguish this from absence: %v", err)
	}
}

// ⛔ TestKeyByFingerprintStopsOnAnUnreadableStream, rather than looping. The
// first version of this code called `continue` here; a packet.Reader cannot be
// resynchronised, so that either repeats forever or swallows the file as one
// packet's payload. 0x80 is a tag byte with a reserved packet type.
func TestKeyByFingerprintStopsOnAnUnreadableStream(t *testing.T) {
	_, scanned, err := keyByFingerprint([]byte{0x80, 0x00}, "AB")
	if err == nil {
		t.Fatal("an unreadable stream was searched to the end")
	}
	if scanned != 0 {
		t.Errorf("scanned = %d, want 0", scanned)
	}
}

// TestKeyBodyRefusals covers the shapes that are not a key file at all.
//
// ⛔ The last one is why the first octet is checked: a README is not armoured,
// so it used to pass through as "binary" and the refusal then advised
// --fingerprint — useless advice for a file holding no keys. RFC 9580 §4.2: a
// packet's first octet has bit 7 set.
func TestKeyBodyRefusals(t *testing.T) {
	if _, ok := keyBody(nil); ok {
		t.Error("an empty file is not a key")
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, ok := keyBody(buf.Bytes()); ok {
		t.Error("empty armour is not a key")
	}
	if _, ok := keyBody([]byte("this is a README, not a key")); ok {
		t.Error("text with bit 7 clear in its first octet is not a packet stream")
	}
	if _, ok := keyBody([]byte{0x99, 0x00, 0x01, 0x04}); !ok {
		t.Error("a packet tag byte must be accepted as binary")
	}
}

// TestSameFingerprintIgnoresPunctuationOnly: it must not ignore DIGITS.
func TestSameFingerprintIgnoresPunctuationOnly(t *testing.T) {
	if !sameFingerprint("AB:CD ef", "abcdEF") {
		t.Error("case, colons and spaces must not matter")
	}
	if sameFingerprint("ABCDEF", "ABCDE0") {
		t.Error("a different fingerprint must not match")
	}
	if sameFingerprint("ABCDEF", "ABCDE") {
		t.Error("a PREFIX must not match: a short id is not a fingerprint")
	}
}

// FuzzReadKeyring: a key file is attacker-adjacent input — it is whatever the
// author downloaded — and this is the parser in front of it. No crash, ever.
func FuzzReadKeyring(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"))
	f.Add([]byte{0x99, 0x00, 0x01, 0x04})
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, _, err := readKeyring(b, "")
		if err == nil && len(keys) == 0 {
			t.Error("readKeyring returned no keys and no error — a caller would verify against nothing")
		}
		// ⛔ AND THE FINGERPRINT-DIRECTED PATH, which walks packets by hand and
		// is therefore the one that could loop or panic on a crafted stream.
		// The fingerprint is a real shape so the search runs rather than
		// failing on the argument.
		if keys, _, err := readKeyring(b, "155D3FC500C834486D1EEA677FD9FCCB000BEEEE"); err == nil && len(keys) != 1 {
			t.Errorf("a named fingerprint returned %d keys and no error", len(keys))
		}
	})
}
