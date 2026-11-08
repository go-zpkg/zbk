package fetch

import (
	"bytes"
	"compress/gzip"
	"errors"
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
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key))
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
		[]string{srv.URL + "/x.tar.gz.asc"}, binaryPublicKey(t, key))
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
		armoredPublicKey(t, key))
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
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key))
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
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key)); err == nil {
		t.Fatal("a signature over other bytes was accepted")
	}
}

// TestDigestVerifiedRefusals walks the input and transport failures.
func TestDigestVerifiedRefusals(t *testing.T) {
	key := testKey(t)
	body := tinyGz(t, "the source")
	good := armoredPublicKey(t, key)

	t.Run("no candidate", func(t *testing.T) {
		if _, err := DigestVerified("http://x/a.tar.gz", nil, good); err == nil ||
			!strings.Contains(err.Error(), "no signature URL") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("empty keyring", func(t *testing.T) {
		_, err := DigestVerified("http://x/a.tar.gz", []string{"http://x/a.asc"}, nil)
		if err == nil || !strings.Contains(err.Error(), "never let a keyserver choose it") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the key file is not a key", func(t *testing.T) {
		_, err := DigestVerified("http://x/a.tar.gz", []string{"http://x/a.asc"},
			[]byte("this is a README, not a key"))
		if err == nil || !strings.Contains(err.Error(), "neither an armored nor a binary") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the archive cannot be pinned", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html>not an archive</html>"))
		}))
		defer srv.Close()
		if _, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, good); err == nil {
			t.Fatal("a page served with 200 was pinned")
		}
	})

	t.Run("every candidate is a 404", func(t *testing.T) {
		srv := signedServer(t, body, nil)
		_, err := DigestVerified(srv.URL+"/x.tar.gz",
			[]string{srv.URL + "/a.asc", srv.URL + "/a.sig"}, good)
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
			[]string{srv.URL + "/x.tar.gz.asc", srv.URL + "/x.tar.gz.sig"}, good)
		if err == nil || !strings.Contains(err.Error(), "503") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "fact about the project") {
			t.Error("an outage was reported as an absence")
		}
	})

	t.Run("an empty signature", func(t *testing.T) {
		srv := signedServer(t, body, map[string][]byte{"/x.tar.gz.asc": {}})
		_, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, good)
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
		_, err := DigestVerified(srv.URL+"/x.tar.gz", []string{srv.URL + "/x.tar.gz.asc"}, good)
		if err == nil || !strings.Contains(err.Error(), "read signature") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the signature cannot be fetched at all", func(t *testing.T) {
		srv := signedServer(t, body, nil)
		_, err := DigestVerified(srv.URL+"/x.tar.gz", []string{"http://127.0.0.1:1/a.asc"}, good)
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
		[]string{srv.URL + "/x.tar.gz.asc"}, armoredPublicKey(t, key))
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
	if _, err := readKeyring(buf.Bytes()); err == nil {
		t.Fatal("an armoured non-key was accepted as a keyring")
	}
}

// FuzzReadKeyring: a key file is attacker-adjacent input — it is whatever the
// author downloaded — and this is the parser in front of it. No crash, ever.
func FuzzReadKeyring(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"))
	f.Add([]byte{0x99, 0x00, 0x01, 0x04})
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, err := readKeyring(b)
		if err == nil && len(keys) == 0 {
			t.Error("readKeyring returned no keys and no error — a caller would verify against nothing")
		}
	})
}
