package fetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// gzEmpty is a minimal, valid gzip member: download()'s magic check looks at
// the first bytes for a .tar.gz, so the body has to actually be one.
var gzEmpty = []byte{0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func TestDigestReturnsTheDigestAndTheSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzEmpty)
	}))
	defer srv.Close()

	got, size, err := Digest(srv.URL + "/x.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(gzEmpty)
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("digest = %s, want %s", got, want)
	}
	if size != int64(len(gzEmpty)) {
		t.Errorf("size = %d, want %d", size, len(gzEmpty))
	}
}

// ⛔⛔ THE WHOLE POINT: A FAILING FETCH YIELDS NO DIGEST. Hashing the body of a
// 504 is how a recipe gets pinned to an error page — 92 bytes that hash like
// anything else — and a wrong pin is worse than none, because a pinned recipe
// is fail-closed and the pin looks authoritative.
func TestDigestRefusesToHashAFailedFetch(t *testing.T) {
	was := sleepFn
	sleepFn = func(time.Duration) {}
	defer func() { sleepFn = was }()

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	got, size, err := Digest(srv.URL + "/x.tar.gz")
	if err == nil {
		t.Fatalf("a 504 must not produce a digest, got %q", got)
	}
	if got != "" || size != 0 {
		t.Errorf("nothing may come back on failure: %q %d", got, size)
	}
	if !strings.Contains(err.Error(), "504") {
		t.Errorf("the error must name what the host said: %v", err)
	}
	// And a 5xx is retried rather than taken as an answer, which is the other
	// half of why this is not `curl | shasum`.
	if hits < 2 {
		t.Errorf("a 5xx must be retried, got %d request(s)", hits)
	}
}

// A 200 carrying something that is not the archive is the shape a status check
// cannot see. download()'s magic check catches it; Digest inherits that, so a
// recipe cannot be pinned to a captcha page either.
func TestDigestRefusesAPageServedWithTwoHundred(t *testing.T) {
	was := sleepFn
	sleepFn = func(time.Duration) {}
	defer func() { sleepFn = was }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Please verify you are human</body></html>"))
	}))
	defer srv.Close()

	if got, _, err := Digest(srv.URL + "/x.tar.gz"); err == nil {
		t.Errorf("an HTML page served as a .tar.gz must not be pinned: %q", got)
	}
}

func TestDigestWhenTheFileCannotBeHashed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzEmpty)
	}))
	defer srv.Close()

	was := ioCopyHash
	ioCopyHash = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("read: I/O error") }
	defer func() { ioCopyHash = was }()

	if _, _, err := Digest(srv.URL + "/x.tar.gz"); err == nil {
		t.Error("a hashing failure must be reported, not rounded to an empty digest")
	}
}

func TestDigestWhenTheSizeCannotBeRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzEmpty)
	}))
	defer srv.Close()

	was := osStatFetched
	osStatFetched = func(string) (os.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: "x", Err: errors.New("gone")}
	}
	defer func() { osStatFetched = was }()

	_, _, err := Digest(srv.URL + "/x.tar.gz")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), srv.URL) {
		t.Errorf("the error must name the URL it was fetching: %v", err)
	}
}
