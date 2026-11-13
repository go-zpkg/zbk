package fetch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/useragent"
)

// The download path must send bk's User-Agent. Go's default is rejected
// OUTRIGHT by some hosts — sourceforge answers "Go-http-client/2.0" with a 403
// — and this package used http.Get verbatim while `versions` had already set
// an agent for the listing path. bk could therefore LIST libisl's versions and
// then fail to DOWNLOAD the tarball it had just found.
func TestDownloadSendsOurUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		// Reject Go's default the way the host that forced this does, so the
		// test fails the same way production did rather than on a header string.
		if strings.HasPrefix(got, "Go-http-client") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	resp, err := httpGet(srv.URL + "/isl-0.28.tar.bz2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (User-Agent %q): the host refused us the way sourceforge did", resp.StatusCode, got)
	}
	if got != useragent.String {
		t.Errorf("User-Agent = %q, want %q", got, useragent.String)
	}
}

// The RANGE branch — a resumed download — goes through a different call, and
// must carry the agent too. A partial download that resumed with Go's default
// would fail only after the first attempt had succeeded, which is the hardest
// kind of bug to see.
func TestResumedDownloadSendsOurUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("rest"))
	}))
	defer srv.Close()

	resp, err := httpGetRange(srv.URL+"/x.tar.bz2", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got != useragent.String {
		t.Errorf("resumed request User-Agent = %q, want %q", got, useragent.String)
	}
}

// A caller that sets its own agent keeps it: this fills a gap, it does not
// take the header over.
func TestCallerAgentWins(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "something-else/1.0")
	resp, err := doWithAgent(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "something-else/1.0" {
		t.Errorf("User-Agent = %q, want the caller's", got)
	}
}

// A URL http.NewRequest itself rejects must come back as an error rather than
// a nil response: the caller dereferences what it is handed.
func TestGetWithAgentRejectsABadURL(t *testing.T) {
	resp, err := httpGet("://not a url")
	if err == nil {
		t.Fatal("want an error for a URL that cannot be parsed")
	}
	if resp != nil {
		t.Errorf("resp = %v, want nil alongside the error", resp)
	}
}
