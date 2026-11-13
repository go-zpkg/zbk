package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/zpkb/support"
)

// The real openssl shape, trimmed. `isMaintained: true` is left on the
// end-of-life lines on purpose: it is what the live API says, and the field
// this must not read.
const eolOpenSSL = `{"schema_version":"1.2.1","result":{"name":"openssl","label":"OpenSSL",
 "links":{"releasePolicy":"https://openssl-library.org/policies/releasestrat/index.html"},
 "releases":[
  {"name":"4.0","isLts":false,"isEol":false,"eolFrom":"2027-05-14","isMaintained":true,"latest":{"name":"4.0.3"}},
  {"name":"3.6","isLts":false,"isEol":false,"eolFrom":"2026-11-01","isMaintained":true,"latest":{"name":"3.6.5"}},
  {"name":"3.5","isLts":true,"isEol":false,"eolFrom":"2030-04-08","isMaintained":true,"latest":{"name":"3.5.9"}},
  {"name":"3.4","isLts":false,"isEol":true,"eolFrom":"2026-10-22","isMaintained":false,"latest":{"name":"3.4.8"}},
  {"name":"1.1.1","isLts":true,"isEol":true,"eolFrom":"2023-09-11","isMaintained":true,"latest":{"name":"1.1.1w"}}
 ]}}`

func withEOLSeams(t *testing.T, body string, ferr error, now string) {
	t.Helper()
	pf, pn := eolFetch, eolNow
	eolFetch = func(string) ([]byte, error) {
		if ferr != nil {
			return nil, ferr
		}
		return []byte(body), nil
	}
	at, err := time.Parse("2006-01-02", now)
	if err != nil {
		t.Fatal(err)
	}
	eolNow = func() time.Time { return at }
	t.Cleanup(func() { eolFetch, eolNow = pf, pn })
}

// ⛔ THE THREE VERDICTS THE REGISTRY EARNED ON THE DAY THIS WAS WRITTEN, and
// the destination that makes them actionable.
func TestEOLJudgesTheVersionsTheRegistryPublishes(t *testing.T) {
	withEOLSeams(t, eolOpenSSL, nil, "2026-10-29")
	code, out, errb := run2(t, "eol", "-product", "openssl", "3.4.7", "3.6.4", "3.5.8", "1.1.1w")
	if code != 0 {
		t.Fatalf("want 0 without -fail, got %d: %s", code, errb)
	}
	for _, want := range []string{
		"3.4.7        end-of-life",
		"3.6.4        expiring",
		"3.5.8        supported",
		"1.1.1w       end-of-life", // the isMaintained:true line
		"longest-supported openssl line: 3.5 (LTS), until 2030-04-08",
		"releasestrat",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output omits %q:\n%s", want, out)
		}
	}
}

// -fail is what a gate uses, and it must stay silent-green when everything is
// supported or a gate could never pass.
func TestEOLFailIsAVerdict(t *testing.T) {
	withEOLSeams(t, eolOpenSSL, nil, "2026-10-29")
	if code, _, _ := run2(t, "eol", "-product", "openssl", "-fail", "3.6.4"); code != 1 {
		t.Errorf("an expiring line with -fail: want 1, got %d", code)
	}
	if code, _, _ := run2(t, "eol", "-product", "openssl", "-fail", "3.5.8"); code != 0 {
		t.Errorf("a supported line with -fail: want 0, got %d", code)
	}
}

// ⛔ THE WINDOW DECIDES WHAT "EXPIRING" MEANS, and the default (90 days) is a
// choice, not a law. With no window at all, 3.6 is merely supported until the
// day it is not.
func TestEOLWindowIsTheCallersChoice(t *testing.T) {
	withEOLSeams(t, eolOpenSSL, nil, "2026-10-29")
	if _, out, _ := run2(t, "eol", "-product", "openssl", "-within", "1h", "3.6.4"); !strings.Contains(out, "supported") {
		t.Errorf("a one-hour window should not call 2026-11-01 expiring:\n%s", out)
	}
	// 2026-10-29 → 2027-05-14 is ~197 days, so 5000h (~208) reaches it and
	// 2400h (100 days) does not. Both are asserted, because a window that
	// reclassified everything would prove nothing about the boundary.
	if _, out, _ := run2(t, "eol", "-product", "openssl", "-within", "2400h", "4.0.2"); !strings.Contains(out, "supported") {
		t.Errorf("100 days does not reach 2027-05-14:\n%s", out)
	}
	if _, out, _ := run2(t, "eol", "-product", "openssl", "-within", "5000h", "4.0.2"); !strings.Contains(out, "expiring") {
		t.Errorf("208 days does reach 2027-05-14:\n%s", out)
	}
}

// A destination is only named when there is one. Everything over is worse news
// than any single finding.
func TestEOLSaysWhenNothingIsSupported(t *testing.T) {
	withEOLSeams(t, `{"result":{"name":"x","releases":[{"name":"1","isEol":true,"eolFrom":"2020-01-01"}]}}`, nil, "2026-10-29")
	_, out, _ := run2(t, "eol", "-product", "x", "1.2")
	if !strings.Contains(out, "no x line is still supported") {
		t.Errorf("output omits the bad news:\n%s", out)
	}
}

func TestEOLRefusesBadInput(t *testing.T) {
	withEOLSeams(t, eolOpenSSL, nil, "2026-10-29")
	for _, c := range []struct {
		what string
		args []string
	}{
		{"no product", []string{"eol", "3.6.4"}},
		{"no versions", []string{"eol", "-product", "openssl"}},
		{"an unknown flag", []string{"eol", "-nope"}},
	} {
		if code, _, _ := run2(t, c.args...); code != 2 {
			t.Errorf("%s: want 2, got %d", c.what, code)
		}
	}
}

func TestEOLReportsAFetchThatFailed(t *testing.T) {
	withEOLSeams(t, "", errors.New("no route to host"), "2026-10-29")
	code, _, errb := run2(t, "eol", "-product", "openssl", "3.6.4")
	if code != 1 {
		t.Fatalf("want 1, got %d", code)
	}
	if !strings.Contains(errb, "no route to host") {
		t.Errorf("the failure was not reported: %s", errb)
	}
}

func TestEOLReportsABodyItCannotRead(t *testing.T) {
	withEOLSeams(t, `{"result":{"name":"x","releases":[]}}`, nil, "2026-10-29")
	code, _, errb := run2(t, "eol", "-product", "x", "1.2")
	if code != 1 {
		t.Fatalf("want 1, got %d", code)
	}
	if !strings.Contains(errb, "not an answer") {
		t.Errorf("an empty product was not called a failure: %s", errb)
	}
}

// withBaseURL points fetchProduct at a test server.
func withBaseURL(t *testing.T, url string) {
	t.Helper()
	prev := eolBaseURL
	eolBaseURL = url
	t.Cleanup(func() { eolBaseURL = prev })
}

func TestFetchProductReadsAProductAndNamesItInTheURL(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("the request did not ask for JSON: %q", r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(eolOpenSSL))
	}))
	defer srv.Close()
	withBaseURL(t, srv.URL+"/api/v1/products/")

	body, err := fetchProduct("openssl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "/openssl") {
		t.Errorf("the product name did not reach the URL: %q", path)
	}
	if _, err := support.ParseProduct(body); err != nil {
		t.Errorf("what came back did not parse: %v", err)
	}
}

// ⛔ A 404 IS NOT AN EMPTY PRODUCT. endoflife.date answers an unknown name
// with a JSON error document that decodes happily into a struct with no
// releases, so a misspelled product would otherwise report "no line claims
// this version" for everything — a typo wearing the clothes of a measurement.
// The status is therefore checked BEFORE the body, and the error names the
// product so the typo is visible.
func TestFetchProductChecksTheStatusBeforeTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"product not found"}`))
	}))
	defer srv.Close()
	withBaseURL(t, srv.URL+"/api/v1/products/")

	_, err := fetchProduct("opensssl")
	if err == nil {
		t.Fatal("a 404 must be an error, not an empty product")
	}
	if !strings.Contains(err.Error(), "opensssl") {
		t.Errorf("the error does not name the product that was asked for: %v", err)
	}
}

func TestFetchProductReportsATransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing is listening now
	withBaseURL(t, srv.URL+"/api/v1/products/")
	if _, err := fetchProduct("openssl"); err == nil {
		t.Error("a dead server must be an error")
	}
}

func TestFetchProductRefusesAnUnbuildableRequest(t *testing.T) {
	if _, err := fetchProduct("\x7f"); err == nil {
		t.Error("an unbuildable request must be an error")
	}
}
