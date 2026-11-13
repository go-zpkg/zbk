package fetch

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"time"

	gogit "github.com/go-git/go-git/v5"

	"github.com/go-zpkg/zpkb/useragent"
)

// osWriteFlags is how extracted regular files are opened.
const osWriteFlags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC

// Injectable seams over the network, process and os operations whose error
// branches are otherwise unreachable in a test (a successful syscall that
// then fails is not reproducible with real files). Tests override these to
// exercise every error-handling path; production uses the real functions
// verbatim.
var (
	// httpGet, not http.Get: Go's default User-Agent is REJECTED outright by
	// some hosts — sourceforge answers "Go-http-client/2.0" with a 403 — and
	// `versions` already learned that for the listing path. A download that
	// cannot fetch what the listing just found is the same bug twice.
	httpGet       = getWithAgent
	httpDo        = doWithAgent
	osCreateTemp  = os.CreateTemp
	osRemove      = os.Remove
	gitPlainClone = gogit.PlainClone
	osRemoveAll   = os.RemoveAll
	osMkdirAll    = os.MkdirAll
	osOpen        = os.Open
	osSymlink     = os.Symlink
	osOpenFile    = os.OpenFile
	osChtimes     = os.Chtimes
	ioCopy        = io.Copy
	// A SEPARATE seam for the download body: a test that injects a copy failure
	// for the extractor must not also break the download, which retries.
	ioCopyBody = io.Copy
	// And a third, for the source digest: a test that makes hashing fail must
	// not also break the extractor it is meant to leave alone.
	ioCopyHash = io.Copy
	// Same reasoning for the handle: the downloaded file is opened twice, once
	// to digest it and once to extract it, and those are different failures.
	// One seam for both would make a test of either a test of neither.
	osOpenHash = os.Open
	// And a fourth for Digest's size report: a test that makes the stat fail
	// must not break the extractor's own handling of the same file.
	osStatFetched = os.Stat
	zipOpen       = defaultZipOpen
	// sleepFn paces the retry backoff; a test sets it to a no-op so the suite
	// does not actually wait out three seconds of it.
	sleepFn = time.Sleep
)

// defaultZipOpen opens a file inside a zip archive for reading.
func defaultZipOpen(f *zip.File) (io.ReadCloser, error) {
	return f.Open()
}

// getWithAgent is http.Get with bk's User-Agent.
func getWithAgent(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return doWithAgent(req)
}

// doWithAgent sends req with bk's User-Agent, unless the caller set one.
func doWithAgent(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", useragent.String)
	}
	return http.DefaultClient.Do(req)
}
