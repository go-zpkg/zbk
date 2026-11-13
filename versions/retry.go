package versions

import (
	"net/http"
	"time"

	"github.com/go-zpkg/zpkb/httpretry"
)

// sleepFn paces the retry backoff; a test sets it to a no-op.
var sleepFn = time.Sleep

// httpDoRetrying repeats a request whose host failed to answer.
//
// Resolving a version is one GET against whatever host the recipe names, and
// those hosts are not all well. Seven x.org recipes were lost in a single batch
// to `dial tcp 131.252.210.176:443: i/o timeout` — and that host is not down:
// three consecutive requests to it answered 200 in 8.2s, 200 in 2.4s, then
// timed out. Giving a flaky host exactly one chance reports our own bad luck as
// a recipe with no candidate version.
//
// A response that ARRIVED is returned as-is, whatever its status, except the
// two shapes that mean "not now": 429 and 5xx. A 404 is an answer.
func httpDoRetrying(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := httpDo(req)
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		if !httpretry.Transient(err, status) || attempt == httpretry.Attempts-1 {
			return resp, err
		}
		if resp != nil {
			// Drain nothing: the body is unread and about to be replaced.
			resp.Body.Close()
		}
		sleepFn(httpretry.Backoff(attempt))
	}
}
