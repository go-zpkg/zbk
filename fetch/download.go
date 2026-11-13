package fetch

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/go-zpkg/zpkb/httpretry"
	"io"
	"io/fs"
	"net/http"
	"syscall"
)

// downloadAttempts is how many times a truncated download is resumed before the
// fetch is called a failure. A source tarball is fetched once per build, so a
// handful of attempts costs nothing and can save the whole build.
const downloadAttempts = 5

// download streams url into a temporary file and returns its path. A body that
// stops early is RESUMED with a Range request rather than restarted, and the
// result is checked against the length the server announced.
//
// Streaming a response straight into the tar extractor — as this package used
// to — cannot recover from a truncated transfer: the extractor has already
// consumed and written part of the archive when the read fails, and the only
// signal is `unexpected EOF`. That is exactly how kernel.org/linux failed: a
// ~150 MB xz tarball, the largest source we fetch, cut mid-transfer. artifact
// learned the same lesson on artifact blobs (Range resume + retries); this is the
// source-side half of it.
func download(url string) (string, error) {
	f, err := osCreateTemp("", "bk-fetch-*")
	if err != nil {
		return "", fmt.Errorf("fetch: temp file: %w", err)
	}
	path := f.Name()
	var got, want int64

	for attempt := 0; attempt < downloadAttempts; attempt++ {
		resp, err := httpGetRange(url, got)
		if err != nil {
			// A host that fails to answer is not a broken recipe. Retry the
			// transient shapes — a timeout, a reset — and give up at once on an
			// error that is itself an answer (a bad URL, an unusable TLS identity).
			if httpretry.Transient(err, 0) && attempt < downloadAttempts-1 {
				sleepFn(httpretry.Backoff(attempt))
				continue
			}
			f.Close()
			osRemove(path)
			return "", fmt.Errorf("fetch: GET %s: %w", url, err)
		}
		switch resp.StatusCode {
		case http.StatusPartialContent:
			// The server honoured the Range: keep appending to what we have.
		case http.StatusOK:
			// It ignored the Range and is replaying the whole body, so start over
			// on a fresh file rather than append to a partial one.
			if got > 0 {
				f.Close()
				osRemove(path)
				nf, err := osCreateTemp("", "bk-fetch-*")
				if err != nil {
					resp.Body.Close()
					return "", fmt.Errorf("fetch: temp file: %w", err)
				}
				f, path, got, want = nf, nf.Name(), 0, 0
			}
		default:
			// 502/503 cost freetype.org and ijg.org a place in the catalogue on a
			// single unlucky draw. 5xx and 429 are the server failing to answer;
			// a 4xx is the server answering, and repeating it hides the message.
			if httpretry.Transient(nil, resp.StatusCode) && attempt < downloadAttempts-1 {
				resp.Body.Close()
				sleepFn(httpretry.Backoff(attempt))
				continue
			}
			resp.Body.Close()
			f.Close()
			osRemove(path)
			return "", fmt.Errorf("fetch: GET %s: %s", url, resp.Status)
		}
		if resp.ContentLength > 0 {
			want = got + resp.ContentLength
		}

		n, copyErr := ioCopyBody(f, resp.Body)
		resp.Body.Close()
		got += n
		if copyErr == nil && (want == 0 || got >= want) {
			// The transfer completed — but a mirror answering 200 with a page
			// instead of the archive completes too. pcre.org 8.45 failed a whole
			// factory run as "bzip2 data invalid: bad magic value" while both of
			// its URLs serve a perfectly good BZh9 tarball from another machine:
			// SourceForge had handed the runner something else. That is a
			// transient as surely as a timeout is, and it was the one shape the
			// retry loop could not see, because the status said 200.
			if magicWrong(url, path) && attempt < downloadAttempts-1 {
				f.Close()
				osRemove(path)
				nf, err := osCreateTemp("", "bk-fetch-*")
				if err != nil {
					return "", fmt.Errorf("fetch: temp file: %w", err)
				}
				f, path, got, want = nf, nf.Name(), 0, 0
				sleepFn(httpretry.Backoff(attempt))
				continue
			}
			f.Close()
			return path, nil
		}
		// A failure to WRITE is not a cut transfer. Retrying it wastes five
		// attempts and then blames the network for a local problem:
		//
		//   fetch: write .../build/.clang-format: no space left on device
		//   fetch: GET https://cdn.kernel.org/…/linux-6.13.9.tar.xz:
		//          still truncated after 5 attempts (148553728 of 148565212 bytes)
		//
		// Those are the same runner, minutes apart — the disk filled, and every
		// later download reported itself as truncated. The bytes had arrived;
		// there was nowhere to put them. Stop, and say which it was.
		if isWriteError(copyErr) {
			f.Close()
			osRemove(path)
			return "", fmt.Errorf("fetch: GET %s: cannot write the download: %w", url, copyErr)
		}
		// Truncated: loop and resume from exactly where this attempt stopped.
	}

	f.Close()
	osRemove(path)
	return "", fmt.Errorf("fetch: GET %s: still truncated after %d attempts (%d of %d bytes)",
		url, downloadAttempts, got, want)
}

// httpGetRange requests url, asking for everything from offset on when a
// previous attempt already stored some bytes.
func httpGetRange(url string, offset int64) (*http.Response, error) {
	if offset == 0 {
		return httpGet(url)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	return httpDo(req)
}

// isWriteError reports whether err came from writing the download to disk
// rather than from reading it off the network.
//
// io.Copy returns the two indistinguishably, so the distinction has to be made
// on the error itself. A full disk, a read-only filesystem, a revoked fd: none
// of them get better by asking the server again, and reporting them as
// "truncated" sends whoever reads the log looking at the network.
func isWriteError(err error) bool {
	if err == nil {
		return false
	}
	// io.Copy wraps nothing, so the syscall error arrives as-is (or inside a
	// *fs.PathError when the writer is an *os.File).
	for _, target := range []error{syscall.ENOSPC, syscall.EDQUOT, syscall.EROFS, syscall.EIO, syscall.EBADF, syscall.EFBIG} {
		if errors.Is(err, target) {
			return true
		}
	}
	var pathErr *fs.PathError
	return errors.As(err, &pathErr)
}

// archiveMagic is the first bytes each COMPRESSED format must start with. Only
// compressed formats are listed: a plain .tar begins with a filename in ASCII,
// which is indistinguishable from an error page by any cheap test, and a
// mis-served .tar is caught later by the extractor with wrapExtract's
// description.
var archiveMagic = map[string][]byte{
	kindTarGz:  {0x1f, 0x8b},
	kindTarXz:  {0xfd, '7', 'z', 'X', 'Z', 0x00},
	kindTarBz2: {'B', 'Z', 'h'},
	kindZip:    {'P', 'K'},
}

// magicWrong reports whether a completed download does not begin the way its
// extension promises — the signature of a mirror that answered 200 with
// something other than the archive.
func magicWrong(url, path string) bool {
	want, ok := archiveMagic[detect(url)]
	if !ok {
		return false
	}
	f, err := osOpen(path)
	if err != nil {
		return false // unreadable is a different problem; let the extractor say so
	}
	defer f.Close()
	head := make([]byte, len(want))
	if _, err := io.ReadFull(f, head); err != nil {
		// Shorter than the magic itself: certainly not the archive.
		return true
	}
	return !bytes.Equal(head, want)
}
