package fetch

import "fmt"

// Digest downloads url and returns its SHA-256 in lowercase hex and its size,
// without extracting anything.
//
// ⛔⛔ IT EXISTS SO THAT THE AUTHOR OF A RECIPE AND THE BUILD THAT CONSUMES IT
// USE THE SAME FETCHER. Every other distribution computes a pinned digest with
// a tool that is not the one the build runs — `shasum`, `nix-prefetch-url`,
// `spack checksum` — so a host quirk the build will meet is not met while
// authoring. This package's download() already carries four defences a hand
// rolled `curl | shasum` does not:
//
//   - a non-2xx is an error, and a 5xx/429 is retried rather than hashed;
//   - a truncated body is RESUMED with a Range request and checked against the
//     length the server announced;
//   - magicWrong() rejects an archive whose magic bytes are not the archive's,
//     which is "a mirror answering 200 with a page" — the one shape a status
//     check cannot see;
//   - the User-Agent is ours, because some hosts answer Go's default with 403.
//
// The hazard is not hypothetical and it is not the build's. Authoring a recipe
// by hand on 2026-11-08, with GitHub's release CDN answering 504:
//
//	$ curl -sSL -o xz-5.8.4.tar.gz https://…/xz-5.8.4.tar.gz   # 504
//	$ shasum -a 256 xz-5.8.4.tar.gz
//	bef140a1a96994029153dca8c00b1750b9a5a764fb9db2dc68d7bb40e8a29e8a
//
// 92 bytes of error page, and a digest that looks exactly like a good one. A
// pinned digest is fail-closed by design, so a WRONG pin is worse than none:
// it makes every future build of that version fail, and it looks authoritative
// while doing it.
func Digest(url string) (string, int64, error) {
	path, digest, size, err := digestKept(url)
	if err != nil {
		return "", 0, err
	}
	osRemove(path)
	return digest, size, nil
}

// digestKept is Digest without removing the file, so that [DigestVerified] can
// check a signature over the exact bytes it just hashed rather than downloading
// them a second time. The caller owns the file.
func digestKept(url string) (string, string, int64, error) {
	path, err := download(url)
	if err != nil {
		return "", "", 0, err
	}
	// ⛔⛔ AND THE MAGIC CHECK IS RE-ASSERTED HERE, BECAUSE download() TREATS IT
	// AS A RETRY AND NOT AS A REFUSAL. Its loop retries a wrong-magic body up to
	// downloadAttempts and then returns the file anyway. That is defensible for
	// a BUILD — a pinned digest, or the extractor, fails next — but Digest's
	// output IS the digest that would have caught it, so for this caller there
	// is nothing downstream. A test asserting a captcha page cannot be pinned
	// failed here until this existed, which is how the distinction was found.
	if magicWrong(url, path) {
		osRemove(path)
		return "", "", 0, fmt.Errorf("fetch: %s: the body is not the archive its name claims "+
			"(a page served with 200, or the wrong file); refusing to pin it", url)
	}

	digest, err := sha256File(path)
	if err != nil {
		osRemove(path)
		return "", "", 0, err
	}
	fi, err := osStatFetched(path)
	if err != nil {
		osRemove(path)
		return "", "", 0, fmt.Errorf("fetch: %s: %w", url, err)
	}
	return path, digest, fi.Size(), nil
}
