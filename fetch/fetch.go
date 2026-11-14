// Package fetch downloads and extracts pkgx package sources.
//
// It supports the archive formats used by pantry distributables
// (.tar.gz/.tgz, .tar.xz, .tar.bz2/.tbz2, .tar, .zip) plus shallow git
// clones via the system git binary. Extraction is pure Go, preserves file
// modes, recreates symlinks, and rejects archive entries whose paths are
// absolute or would escape the destination directory.
package fetch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-compressions/xz"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-zpkg/artifact"
)

// maxXzDictionary bounds the window an .xz source archive may make the decoder
// keep: 256 MiB, go-compressions/xz's own default, stated here so the bound is
// readable at the call site (xz -9 uses 64 MiB). The window grows with the
// decoded data, never from the dictionary size a header declares, so this is
// a ceiling on what real data can ask for, not an allocation.
const maxXzDictionary = 256 << 20

// newXzReader is the one place an .xz source archive is opened.
func newXzReader(r io.Reader) (*xz.Reader, error) {
	return xz.ReaderConfig{MaxDictionary: maxXzDictionary}.NewReader(r)
}

// Archive kinds detected from a URL's file extension.
const (
	kindTarGz  = "tar.gz"
	kindTarXz  = "tar.xz"
	kindTarBz2 = "tar.bz2"
	kindTar    = "tar"
	kindZip    = "zip"
)

// Fetch downloads url and extracts the archive into destDir, stripping
// stripComponents leading path components from every entry (like
// `tar --strip-components=N`). The archive format is detected from the
// URL's extension: .tar.gz/.tgz, .tar.xz, .tar.bz2/.tbz2, .tar, .zip.
//
// It returns the SHA-256 of the bytes that arrived, in lowercase hex. The
// factory signs and attests the artifact it produces; until this existed nothing
// recorded what the artifact was made FROM, so a source tarball that changed
// upstream — 57% of this pantry is built from tarballs GitHub generates on
// request rather than stores — produced a different artifact, correctly signed,
// whose provenance named a URL and not the bytes that came back from it. The
// digest is returned even when extraction then fails: what arrived is worth
// knowing precisely when it was not what was expected.
func Fetch(url, destDir string, stripComponents int) (string, error) {
	kind := detect(url)
	if kind == "" {
		return "", fmt.Errorf("fetch: unknown archive extension in %q", url)
	}
	// Download to a temp file FIRST, resumably: a truncated stream cannot be
	// recovered once the extractor has begun consuming it.
	path, err := download(url)
	if err != nil {
		return "", err
	}
	defer osRemove(path)
	digest, err := sha256File(path)
	if err != nil {
		return "", fmt.Errorf("fetch: digest %s: %w", url, err)
	}
	// Asked before the mirror is told, so a mismatch refuses the bytes rather
	// than recording them as the new truth.
	if Pin != nil {
		if err := Pin(url, digest); err != nil {
			return "", err
		}
	}
	// The one moment the bytes exist on disk with their digest known. A source
	// mirror is populated HERE or not at all: the caller sees only the digest,
	// and the temp file is gone the moment this function returns.
	//
	// Best-effort by construction. A build that already holds the bytes it
	// needs must not fail because a registry was unreachable; the mirror is for
	// the NEXT rebuild, not this one. Mirror reports its own trouble.
	if Mirror != nil {
		Mirror(path, digest, url)
	}
	body, err := osOpen(path)
	if err != nil {
		return digest, fmt.Errorf("fetch: open %s: %w", path, err)
	}
	defer body.Close()
	if err := osMkdirAll(destDir, 0o755); err != nil {
		return digest, fmt.Errorf("fetch: create %s: %w", destDir, err)
	}
	// A mirror that answers 200 with an error page fails HERE, in the
	// decompressor, with a message that blames the archive. Read the head once
	// so the failure can say what actually arrived.
	head := readHead(body)
	switch kind {
	case kindTarGz:
		gz, err := gzip.NewReader(body)
		if err != nil {
			return digest, fmt.Errorf("fetch: read gzip from %s: %w — %s", url, err, describeBody(head))
		}
		defer gz.Close()
		return digest, extractTar(tar.NewReader(gz), destDir, stripComponents)
	case kindTarXz:
		xr, err := newXzReader(body)
		if err != nil {
			return digest, fmt.Errorf("fetch: read xz from %s: %w — %s", url, err, describeBody(head))
		}
		return digest, extractTar(tar.NewReader(xr), destDir, stripComponents)
	case kindTarBz2:
		// compress/bzip2 has no eager constructor: NewReader always succeeds and
		// the corruption surfaces mid-extract, out of extractTar, with neither
		// the URL nor a hint. pcre.org 8.45 failed a whole factory run as
		// "fetch: bzip2 data invalid: bad magic value" and nothing else.
		err := extractTar(tar.NewReader(bzip2.NewReader(body)), destDir, stripComponents)
		return digest, wrapExtract(err, "bzip2", url, head)
	case kindTar:
		return digest, wrapExtract(extractTar(tar.NewReader(body), destDir, stripComponents), "tar", url, head)
	default: // kindZip
		data, err := io.ReadAll(body)
		if err != nil {
			return digest, fmt.Errorf("fetch: read body of %s: %w", url, err)
		}
		return digest, wrapExtract(extractZip(data, destDir, stripComponents), "zip", url, head)
	}
}

// Mirror, when set, is handed every archive Fetch downloads: its path on disk,
// its sha256 in lowercase hex, and the URL it came from.
//
// It exists because 57% of this pantry is built from tarballs GitHub GENERATES
// on request rather than stores — of 165 such URLs probed, not one advertises a
// Content-Length, because the object does not exist until someone asks. For
// those sources a mirror is not a copy of anything: it is the first stored
// artefact they have ever had, and this is the only place in the build where
// the bytes and their digest are both in hand.
//
// It returns nothing on purpose. A build holding the bytes it needs must not
// fail because a registry was unreachable — the mirror serves the NEXT rebuild.
// ErrSourcePinMismatch is returned when a URL serves bytes other than the ones
// it served before. It is wrapped with both digests and the URL.
var ErrSourcePinMismatch = errors.New("fetch: this URL has served different bytes before")

// Pin, when set, is consulted with a download's URL and the digest it actually
// has, BEFORE Mirror is given the chance to store it. Returning an error fails
// the fetch.
//
// This is trust on first use, and it is the only control there is. Exactly one
// recipe of 904 in the pantry carries a `sha:`, and that one points at a
// `.sha256` served by the same host as the tarball — it catches corruption,
// not substitution. For everything else TLS is the whole of it, across 233
// distinct upstream hosts.
//
// It does not make an upstream trustworthy. It makes a CHANGE visible, which
// is the part nobody had. A version bump is not a change here: the version is
// in the URL, so a new release asks a question that has never been asked and
// is recorded rather than refused. What fires is the same URL serving
// different bytes — a re-cut tarball, a compromised mirror, a hijacked
// domain — and those are exactly the cases nothing else would notice.
//
// Separate from Mirror because the contracts differ. Mirror is best-effort
// and swallows its own failures: a build that already holds the bytes must
// not die because a registry was unreachable. A refusal must not be swallowed.
var Pin func(url, sha256hex string) error

// An implementation that wants its failures seen logs them itself.
var Mirror func(archivePath, sha256hex, url string)

// ExtractTarGzFile extracts the local gzip-compressed tar at src into destDir,
// stripping strip leading path components (like `tar --strip-components=N`). It
// reuses the same hardened extractor as Fetch, so absolute or dest-escaping
// entries are rejected rather than written. zpkvenv's poetry seal uses it to
// unpack a freshly built sdist into the in-project venv's site-packages.
func ExtractTarGzFile(src, destDir string, strip int) error {
	f, err := osOpen(src)
	if err != nil {
		return fmt.Errorf("fetch: open %s: %w", src, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("fetch: read gzip from %s: %w", src, err)
	}
	defer gz.Close()
	if err := osMkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("fetch: create %s: %w", destDir, err)
	}
	return extractTar(tar.NewReader(gz), destDir, strip)
}

// FetchGit shallow-clones ref of repoURL into destDir with go-git's pure-Go
// clone — NO `git` binary dependency. `git clone --branch <ref>` accepts either
// a tag or a branch, so try the ref as a tag first, then as a branch (cleaning
// the destination between attempts, since PlainClone needs an empty target).
// FetchGit shallow-clones repoURL at ref into destDir and returns the commit
// hash it landed on. A tag is a moving target — it can be deleted and re-cut at
// different content, and nothing in a clone says it was — so the commit is the
// only thing about a git source worth attesting.
func FetchGit(repoURL, ref, destDir string) (string, error) {
	// pkgx marks a git distributable with a "git+" URL prefix (e.g.
	// git+https://github.com/o/r); strip it to the plain transport scheme that
	// go-git (and git) actually speak.
	repoURL = strings.TrimPrefix(repoURL, "git+")
	var lastErr error
	for _, rn := range []plumbing.ReferenceName{
		plumbing.NewTagReferenceName(ref),
		plumbing.NewBranchReferenceName(ref),
	} {
		_ = osRemoveAll(destDir)
		repo, err := gitPlainClone(destDir, false, &gogit.CloneOptions{
			URL: repoURL, ReferenceName: rn, Depth: 1, SingleBranch: true, Tags: gogit.NoTags,
		})
		if err == nil {
			return headCommit(repo), nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("fetch: git clone %s@%s: %w", repoURL, ref, lastErr)
}

// detect maps a URL to an archive kind by extension, ignoring any query
// string or fragment. It returns "" for unknown extensions.
func detect(url string) string {
	name := strings.ToLower(url)
	if i := strings.IndexAny(name, "?#"); i >= 0 {
		name = name[:i]
	}
	switch {
	case strings.HasSuffix(name, artifact.ExtTarGz), strings.HasSuffix(name, ".tgz"):
		return kindTarGz
	case strings.HasSuffix(name, artifact.ExtTarXz):
		return kindTarXz
	case strings.HasSuffix(name, ".tar.bz2"), strings.HasSuffix(name, ".tbz2"):
		return kindTarBz2
	case strings.HasSuffix(name, ".zip"):
		return kindZip
	case strings.HasSuffix(name, ".tar"):
		return kindTar
	}
	return ""
}

// safeTarget resolves an archive entry name to a path under destDir after
// stripping strip leading components. ok is false when the entry should be
// skipped (fully consumed by stripping). Absolute entry names and names
// escaping destDir yield an error.
func safeTarget(destDir, name string, strip int) (target string, ok bool, err error) {
	if path.IsAbs(name) || filepath.IsAbs(filepath.FromSlash(name)) {
		return "", false, fmt.Errorf("fetch: absolute path %q in archive", name)
	}
	parts := stripComponents(name)
	if len(parts) <= strip {
		return "", false, nil
	}
	rel := path.Join(parts[strip:]...)
	if rel == "." {
		return "", false, nil
	}
	target = filepath.Join(destDir, filepath.FromSlash(rel))
	prefix := filepath.Clean(destDir) + string(filepath.Separator)
	if !strings.HasPrefix(target+string(filepath.Separator), prefix) {
		return "", false, fmt.Errorf("fetch: path traversal %q in archive", name)
	}
	return target, true, nil
}

// permOr returns the permission bits of m, or fallback when m carries none
// (e.g. zip entries written without Unix modes).
func permOr(m, fallback fs.FileMode) fs.FileMode {
	if p := m.Perm(); p != 0 {
		return p
	}
	return fallback
}

// writeFile creates target with perm and copies r into it.
func writeFile(target string, perm fs.FileMode, r io.Reader) error {
	f, err := osOpenFile(target, osWriteFlags, perm)
	if err != nil {
		return fmt.Errorf("fetch: create %s: %w", target, err)
	}
	if _, err := ioCopy(f, r); err != nil {
		f.Close()
		return fmt.Errorf("fetch: write %s: %w", target, err)
	}
	return f.Close()
}

// extractTar extracts every entry of tr into destDir, stripping strip leading
// path components. It delegates to the shared artifact.Extract, the pkgx
// ecosystem's single tar extractor: it strips components, restores each regular
// file's recorded mtime (tar(1) semantics — recipes such as libexpat 2.8.3
// depend on generated files staying newer than their sources), rejects absolute
// or directory-escaping names (and hard-link sources) with artifact.ErrInsecurePath,
// and reproduces dirs, regular files, symlinks and hard links; unsupported entry
// types (fifos, devices, ...) are skipped.
func extractTar(tr *tar.Reader, destDir string, strip int) error {
	return artifact.Extract(tr, destDir, strip)
}

// restoreTime gives an extracted file the modification time the archive
// recorded, exactly as tar(1) does. Recipes DEPEND on this: a release tarball
// ships generated files NEWER than the sources they derive from precisely so
// make leaves them alone. Stamping every file with "now" instead re-orders them
// by archive position, and make then tries to regenerate — libexpat 2.8.3 dies
// that way (doc/xmlwf.1 is archived before, hence stamped older than,
// doc/xmlwf.xml → make runs the docbook rule with no docbook2x-man installed →
// `test "x" != x` → Error 1), and the same trap is behind the autotools
// maintainer-mode rebuilds MAKEFLAGS/TouchAutotools work around.
//
// An archive with no recorded time (zero) is left as written.
func restoreTime(path string, mt time.Time) error {
	if mt.IsZero() {
		return nil
	}
	if err := osChtimes(path, mt, mt); err != nil {
		return fmt.Errorf("fetch: set mtime %s: %w", path, err)
	}
	return nil
}

// extractZip extracts a zip archive held in data into destDir, stripping
// strip leading path components. As with tar, zip.ErrInsecurePath is
// tolerated because safeTarget performs its own (stricter) vetting.
func extractZip(data []byte, destDir string, strip int) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return fmt.Errorf("fetch: read zip: %w", err)
	}
	for _, f := range zr.File {
		target, ok, err := safeTarget(destDir, f.Name, strip)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := osMkdirAll(target, permOr(mode, 0o755)); err != nil {
				return fmt.Errorf("fetch: create %s: %w", target, err)
			}
		case mode&fs.ModeSymlink != 0:
			rc, err := zipOpen(f)
			if err != nil {
				return fmt.Errorf("fetch: open %s in zip: %w", f.Name, err)
			}
			var link strings.Builder
			_, err = ioCopy(&link, rc)
			rc.Close()
			if err != nil {
				return fmt.Errorf("fetch: read %s in zip: %w", f.Name, err)
			}
			if err := osMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("fetch: create %s: %w", filepath.Dir(target), err)
			}
			if err := osSymlink(link.String(), target); err != nil {
				return fmt.Errorf("fetch: symlink %s: %w", target, err)
			}
		default:
			if err := osMkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("fetch: create %s: %w", filepath.Dir(target), err)
			}
			rc, err := zipOpen(f)
			if err != nil {
				return fmt.Errorf("fetch: open %s in zip: %w", f.Name, err)
			}
			err = writeFile(target, permOr(mode, 0o644), rc)
			rc.Close()
			if err != nil {
				return err
			}
			if err := restoreTime(target, f.Modified); err != nil {
				return err
			}
		}
	}
	return nil
}

// sha256File is the SHA-256 of a downloaded file, in lowercase hex.
//
// It reads the finished file in its own pass rather than hashing the download
// stream, because those are not the same bytes: download() resumes a truncated
// transfer with a Range request, so what passes through it can include a prefix
// that was already written and is not repeated. Hashing what is on disk when
// the download is declared complete cannot be wrong that way, and a second read
// of a local temp file costs a fraction of the transfer that produced it.
func sha256File(path string) (string, error) {
	f, err := osOpenHash(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := ioCopyHash(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// headCommit is the commit a fresh clone landed on, or "" when it cannot be
// read. A missing commit weakens the attestation; failing the build over it
// would be worse, because the source is already correctly checked out.
func headCommit(repo *gogit.Repository) string {
	if repo == nil {
		return ""
	}
	ref, err := repo.Head()
	if err != nil {
		return ""
	}
	return ref.Hash().String()
}

// stripComponents splits an archive member name the way `tar --strip-components`
// counts it: a leading "." IS a component.
//
// `path.Clean` removes it before the count, so N components off a "./"-prefixed
// archive strips N+1 — which does not fail, it FLATTENS: the real root entry is
// dropped and a subdirectory's namesake takes its place. The tar side of this
// is go-zpkg/artifact#69, where `hdfgroup.org/HDF5 2.2.0` built the wrong tree
// and cmake reported it as an unknown command in "CMakeLists.txt". Zip archives
// carry "./" prefixes less often, but the two extractors must not disagree
// about what `strip-components` means.
//
// Empty segments (from "//" or a trailing "/") are not components and are
// dropped; "." is kept.
func stripComponents(name string) []string {
	raw := strings.Split(name, "/")
	out := raw[:0]
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
