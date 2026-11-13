package artifactpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/go-compressions/xz"
)

func hasPrefix(b, p []byte) bool { return bytes.HasPrefix(b, p) }

// Comparing two artifacts entry by entry, which is the only way to learn
// anything from "the digests differ".
//
// ⛔⛔ THIS EXISTS BECAUSE THE MEASUREMENT WAS DONE ONCE, BY HAND, AND FOUND A
// REAL DEFECT. On 2026-09-29 zlib.net 1.3.2 was built on the s390x seed VM
// before and after it was replaced:
//
//	every FILE byte-identical, 14 entries either side
//	directories   0755 → 0775      the hosts' umasks, 0022 and 0002
//
// `normalise` in this package fixes that class now, citing
// reproducible-builds.org. But the finding came from a comparison nobody has
// run since, and a class of defect that is only ever found by hand is a class
// that comes back. Two digests that differ say "differ"; this says WHAT.
//
// ⛔ IT CLASSIFIES, AND THE CLASS IS THE POINT. "The artifacts differ" sends
// someone to diff two tarballs. "Three directories differ in MODE ONLY" names
// the umask, and "one file differs in CONTENT" names the compiler or an
// embedded path or a timestamp — different problems with different fixes.

// Diff is one difference between two artifacts.
type Diff struct {
	// Entry is the archive path. For OnlyInA/OnlyInB it is the missing one.
	Entry string
	// Kind is what differs: "content", "mode", "size", "type", "link",
	// "mtime", "owner", "only-in-a", "only-in-b".
	Kind string
	// A and B render the two values, in that order. Empty for a missing entry.
	A, B string
}

func (d Diff) String() string {
	if d.A == "" && d.B == "" {
		return fmt.Sprintf("%-10s %s", d.Kind, d.Entry)
	}
	return fmt.Sprintf("%-10s %s: %s vs %s", d.Kind, d.Entry, d.A, d.B)
}

// Report is the verdict on a pair of artifacts.
type Report struct {
	Entries int // entries in A
	Diffs   []Diff
}

// Identical reports whether the two artifacts are the same artifact.
//
// ⛔ AN EMPTY REPORT ON AN EMPTY PAIR IS NOT A PASS. Two archives that could
// not be read, or that hold nothing, produce no differences — and a caller
// asking "are these reproducible?" would be told yes. Entries must be
// positive for the answer to mean anything, which is the same reason
// `pecheck` counts its denominator.
func (r Report) Identical() bool { return r.Entries > 0 && len(r.Diffs) == 0 }

// member is one archive member, reduced to what reproducibility cares about.
//
// Not `entry`: artifactpkg_test.go already has a type by that name, and the
// compiler reports the collision against THIS file even though the test file
// was there first.
type member struct {
	mode     int64
	size     int64
	typeflag byte
	link     string
	modTime  int64
	uid, gid int
	digest   string // sha256 of the content, "" for non-regular entries
}

// Compare reads two artifact tarballs and reports every difference between
// them, ordered by archive path.
//
// ⛔ ORDER IS IMPOSED, NOT ASSUMED. WriteArtifact sorts paths, so two artifacts
// of one recipe normally arrive in the same order — but a report that
// depended on that would turn "the entries came in a different order" into
// hundreds of spurious content diffs, burying the one real difference. Both
// sides are read into maps and compared by NAME.
func Compare(pathA, pathB string) (Report, error) {
	a, err := readEntries(pathA)
	if err != nil {
		return Report{}, fmt.Errorf("reading %s: %w", pathA, err)
	}
	b, err := readEntries(pathB)
	if err != nil {
		return Report{}, fmt.Errorf("reading %s: %w", pathB, err)
	}
	return compareEntries(a, b), nil
}

func compareEntries(a, b map[string]member) Report {
	rep := Report{Entries: len(a)}
	names := make([]string, 0, len(a)+len(b))
	seen := map[string]bool{}
	for n := range a {
		names = append(names, n)
		seen[n] = true
	}
	for n := range b {
		if !seen[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	for _, n := range names {
		ea, okA := a[n]
		eb, okB := b[n]
		switch {
		case !okB:
			rep.Diffs = append(rep.Diffs, Diff{Entry: n, Kind: "only-in-a"})
			continue
		case !okA:
			rep.Diffs = append(rep.Diffs, Diff{Entry: n, Kind: "only-in-b"})
			continue
		}
		// ⛔ EVERY FIELD, NOT THE FIRST ONE THAT DIFFERS. An artifact whose
		// files differ in BOTH mode and content has two problems, and
		// stopping at the first hides the second behind a fix for the first.
		if ea.typeflag != eb.typeflag {
			rep.Diffs = append(rep.Diffs, Diff{n, "type", string(ea.typeflag), string(eb.typeflag)})
		}
		if ea.mode != eb.mode {
			rep.Diffs = append(rep.Diffs, Diff{n, "mode", fmt.Sprintf("%04o", ea.mode), fmt.Sprintf("%04o", eb.mode)})
		}
		if ea.uid != eb.uid || ea.gid != eb.gid {
			rep.Diffs = append(rep.Diffs, Diff{n, "owner",
				fmt.Sprintf("%d/%d", ea.uid, ea.gid), fmt.Sprintf("%d/%d", eb.uid, eb.gid)})
		}
		if ea.link != eb.link {
			rep.Diffs = append(rep.Diffs, Diff{n, "link", ea.link, eb.link})
		}
		if ea.size != eb.size {
			rep.Diffs = append(rep.Diffs, Diff{n, "size", fmt.Sprint(ea.size), fmt.Sprint(eb.size)})
		}
		if ea.digest != eb.digest {
			rep.Diffs = append(rep.Diffs, Diff{n, "content", short(ea.digest), short(eb.digest)})
		}
		// mtime LAST and reported like anything else. artifactpkg deliberately
		// does not fix mtime to an epoch — an artifact's timestamps say when it
		// was made, and that is a policy choice this package documents. So
		// two builds an hour apart WILL differ here, and the report says so
		// plainly rather than pretending it is bit-identity.
		if ea.modTime != eb.modTime {
			rep.Diffs = append(rep.Diffs, Diff{n, "mtime", fmt.Sprint(ea.modTime), fmt.Sprint(eb.modTime)})
		}
	}
	return rep
}

// Classes counts the differences by kind, newest question first: how many
// entries differ, and in what way.
func (r Report) Classes() map[string]int {
	out := map[string]int{}
	for _, d := range r.Diffs {
		out[d.Kind]++
	}
	return out
}

// WithoutMTime is the report with mtime differences removed.
//
// ⛔ A SEPARATE ANSWER, NOT A LOOSER ONE. "Identical apart from timestamps"
// is the useful verdict for a factory that does not set SOURCE_DATE_EPOCH,
// and it is a DIFFERENT claim from bit-identity. Returning it from Identical()
// would quietly relax the check; returning it here makes a caller say which
// of the two questions it is asking.
func (r Report) WithoutMTime() Report {
	out := Report{Entries: r.Entries}
	for _, d := range r.Diffs {
		if d.Kind != "mtime" {
			out.Diffs = append(out.Diffs, d)
		}
	}
	return out
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	if d == "" {
		return "-"
	}
	return d
}

// readEntries reads a .tar.gz (or plain .tar) into a map keyed by cleaned
// archive path.
func readEntries(path string) (map[string]member, error) {
	f, err := openForRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// ⛔⛔ EVERY CODEC A ARTIFACT IS PUBLISHED IN, AND THE FIRST VERSION OF THIS
	// KNEW ONLY GZIP. `Codec` is `artifact.ExtTarZst` — zstd is what new artifacts
	// ARE — and the first run against the registry proved it:
	//
	//	mirror --from oci://ghcr.io/go-pkgx/packages zlib.net
	//	  → zlib.net/darwin/aarch64/v1.3.2.tar.zst
	//
	// A gzip-only reader could not read a single published artifact. The unit
	// tests were green throughout, because they wrote their own fixtures with
	// the codec the reader happened to support — which is the whole reason to
	// run a new tool against real data before believing it.
	//
	// Sniffed by MAGIC, not by extension: a caller comparing a local rebuild
	// against a published artifact has one of each, and `mirror` names files by
	// the codec while `WriteArtifact` names them by `Codec`. An extension can
	// also simply be wrong, and a wrong extension must not read as corruption.
	var r io.Reader = f
	var magic [6]byte
	n, err := io.ReadFull(f, magic[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	head := magic[:n]
	switch {
	case hasPrefix(head, []byte{0x1f, 0x8b}):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case hasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		zr, closeZstd, err := zstdNewReader(f)
		if err != nil {
			return nil, err
		}
		defer closeZstd()
		r = zr
	case hasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		xr, err := xz.NewReader(f)
		if err != nil {
			return nil, err
		}
		r = xr
	}

	out := map[string]member{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		e := member{
			mode:     hdr.Mode,
			size:     hdr.Size,
			typeflag: hdr.Typeflag,
			link:     hdr.Linkname,
			modTime:  hdr.ModTime.Unix(),
			uid:      hdr.Uid,
			gid:      hdr.Gid,
		}
		if hdr.Typeflag == tar.TypeReg {
			h := sha256.New()
			if _, err := io.Copy(h, tr); err != nil {
				return nil, err
			}
			e.digest = hex.EncodeToString(h.Sum(nil))
		}
		out[name] = e
	}
	return out, nil
}
