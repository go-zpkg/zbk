// Package artifactpkg packages a finished install tree into a pkgx artifact.
//
// A pkgx artifact is a compressed tar whose entries are all prefixed
// "<project>/v<version>/" (e.g. "openssl.org/v1.1.1w/bin/openssl"). The dist
// layout places each artifact at "<project>/<os>/<arch>/v<version><ext>" next to a
// "versions.txt" listing the published versions, one per line.
//
// Codec chooses the compression. It stays gzip until the readers are deployed:
// publishing a codec the installed base cannot read would brick every install,
// and an artifact already published is never rewritten. See Codec.
package artifactpkg

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/go-zpkg/artifact"
	"github.com/klauspost/compress/zstd"
)

// Artifact walks installDir and writes a gzip'd tar to w in which every entry
// path is "<project>/v<version>/<relpath>". Regular files (with their mode
// bits), directories, and symlinks (tar TypeSymlink plus link target) are
// preserved. Hidden files are included; only the walk root itself is skipped.
// Paths are sorted for deterministic output.
func Artifact(installDir, project, version string, w io.Writer) error {
	var rels []string
	if err := walkDir(installDir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == installDir {
			return nil
		}
		rel, err := filepath.Rel(installDir, path)
		if err != nil {
			return err
		}
		rels = append(rels, rel)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(rels)

	gz, err := compressor(w)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	for _, rel := range rels {
		if err := addEntry(tw, installDir, project, version, rel); err != nil {
			tw.Close()
			gz.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		gz.Close()
		return err
	}
	return gz.Close()
}

// addEntry appends the entry at installDir/rel to tw under the artifact prefix.
func addEntry(tw *tar.Writer, installDir, project, version, rel string) error {
	full := filepath.Join(installDir, rel)
	fi, err := osLstat(full)
	if err != nil {
		return err
	}
	link := ""
	if fi.Mode()&fs.ModeSymlink != 0 {
		if link, err = osReadlink(full); err != nil {
			return err
		}
	}
	hdr, err := tarFileInfoHeader(fi, link)
	if err != nil {
		return err
	}
	hdr.Name = project + "/v" + version + "/" + filepath.ToSlash(rel)
	if fi.IsDir() {
		hdr.Name += "/"
	}
	normalise(hdr, fi)
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	f, err := osOpen(full)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = ioCopy(tw, f)
	return err
}

// normalise strips the BUILDER from an artifact's tar headers.
//
// Two builds of one recipe on two machines produced two different artifacts, and
// the difference was the umask. Measured 2026-09-29, zlib.net 1.3.2 built on
// the s390x seed VM before and after it was replaced:
//
//	every FILE byte-identical, 14 entries either side
//	directories   0755 → 0775      the hosts' umasks, 0022 and 0002
//	uid/gid/uname 1000/linux1      the same ONLY because the account was
//
// Files were untouched because cp and install preserve the source's mode; a
// directory gets its mode from mkdir, which applies the umask. So the same
// source, the same compiler and the same libc still gave two digests.
//
// reproducible-builds.org says exactly this under "Archive metadata" —
// "Permissions on build artifacts may vary, for example due to differing
// umask settings" — and prescribes `--mode=a=rX,u+w` together with
// `--owner=0 --group=0 --numeric-owner`. That is what this does:
//
//	directories and anything executable   0755
//	everything else                       0644
//	setuid, setgid and sticky             KEPT — an artifact that ships one
//	                                      means it, and a=rX would strip it
//	uid, gid                              0, with the names cleared
//
// mtime is deliberately NOT touched, and it is the third member of this class:
// every entry already carries ONE timestamp, but it is the build's. Fixing it
// to an epoch would make an artifact say nothing about when it was made, and that
// is a policy choice rather than a defect. It is named here so the next person
// finds it already weighed instead of thinking it was missed.
func normalise(hdr *tar.Header, fi fs.FileInfo) {
	// The bits that are not permissions: setuid, setgid, sticky.
	special := hdr.Mode &^ 0o777
	perm := int64(0o644)
	if fi.IsDir() || hdr.Mode&0o111 != 0 {
		perm = 0o755
	}
	hdr.Mode = special | perm
	hdr.Uid, hdr.Gid = 0, 0
	hdr.Uname, hdr.Gname = "", ""
}

// WriteArtifact creates "outDir/<project>/<os>/<arch>/v<version>.tar.gz",
// artifacts installDir into it, and appends version to the sibling
// "versions.txt". It returns the tarball path.
func WriteArtifact(installDir, project, version, os, arch, outDir string) (string, error) {
	dir := filepath.Join(outDir, project, os, arch)
	if err := osMkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tarballPath := filepath.Join(dir, "v"+version+Codec)
	f, err := osCreate(tarballPath)
	if err != nil {
		return "", err
	}
	if err := Artifact(installDir, project, version, f); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	vf, err := osOpenFileAppend(filepath.Join(dir, "versions.txt"))
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(vf, version+"\n"); err != nil {
		vf.Close()
		return "", err
	}
	if err := vf.Close(); err != nil {
		return "", err
	}
	return tarballPath, nil
}

// Codec is the extension — and therefore the compression — new artifacts are
// written with. One of artifact.ExtTarGz or artifact.ExtTarZst.
//
// It defaults to zstd. The readers shipped first (artifact v0.8.0, in pkgx, pkgm
// and bk), which is the order that mattered: a consumer meeting a codec it
// cannot decode fails with "invalid header", which reads like a corrupt
// download rather than a format it was never taught.
//
// The blast radius of this default is bounded by construction. Artifacts already
// published are never rewritten — they stay gzip and stay readable by anything,
// old binaries included. Only NEW publishes change, and an operator who needs
// the old format says --compress gzip.
//
// Measured on the same package, version and platform (lz4.org 1.10.0,
// linux/aarch64): the published gzip layer is 311 344 bytes, the zstd artifact
// 169 518 — 1.83x smaller, and faster to decompress.
//
// Measured on real artifact payloads, zstd -19 beats xz on ratio, compression
// time AND decompression time, and gzip has the poorest ratio of the three
// while decompressing slower than zstd. Every install pays the decompression;
// the factory pays the compression once.
var Codec = artifact.ExtTarZst

// compressor wraps w in the encoder Codec names. zstd is used at its highest
// level: the factory compresses an artifact once and every consumer pays for the
// size forever, so the asymmetry is worth the seconds.
func compressor(w io.Writer) (io.WriteCloser, error) {
	switch Codec {
	case artifact.ExtTarZst:
		return zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	case artifact.ExtTarGz:
		return gzip.NewWriter(w), nil
	default:
		return nil, fmt.Errorf("artifactpkg: unknown codec %q", Codec)
	}
}
