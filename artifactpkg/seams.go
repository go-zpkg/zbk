package artifactpkg

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// Injectable seams over the operations whose error branches are otherwise
// unreachable in a test (a successful syscall that then fails is not
// reproducible with real files). Tests override these to exercise every
// error-handling path; production uses the stdlib functions verbatim.
var (
	walkDir           = filepath.WalkDir
	osLstat           = os.Lstat
	osReadlink        = os.Readlink
	osOpen            = os.Open
	osMkdirAll        = os.MkdirAll
	ioCopy            = io.Copy
	tarFileInfoHeader = tar.FileInfoHeader

	// osCreate and osOpenFileAppend return io.WriteCloser (not *os.File) so
	// tests can inject writers whose Write or Close fails.
	osCreate = func(name string) (io.WriteCloser, error) {
		return os.Create(name)
	}
	osOpenFileAppend = func(name string) (io.WriteCloser, error) {
		return os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	}

	// Seams for the artifact COMPARISON (compare.go). Three of its error
	// branches cannot be reached with a real file: a freshly opened regular
	// file does not fail its first Read, does not fail Seek(0), and
	// zstd.NewReader with no options does not fail at all. They are still
	// branches, and a 100% gate is only worth having if it is not worked
	// around — so they are injected rather than deleted or excused.
	openForRead = func(name string) (readSeekCloser, error) { return os.Open(name) }

	// zstdNewReader returns a plain io.Reader and a close func because
	// zstd.Decoder.Close returns nothing while gzip.Reader.Close returns an
	// error — one shape for both keeps readEntries from caring which.
	//
	// ⛔ NO `if err != nil` HERE, AND THAT IS THE POINT. zstd.NewReader with
	// no options cannot fail, so a branch on its error could never be taken
	// and would sit forever as the one line a 100% gate has to be argued
	// around. The error is passed back UNEXAMINED — the caller already
	// returns on it before the close func is ever invoked, so the closure
	// over a nil decoder is written but never run. The seam still lets a test
	// make this fail, which is what the branch was for.
	zstdNewReader = func(r io.Reader) (io.Reader, func(), error) {
		d, err := zstd.NewReader(r)
		return d, func() { d.Close() }, err
	}
)

// readSeekCloser is what readEntries needs of a file: the sniff reads the
// first bytes and then rewinds.
type readSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}
