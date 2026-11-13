package fixup

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"strings"
)

// Sentinels returned by SetInterp.
var (
	// ErrNoInterp is returned for an ELF with no PT_INTERP program header,
	// which is nearly all of them: a shared library does not name one.
	ErrNoInterp = errors.New("elf has no PT_INTERP")
	// ErrInterpNoSpace is returned when the replacement is longer than the
	// slot. PT_INTERP's string is fixed-width in the file like .dynstr's, and
	// the segment cannot grow without moving everything after it.
	ErrInterpNoSpace = errors.New("interpreter path does not fit in place")
)

// ReadInterp returns an ELF's PT_INTERP string without its NUL, or "" when the
// file has no such program header.
func ReadInterp(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := p.ReadAt(buf, 0); err != nil {
			return "", err
		}
		// To the FIRST NUL, not the last: the slot is NUL-padded and the
		// path is NUL-terminated, so trimming from the right would hand back
		// the padding of a slot that holds anything after its terminator. A
		// slot with no NUL at all is malformed — the kernel rejects it — and
		// is returned whole rather than guessed at.
		if i := bytes.IndexByte(buf, 0); i >= 0 {
			buf = buf[:i]
		}
		return string(buf), nil
	}
	return "", nil
}

// SetInterp overwrites an ELF's PT_INTERP string in place, zero-padding the
// slack.
//
// In place, like SetRunpath, and for the same reason: the string's length is
// baked into p_filesz and into every offset after it, so growing it would mean
// rewriting the file. Shrinking is free — the kernel reads p_filesz bytes and
// requires the last to be NUL, which zero-padding keeps true.
func SetInterp(path, value string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	var off, size uint64
	found := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			off, size, found = p.Off, p.Filesz, true
			break
		}
	}
	f.Close()
	if !found {
		return ErrNoInterp
	}
	// +1 for the NUL the kernel insists on.
	if uint64(len(value))+1 > size {
		return ErrInterpNoSpace
	}

	restore, err := ensureWritable(path)
	if err != nil {
		return err
	}
	defer restore()
	fh, err := osOpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer fh.Close()

	buf := make([]byte, size) // value, then NUL padding to the full slot
	copy(buf, value)
	_, err = fh.WriteAt(buf, int64(off))
	return err
}

// fixInterp rewrites a staged interpreter path onto the final prefix.
//
// Almost nothing needs this. A shared library has no PT_INTERP and an ordinary
// executable's names the system loader, which is not under our prefix. The one
// artefact that has both is gnu.org/glibc's libc.so.6, which is executable —
// that is how `libc.so.6 --version` works — and whose PT_INTERP is its OWN
// ld.so, built with --prefix and therefore baked with the staging directory:
//
//	[Requesting program interpreter:
//	   /home/linux1/.pkgx/gnu.org/glibc/v2.44+brewing/lib/glibc-2.44/ld64.so.1]
//
// Two things wrong in one string. `+brewing` is Paths.BuildInstall, which
// exists during the build and nowhere after it. `/home/linux1` is the runner's
// home: a published, signed artifact naming the account that made it.
//
// Measured when it was found (go-zpkg/bk#263): of 250 ELFs sampled in the
// s390x store, exactly one carried a staging interpreter. So this is not a
// sweep that fixes a class — it is one artefact, and the guard is here rather
// than in the glibc recipe because every other consumer of a staged path
// (.pc files, .cmake files, staged scripts, Mach-O install names, and since
// then the ELF RUNPATH) is already unstaged by fixup. PT_INTERP was the one
// program header that was not.
//
// It does NOT make the path portable — the final prefix is still absolute and
// still under whoever's $ZPKG_DIR built it. What it buys is that the path
// names a directory that will exist, and that the artefact stops carrying a
// username. Making it relocatable is a different problem, and pkgx solves it
// by never executing libc.so.6 directly.
func fixInterp(opts Options) error {
	if opts.BuildInstall == "" || opts.BuildInstall == opts.Prefix {
		return nil
	}
	return walkExes(opts.Prefix, func(exe string) error {
		cur, err := ReadInterp(exe)
		if err != nil || cur == "" || !strings.HasPrefix(cur, opts.BuildInstall) {
			// An unreadable file here is not this step's business: walkExes
			// visits every regular file under bin/lib/libexec, most of which
			// are not ELF at all.
			return nil
		}
		want := opts.Prefix + strings.TrimPrefix(cur, opts.BuildInstall)
		if err := SetInterp(exe, want); err != nil {
			// ErrInterpNoSpace cannot happen for an unstaging rewrite — the
			// result is shorter by the length of "+brewing" — but reporting
			// beats a silent skip if the premise ever changes.
			return err
		}
		opts.log("interp %s: %s -> %s", exe, cur, want)
		return nil
	})
}
