package fixup

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// Mach-O code signing, enough of it to re-sign what we just rewrote.
//
// Editing a Mach-O in place invalidates its signature, and on Apple silicon
// that is FATAL and SILENT — the kernel kills the process before it prints
// anything:
//
//	$ ./bin/main
//	$ echo $?
//	137                                     ← SIGKILL, no message at all
//	$ codesign -v bin/main
//	bin/main: invalid signature (code or signature have been modified)
//
// The linker ad-hoc signs every arm64 binary it produces (flags 0x20002 =
// adhoc|linker-signed), so this applies to essentially everything bk builds
// for darwin/aarch64. Stripping +brewing from an install name is exactly such
// an edit. Without what follows, an artifact whose paths we fixed would be a
// artifact nobody can run, and the failure would look like nothing at all.
//
// Re-signing is affordable here because our edits are SIZE-PRESERVING: strings
// are overwritten in their existing load-command slot and zero-padded. The
// signature blob stays where it is, the code limit does not move, the number
// of page hashes does not change. Only the digests themselves are stale — so
// re-signing is recomputing them in place, which needs no key, no CMS, and no
// external tool. `codesign -s -` would do the same thing by shelling out to a
// program bk cannot rely on when cross-building.
//
// The layout below was verified against a real published artifact before any of
// it was used: recomputing every code slot of ghcr.io/go-zpkg/packages'
// darwin/aarch64 `rust-lang.org/cargo` v0.99.0 reproduced 8159 of 8159 stored
// hashes. An unmodified binary hashing to itself is the proof the structure is
// read correctly.
const (
	lcCodeSignature = 0x1d

	csMagicEmbeddedSignature = 0xfade0cc0
	csMagicCodeDirectory     = 0xfade0c02

	// Hash algorithms a CodeDirectory can name (cs_blobs.h CS_HASHTYPE_*).
	csHashSHA1            = 1
	csHashSHA256          = 2
	csHashSHA256Truncated = 3
	csHashSHA384          = 4
)

// ErrBadSignature means the embedded signature is not shaped the way the
// format says. bk refuses to guess at it: a half-understood signature rewritten
// anyway produces a binary that dies with no message.
var ErrBadSignature = errors.New("fixup: malformed Mach-O code signature")

// resignSlice recomputes the code-slot hashes of the embedded signature in one
// Mach-O slice, in place. slice is the whole thin image (offsets inside a
// signature are relative to it, not to the containing fat file).
//
// It reports whether a signature was found and rewritten; an unsigned slice is
// not an error, it simply has nothing to restate.
func resignSlice(slice []byte, bo binary.ByteOrder, hdr, ncmd int) (bool, error) {
	return walkSignature(slice, bo, hdr, ncmd, true)
}

// walkSignature finds a slice's embedded signature and either rewrites its code
// slots (apply) or reports whether they still describe the bytes.
func walkSignature(slice []byte, bo binary.ByteOrder, hdr, ncmd int, apply bool) (bool, error) {
	off, size, ok := codeSignatureCmd(slice, bo, hdr, ncmd)
	if !ok {
		return false, nil
	}
	if off+size > len(slice) {
		return false, fmt.Errorf("%w: LC_CODE_SIGNATURE at %d+%d runs past the %d-byte slice",
			ErrBadSignature, off, size, len(slice))
	}
	return resignSuperBlob(slice, slice[off:off+size], apply)
}

// MachoSignatureStale reports whether path is a signed Mach-O whose code-slot
// hashes no longer describe its own bytes — the state an in-place edit leaves
// behind, and the one macOS refuses to run on Apple silicon.
//
// It asks the same question `codesign -v` does, without codesign: the answer is
// needed on machines that do not have it, and about artifacts built for a
// platform the asking machine is not. An unsigned Mach-O is not stale — there
// is nothing to disagree with — so it reports false.
func MachoSignatureStale(path string) (bool, error) {
	raw, slices, err := machoInfo(path)
	if err != nil {
		return false, err
	}
	for i, sl := range slices {
		stale, err := walkSignature(raw[sl.off:sl.off+sl.size], sl.bo, sl.hdr, sl.ncmd, false)
		if err != nil {
			return false, sliceErr(path, i, len(slices), err)
		}
		if stale {
			return true, nil
		}
	}
	return false, nil
}

// codeSignatureCmd finds LC_CODE_SIGNATURE and returns the file offset and
// length of the signature blob it points at.
func codeSignatureCmd(slice []byte, bo binary.ByteOrder, hdr, ncmd int) (off, size int, ok bool) {
	p := hdr
	for i := 0; i < ncmd && p+8 <= len(slice); i++ {
		cmd := bo.Uint32(slice[p:])
		sz := int(bo.Uint32(slice[p+4:]))
		if sz < 8 || p+sz > len(slice) {
			return 0, 0, false
		}
		if cmd == lcCodeSignature && sz >= 16 {
			return int(bo.Uint32(slice[p+8:])), int(bo.Uint32(slice[p+12:])), true
		}
		p += sz
	}
	return 0, 0, false
}

// resignSuperBlob walks an embedded signature SuperBlob and recomputes every
// CodeDirectory it holds. There can be more than one — a binary signed for
// several hash algorithms carries an "alternate" directory per algorithm, and
// leaving one of them stale is the same failure as leaving them all stale.
//
// Everything in a signature blob is BIG-endian, whatever the Mach-O's own byte
// order: it is a cross-architecture structure.
func resignSuperBlob(slice, sig []byte, apply bool) (bool, error) {
	be := binary.BigEndian
	if len(sig) < 12 || be.Uint32(sig) != csMagicEmbeddedSignature {
		// Not an embedded signature (a detached or unknown blob): leave it be
		// rather than write over something we do not understand.
		return false, nil
	}
	count := int(be.Uint32(sig[8:]))
	if 12+count*8 > len(sig) {
		return false, fmt.Errorf("%w: SuperBlob claims %d blobs, which does not fit in %d bytes",
			ErrBadSignature, count, len(sig))
	}
	done := false
	for i := 0; i < count; i++ {
		o := int(be.Uint32(sig[12+i*8+4:]))
		if o < 0 || o+8 > len(sig) {
			return done, fmt.Errorf("%w: blob %d of %d starts at %d, past the %d-byte signature",
				ErrBadSignature, i, count, o, len(sig))
		}
		if be.Uint32(sig[o:]) != csMagicCodeDirectory {
			continue
		}
		length := int(be.Uint32(sig[o+4:]))
		if length < 44 || o+length > len(sig) {
			return done, fmt.Errorf("%w: CodeDirectory at %d claims %d bytes of a %d-byte signature",
				ErrBadSignature, o, length, len(sig))
		}
		changed, err := resignCodeDirectory(slice, sig[o:o+length], apply)
		if err != nil {
			return done, err
		}
		// Applying, "done" means a directory was restated; checking, it means
		// one disagreed with the bytes — and one is enough to condemn the file.
		if apply || changed {
			done = true
		}
		if !apply && changed {
			return true, nil
		}
	}
	return done, nil
}

// resignCodeDirectory rewrites the code slots of one CodeDirectory.
//
// Special slots (Info.plist, requirements, entitlements…) live at NEGATIVE
// indices, before hashOffset, and hash blobs we never touch — so they stay as
// they are. Only the code slots, which hash the image itself, went stale.
func resignCodeDirectory(slice, cd []byte, apply bool) (bool, error) {
	be := binary.BigEndian
	var (
		version   = be.Uint32(cd[8:])
		hashOff   = int(be.Uint32(cd[16:]))
		nCode     = int(be.Uint32(cd[28:]))
		codeLimit = int64(be.Uint32(cd[32:]))
		hashSize  = int(cd[36])
		hashType  = cd[37]
		pageShift = cd[39]
	)
	// A >4GiB image cannot state its limit in the uint32 field; version 0x20300
	// added a 64-bit one at offset 56 and leaves the old field zero.
	if version >= 0x20300 && codeLimit == 0 && len(cd) >= 64 {
		codeLimit = int64(be.Uint64(cd[56:]))
	}
	newHash, digestSize := hasherFor(hashType)
	if newHash == nil {
		return false, fmt.Errorf("fixup: unknown code signature hash type %d", hashType)
	}
	if hashSize <= 0 || hashSize > digestSize {
		return false, fmt.Errorf("%w: hash size %d is not in 1..%d for hash type %d",
			ErrBadSignature, hashSize, digestSize, hashType)
	}
	if codeLimit < 0 || codeLimit > int64(len(slice)) {
		return false, fmt.Errorf("%w: code limit %d is not within the %d-byte slice",
			ErrBadSignature, codeLimit, len(slice))
	}
	if hashOff < 0 || hashOff+nCode*hashSize > len(cd) {
		return false, fmt.Errorf("%w: %d code slots of %d bytes at offset %d run past the %d-byte CodeDirectory",
			ErrBadSignature, nCode, hashSize, hashOff, len(cd))
	}
	// pageSize 0 means the whole image is hashed as one slot rather than paged.
	page := int64(1) << pageShift
	if pageShift == 0 {
		page = codeLimit
	}
	stale := false
	for i := 0; i < nCode; i++ {
		start := int64(i) * page
		if start > codeLimit {
			return false, fmt.Errorf("%w: code slot %d of %d starts at %d, past the code limit %d",
				ErrBadSignature, i, nCode, start, codeLimit)
		}
		end := start + page
		if end > codeLimit {
			end = codeLimit
		}
		h := newHash()
		h.Write(slice[start:end])
		sum := h.Sum(nil)[:hashSize]
		slot := cd[hashOff+i*hashSize : hashOff+(i+1)*hashSize]
		if apply {
			copy(slot, sum)
			continue
		}
		if !bytes.Equal(slot, sum) {
			return true, nil
		}
	}
	return stale, nil
}

// hasherFor maps a CS_HASHTYPE_* to its constructor and full digest length.
// The truncated variant is the same digest cut to the directory's hashSize,
// which the caller applies, so it shares SHA-256's constructor.
func hasherFor(t byte) (func() hash.Hash, int) {
	switch t {
	case csHashSHA1:
		return func() hash.Hash { return sha1.New() }, sha1.Size
	case csHashSHA256, csHashSHA256Truncated:
		return func() hash.Hash { return sha256.New() }, sha256.Size
	case csHashSHA384:
		return func() hash.Hash { return sha512.New384() }, sha512.Size384
	}
	return nil, 0
}

// sliceErr names the file, and the architecture slice within it, that a
// signature refusal came from.
//
// `ErrBadSignature` on its own says a signature is malformed and nothing about
// WHOSE. `openprinting.github.io/cups` failed its rebuild with exactly that and
// no way to tell which of its binaries to look at — a guard that refuses
// without naming its subject makes the operator reproduce the whole build to
// find out what it already knew.
//
// A fat binary's slice index is part of the answer: only one architecture may
// be malformed, and "the third slice" is where to point `otool -arch` at.
func sliceErr(path string, i, n int, err error) error {
	if n <= 1 {
		return fmt.Errorf("%s: %w", path, err)
	}
	return fmt.Errorf("%s (slice %d of %d): %w", path, i, n, err)
}
