package fixup

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signedImage builds a thin Mach-O carrying one string load command and a
// valid embedded signature over everything before the signature blob.
//
// The hashes are computed here with a direct sha256/sha1 call rather than by
// calling the code under test, so a test failure means the two disagree — not
// that one function agrees with itself.
type signedImage struct {
	raw       []byte
	sigOff    int
	cdOff     int // absolute offset of the CodeDirectory
	hashOff   int // absolute offset of code slot 0
	hashSize  int
	nCode     int
	codeLimit int
}

type sigOpts struct {
	hashType  byte
	hashSize  int
	pageShift byte
	version   uint32
	nCDs      int  // how many CodeDirectories the SuperBlob holds
	badHashes bool // fill the slots with zeroes instead of the right digests
	unpaged   bool // pageSize 0: one hash covering the whole image
}

// slotPage is the byte range one code slot covers.
func (o sigOpts) slotPage(codeLimit int) int {
	if o.unpaged {
		return codeLimit
	}
	shift := o.pageShift
	if shift == 0 {
		shift = 12
	}
	return 1 << shift
}

func buildSignedMachO(t *testing.T, str string, o sigOpts) signedImage {
	t.Helper()
	if o.hashType == 0 {
		o.hashType, o.hashSize = csHashSHA256, sha256.Size
	}
	if o.pageShift == 0 {
		o.pageShift = 12
	}
	if o.version == 0 {
		o.version = 0x20400
	}
	if o.nCDs == 0 {
		o.nCDs = 1
	}
	le := binary.LittleEndian

	// LC_RPATH (string at offset 12) then LC_CODE_SIGNATURE (16 bytes).
	rpSize := 12 + len(str) + 1
	for rpSize%8 != 0 {
		rpSize++
	}
	cmds := make([]byte, rpSize+16)
	le.PutUint32(cmds[0:], lcRpath)
	le.PutUint32(cmds[4:], uint32(rpSize))
	le.PutUint32(cmds[8:], 12)
	copy(cmds[12:], str)
	sig := cmds[rpSize:]
	le.PutUint32(sig[0:], lcCodeSignature)
	le.PutUint32(sig[4:], 16)

	// The image: header + commands + filler, page-aligned so the last code
	// slot is a partial one (the case an off-by-one would get wrong).
	const imageSize = 8192 + 512
	raw := make([]byte, imageSize)
	le.PutUint32(raw[0:], 0xfeedfacf) // MH_MAGIC_64
	le.PutUint32(raw[4:], 0x0100000c) // CPU_TYPE_ARM64
	le.PutUint32(raw[12:], 2)         // MH_EXECUTE
	le.PutUint32(raw[16:], 2)         // ncmds
	le.PutUint32(raw[20:], uint32(len(cmds)))
	copy(raw[32:], cmds)
	for i := 32 + len(cmds); i < imageSize; i++ {
		raw[i] = byte(i) // something that actually changes between pages
	}
	le.PutUint32(raw[32+rpSize+8:], uint32(imageSize)) // dataoff

	page := o.slotPage(imageSize)
	nCode := (imageSize + page - 1) / page
	storedShift := o.pageShift
	if o.unpaged {
		storedShift = 0
	}
	// SuperBlob: magic, length, count, then one 8-byte index per blob.
	idx := 12 + 8*o.nCDs
	cdLen := 88 + 8 + nCode*o.hashSize // fixed fields + identifier + slots
	sigLen := idx + cdLen*o.nCDs
	blob := make([]byte, sigLen)
	be := binary.BigEndian
	be.PutUint32(blob[0:], csMagicEmbeddedSignature)
	be.PutUint32(blob[4:], uint32(sigLen))
	be.PutUint32(blob[8:], uint32(o.nCDs))
	img := signedImage{hashSize: o.hashSize, nCode: nCode, codeLimit: imageSize, sigOff: imageSize}
	for c := 0; c < o.nCDs; c++ {
		cdOff := idx + c*cdLen
		be.PutUint32(blob[12+c*8:], uint32(c)) // slot type: 0, then alternates
		be.PutUint32(blob[12+c*8+4:], uint32(cdOff))
		cd := blob[cdOff : cdOff+cdLen]
		be.PutUint32(cd[0:], csMagicCodeDirectory)
		be.PutUint32(cd[4:], uint32(cdLen))
		be.PutUint32(cd[8:], o.version)
		be.PutUint32(cd[12:], 0x20002) // adhoc | linker-signed
		be.PutUint32(cd[16:], uint32(96))
		be.PutUint32(cd[20:], uint32(88)) // identOffset
		be.PutUint32(cd[24:], 0)          // nSpecialSlots
		be.PutUint32(cd[28:], uint32(nCode))
		if o.version >= 0x20300 {
			be.PutUint64(cd[56:], uint64(imageSize)) // codeLimit64, uint32 left zero
		} else {
			be.PutUint32(cd[32:], uint32(imageSize))
		}
		cd[36] = byte(o.hashSize)
		cd[37] = o.hashType
		cd[39] = storedShift
		copy(cd[88:], "id\x00")
		if c == 0 {
			img.cdOff = imageSize + cdOff
			img.hashOff = imageSize + cdOff + 96
		}
	}
	// The command must state the blob's length as well as its offset: a
	// signature of length zero is one bk cannot even find.
	le.PutUint32(raw[32+rpSize+12:], uint32(sigLen))
	raw = append(raw, blob...)
	img.raw = raw
	if !o.badHashes {
		fillSlots(img.raw, o, nCode, idx, cdLen, imageSize)
	}
	return img
}

// fillSlots writes the correct digests into every CodeDirectory.
func fillSlots(raw []byte, o sigOpts, nCode, idx, cdLen, limit int) {
	page := o.slotPage(limit)
	for c := 0; c < o.nCDs; c++ {
		hashOff := limit + idx + c*cdLen + 96
		for i := 0; i < nCode; i++ {
			start, end := i*page, (i+1)*page
			if end > limit {
				end = limit
			}
			copy(raw[hashOff+i*o.hashSize:], slotDigest(raw[start:end], o.hashType)[:o.hashSize])
		}
	}
}

func slotDigest(b []byte, hashType byte) []byte {
	switch hashType {
	case csHashSHA1:
		h := sha1.Sum(b)
		return h[:]
	case csHashSHA384:
		h := sha512.Sum384(b)
		return h[:]
	}
	h := sha256.Sum256(b)
	return h[:]
}

func writeImage(t *testing.T, img signedImage) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "signed")
	if err := os.WriteFile(p, img.raw, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// checkSlots asserts every code slot on disk hashes the bytes now under it.
func checkSlots(t *testing.T, path string, o sigOpts, img signedImage) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if o.hashType == 0 {
		o.hashType, o.hashSize = csHashSHA256, sha256.Size
	}
	page := o.slotPage(img.codeLimit)
	for i := 0; i < img.nCode; i++ {
		start, end := i*page, (i+1)*page
		if end > img.codeLimit {
			end = img.codeLimit
		}
		want := slotDigest(raw[start:end], o.hashType)[:img.hashSize]
		got := raw[img.hashOff+i*img.hashSize : img.hashOff+(i+1)*img.hashSize]
		if !bytes.Equal(want, got) {
			t.Fatalf("slot %d: signature describes bytes that are not there\n got  %x\n want %x", i, got[:8], want[:8])
		}
	}
}

// The point of the whole file: rewriting a string leaves a signature that no
// longer describes the file, and an arm64 kernel kills such a binary with no
// message at all. After a rewrite the slots must cover what is now on disk.
func TestRewriteResignsWhatItChanged(t *testing.T) {
	o := sigOpts{}
	img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", o)
	p := writeImage(t, img)
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewriteMachoStrings(p, func(s string) string {
		return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("nothing was rewritten, so this proves nothing")
	}
	if bytes.Equal(before[img.hashOff:img.hashOff+img.hashSize], after[img.hashOff:img.hashOff+img.hashSize]) {
		t.Error("the code slot covering the load commands did not move: the signature was not restated")
	}
	checkSlots(t, p, o, img)
}

// A file we do NOT change must not be re-signed either — re-signing rewrites
// the file, and an artifact whose mtimes churn for nothing is an artifact whose
// caching cannot be trusted.
func TestUnchangedFileIsNotResigned(t *testing.T) {
	img := buildSignedMachO(t, "/opt/x/v1/lib", sigOpts{})
	p := writeImage(t, img)
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewriteMachoStrings(p, func(s string) string { return s }); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, img.raw) || !after.ModTime().Equal(before.ModTime()) {
		t.Error("an untouched Mach-O was written back")
	}
}

// Every hash algorithm a CodeDirectory can name, plus the truncated variant
// (SHA-256 cut to 20 bytes) that hashSize — not the algorithm — decides.
func TestResignHashTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    sigOpts
	}{
		{"sha256", sigOpts{hashType: csHashSHA256, hashSize: sha256.Size}},
		{"sha1", sigOpts{hashType: csHashSHA1, hashSize: sha1.Size}},
		{"sha256 truncated", sigOpts{hashType: csHashSHA256Truncated, hashSize: 20}},
		{"sha384", sigOpts{hashType: csHashSHA384, hashSize: sha512.Size384}},
		{"one hash for the whole image", sigOpts{hashType: csHashSHA256, hashSize: sha256.Size, unpaged: true}},
		{"pre-0x20300 codeLimit", sigOpts{hashType: csHashSHA256, hashSize: sha256.Size, version: 0x20100}},
		{"alternate directories", sigOpts{hashType: csHashSHA256, hashSize: sha256.Size, nCDs: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", tc.o)
			p := writeImage(t, img)
			if err := RewriteMachoStrings(p, func(s string) string {
				return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
			}); err != nil {
				t.Fatal(err)
			}
			checkSlots(t, p, tc.o, img)
		})
	}
}

// A signature bk cannot make sense of must stop the rewrite, not be written
// over: a half-understood signature restated anyway produces a binary that
// dies with no message, which is the failure this whole file exists to avoid.
func TestMalformedSignatureRefused(t *testing.T) {
	// Each case also pins what the message SAYS. ErrBadSignature on its own
	// tells an operator a signature is malformed and nothing about which file
	// or which check — `openprinting.github.io/cups` failed a rebuild with
	// exactly that, and there was no way to tell which of its binaries to open.
	for _, tc := range []struct {
		name   string
		break_ func(img *signedImage)
		want   error
		says   string
	}{
		{"blob index past the end", func(img *signedImage) {
			binary.BigEndian.PutUint32(img.raw[img.sigOff+16:], 0xfffffff0)
		}, ErrBadSignature, "blob 0 of 1 starts at"},
		{"directory longer than the blob", func(img *signedImage) {
			binary.BigEndian.PutUint32(img.raw[img.cdOff+4:], 0xfffffff0)
		}, ErrBadSignature, "CodeDirectory at"},
		{"code limit past the image", func(img *signedImage) {
			binary.BigEndian.PutUint64(img.raw[img.cdOff+56:], 1<<40)
		}, ErrBadSignature, "code limit"},
		{"hash bigger than its algorithm", func(img *signedImage) {
			img.raw[img.cdOff+36] = 64
		}, ErrBadSignature, "hash size 64 is not in"},
		{"slots past the directory", func(img *signedImage) {
			binary.BigEndian.PutUint32(img.raw[img.cdOff+28:], 1<<20)
		}, ErrBadSignature, "code slots of"},
		{"more slots than the image has pages", func(img *signedImage) {
			binary.BigEndian.PutUint64(img.raw[img.cdOff+56:], 100)
		}, ErrBadSignature, "past the code limit"},
		{"blob count past the end", func(img *signedImage) {
			binary.BigEndian.PutUint32(img.raw[img.sigOff+8:], 1<<20)
		}, ErrBadSignature, "SuperBlob claims"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", sigOpts{})
			tc.break_(&img)
			p := writeImage(t, img)
			err := RewriteMachoStrings(p, func(s string) string {
				return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("err = %q, does not say %q", err, tc.says)
			}
			if !strings.Contains(err.Error(), p) {
				t.Errorf("err = %q, does not name the file %q", err, p)
			}
		})
	}
}

// sliceErr names the architecture slice only when there is more than one: a
// thin binary has no slice to point at, and saying "slice 0 of 1" would be
// noise in every message a linux or single-arch build produces.
func TestSliceErrNamesTheSliceOnlyInAFatBinary(t *testing.T) {
	base := fmt.Errorf("%w: something", ErrBadSignature)
	thin := sliceErr("/p/lib/a.dylib", 0, 1, base)
	if !errors.Is(thin, ErrBadSignature) || strings.Contains(thin.Error(), "slice") {
		t.Errorf("thin: %v", thin)
	}
	if !strings.Contains(thin.Error(), "/p/lib/a.dylib") {
		t.Errorf("thin does not name the file: %v", thin)
	}
	fat := sliceErr("/p/lib/a.dylib", 2, 3, base)
	if !errors.Is(fat, ErrBadSignature) || !strings.Contains(fat.Error(), "slice 2 of 3") {
		t.Errorf("fat: %v", fat)
	}
}

// An unknown hash algorithm is refused by name rather than skipped: skipping
// would leave stale hashes behind, which is the outcome we cannot allow.
func TestUnknownHashTypeRefused(t *testing.T) {
	img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", sigOpts{})
	img.raw[img.cdOff+37] = 99
	p := writeImage(t, img)
	err := RewriteMachoStrings(p, func(s string) string {
		return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
	})
	if err == nil {
		t.Fatal("want an error for an algorithm we cannot compute")
	}
	if !strings.Contains(err.Error(), "hash type 99") {
		t.Errorf("err = %q, does not name the algorithm it could not compute", err)
	}
}

// An unsigned Mach-O — most linux-built and older darwin objects — is rewritten
// as before. Nothing to restate is not an error.
func TestUnsignedMachOStillRewrites(t *testing.T) {
	p := buildMachO(t, machoCmd{lcIDDylib, "/opt/x/v1+brewing/lib/libz.dylib"})
	if err := RewriteMachoStrings(p, func(s string) string {
		return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
	}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(p)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "/opt/x/v1/lib/libz.dylib" {
		t.Errorf("string = %q", got[0])
	}
}

// A blob that is not an embedded signature (a detached one, or a format we do
// not know) is left alone rather than parsed as one.
func TestForeignSignatureBlobLeftAlone(t *testing.T) {
	img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", sigOpts{})
	binary.BigEndian.PutUint32(img.raw[img.sigOff:], 0xfade0b01) // a CMS blob
	p := writeImage(t, img)
	if err := RewriteMachoStrings(p, func(s string) string {
		return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
	}); err != nil {
		t.Fatal(err)
	}
}

// LC_CODE_SIGNATURE can point past the end of the file — a truncated download,
// or a load command we misread. Refuse rather than index into it.
func TestSignatureOutOfBounds(t *testing.T) {
	img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", sigOpts{})
	le := binary.LittleEndian
	// The LC_CODE_SIGNATURE dataoff sits right after the LC_RPATH command.
	rpSize := int(le.Uint32(img.raw[36:]))
	le.PutUint32(img.raw[32+rpSize+8:], uint32(len(img.raw)-4))
	p := writeImage(t, img)
	err := RewriteMachoStrings(p, func(s string) string {
		return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
	})
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// A SuperBlob holds more than code directories — requirements, entitlements, a
// CMS envelope. Anything that is not a directory is stepped over, not parsed as
// one, and the directories beside it are still restated.
func TestNonDirectoryBlobsAreSteppedOver(t *testing.T) {
	o := sigOpts{nCDs: 2, hashType: csHashSHA256, hashSize: sha256.Size}
	img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", o)
	// Turn the second directory into a requirements blob.
	be := binary.BigEndian
	second := img.sigOff + int(be.Uint32(img.raw[img.sigOff+12+8+4:]))
	be.PutUint32(img.raw[second:], 0xfade0c01)
	p := writeImage(t, img)
	if err := RewriteMachoStrings(p, func(s string) string {
		return string(bytes.ReplaceAll([]byte(s), []byte("+brewing"), nil))
	}); err != nil {
		t.Fatal(err)
	}
	checkSlots(t, p, o, img)
}

// A load command whose size is nonsense stops the walk rather than sending it
// off the end of the image. There is then no signature to restate, which is
// not an error — the caller has already rewritten what it came to rewrite.
func TestMalformedLoadCommandStopsTheSearch(t *testing.T) {
	img := buildSignedMachO(t, "/opt/x/v1/lib", sigOpts{})
	binary.LittleEndian.PutUint32(img.raw[36:], 0) // LC_RPATH cmdsize = 0
	found, err := resignSlice(img.raw, binary.LittleEndian, 32, 2)
	if err != nil {
		t.Fatalf("err = %v, want none", err)
	}
	if found {
		t.Error("claimed to have found a signature past a command it could not read")
	}
}

// MachoSignatureStale must answer the question `codesign -v` answers, on
// machines that do not have codesign and about artifacts built for a platform
// the asking machine is not — which is what makes a fleet-wide sweep possible.
func TestMachoSignatureStale(t *testing.T) {
	t.Run("a signature that describes the bytes", func(t *testing.T) {
		p := writeImage(t, buildSignedMachO(t, "/opt/x/v1/lib", sigOpts{}))
		stale, err := MachoSignatureStale(p)
		if err != nil {
			t.Fatal(err)
		}
		if stale {
			t.Error("called an untouched binary stale")
		}
	})
	t.Run("a signature that does not", func(t *testing.T) {
		p := writeImage(t, buildSignedMachO(t, "/opt/x/v1/lib", sigOpts{badHashes: true}))
		stale, err := MachoSignatureStale(p)
		if err != nil {
			t.Fatal(err)
		}
		if !stale {
			t.Error("missed a signature that no longer describes the file")
		}
	})
	t.Run("edited in place, unrepaired", func(t *testing.T) {
		// The exact state every darwin artifact built before re-signing is in:
		// the load command was rewritten and the hashes were left behind.
		img := buildSignedMachO(t, "/opt/x/v1+brewing/lib", sigOpts{})
		p := writeImage(t, img)
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		copy(raw[44:], "/opt/x/v1/lib\x00\x00\x00\x00\x00\x00\x00\x00")
		if err := os.WriteFile(p, raw, 0o755); err != nil {
			t.Fatal(err)
		}
		stale, err := MachoSignatureStale(p)
		if err != nil {
			t.Fatal(err)
		}
		if !stale {
			t.Error("an edited, unrepaired binary read as sound")
		}
	})
	t.Run("unsigned", func(t *testing.T) {
		p := buildMachO(t, machoCmd{lcIDDylib, "/opt/x/v1/lib/libz.dylib"})
		stale, err := MachoSignatureStale(p)
		if err != nil {
			t.Fatal(err)
		}
		if stale {
			// Nothing claims anything about these bytes, so nothing disagrees.
			t.Error("an unsigned Mach-O cannot be stale")
		}
	})
	t.Run("not a Mach-O", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "script")
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := MachoSignatureStale(p); err == nil {
			t.Error("want an error for something that is not a Mach-O")
		}
	})
	t.Run("a signature we cannot read", func(t *testing.T) {
		img := buildSignedMachO(t, "/opt/x/v1/lib", sigOpts{})
		img.raw[img.cdOff+37] = 99 // an algorithm we cannot compute
		p := writeImage(t, img)
		if _, err := MachoSignatureStale(p); err == nil {
			t.Error("want an error rather than a verdict we cannot justify")
		}
	})
}
