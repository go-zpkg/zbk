package fixup

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// fatMagic64 is the 64-bit universal-binary magic (FAT_MAGIC_64, big-endian on
// disk); debug/macho only knows the 32-bit macho.MagicFat (0xcafebabe).
const fatMagic64 = 0xcafebabf

// Mach-O load commands that carry a path/name string at struct offset 8
// (DylibCmd.Name and RpathCmd.Path are both the third uint32).
const (
	lcReqDyld       = 0x80000000
	lcLoadDylib     = 0xc
	lcIDDylib       = 0xd
	lcLoadWeakDylib = 0x18 | lcReqDyld
	lcReexportDylib = 0x1f | lcReqDyld
	lcRpath         = 0x1c | lcReqDyld
)

func machoStringCmd(cmd uint32) bool {
	switch cmd {
	case lcLoadDylib, lcIDDylib, lcLoadWeakDylib, lcReexportDylib, lcRpath:
		return true
	}
	return false
}

// isMachO reports whether path is a Mach-O object, thin or fat (universal).
func isMachO(path string) bool {
	_, _, err := machoInfo(path)
	return err == nil
}

// machoSlice locates one architecture slice inside a Mach-O file (a thin file
// is a single slice spanning the whole file): byte range, byte order, header
// size and load-command count.
type machoSlice struct {
	off, size int
	bo        binary.ByteOrder
	hdr, ncmd int
}

// machoInfo reads a Mach-O (thin or fat) and returns its raw bytes plus the
// parsed header info of every architecture slice.
func machoInfo(path string) ([]byte, []machoSlice, error) {
	raw, err := osReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	slices, err := machoSlices(raw)
	if err != nil {
		return nil, nil, err
	}
	return raw, slices, nil
}

// machoSlices parses raw as a thin or fat (universal) Mach-O. A fat file
// starts with FAT_MAGIC/FAT_MAGIC_64 and nfat_arch (both uint32 BE) followed
// by nfat_arch fat_arch entries; each entry locates one thin slice.
func machoSlices(raw []byte) ([]machoSlice, error) {
	if len(raw) >= 8 {
		switch binary.BigEndian.Uint32(raw) {
		case macho.MagicFat:
			ff, err := macho.NewFatFile(bytes.NewReader(raw))
			if err != nil {
				return nil, err
			}
			var out []machoSlice
			for _, a := range ff.Arches {
				hdr := 28
				if a.Magic == macho.Magic64 {
					hdr = 32
				}
				out = append(out, machoSlice{off: int(a.Offset), size: int(a.Size), bo: a.ByteOrder, hdr: hdr, ncmd: int(a.Ncmd)})
			}
			return out, nil
		case fatMagic64:
			return fat64Slices(raw)
		}
	}
	sl, err := thinSlice(raw, 0, len(raw))
	if err != nil {
		return nil, err
	}
	return []machoSlice{sl}, nil
}

// fat64Slices hand-parses a FAT_MAGIC_64 header (debug/macho only supports the
// 32-bit fat format): nfat_arch fat_arch_64 entries of 32 bytes — cputype(4)
// cpusubtype(4) offset(8) size(8) align(4) reserved(4) — offset and size as
// uint64 BE at entry offsets 8 and 16.
func fat64Slices(raw []byte) ([]machoSlice, error) {
	be := binary.BigEndian
	narch := int(be.Uint32(raw[4:]))
	var out []machoSlice
	for i := 0; i < narch; i++ {
		e := 8 + i*32
		if e+32 > len(raw) {
			return nil, errors.New("fixup: truncated fat_arch_64 table")
		}
		sl, err := thinSlice(raw, int(be.Uint64(raw[e+8:])), int(be.Uint64(raw[e+16:])))
		if err != nil {
			return nil, err
		}
		out = append(out, sl)
	}
	return out, nil
}

// thinSlice parses the thin Mach-O header at raw[off:off+size].
func thinSlice(raw []byte, off, size int) (machoSlice, error) {
	if off < 0 || off > len(raw) || size < 0 || size > len(raw)-off {
		return machoSlice{}, errors.New("fixup: Mach-O slice out of bounds")
	}
	f, err := macho.NewFile(bytes.NewReader(raw[off : off+size]))
	if err != nil {
		return machoSlice{}, err
	}
	hdr := 28
	if f.Magic == macho.Magic64 {
		hdr = 32
	}
	sl := machoSlice{off: off, size: size, bo: f.ByteOrder, hdr: hdr, ncmd: int(f.Ncmd)}
	f.Close()
	return sl, nil
}

// walkMachoStrings visits each dylib-name/rpath string, replacing it in raw with
// visit's return value (in place). It reports whether anything changed and
// returns ErrNoSpace if a replacement is longer than its fixed load-command slot.
func walkMachoStrings(raw []byte, bo binary.ByteOrder, hdr, ncmd int, visit func(cmd uint32, s string) string) (bool, error) {
	changed := false
	off := hdr
	for i := 0; i < ncmd && off+8 <= len(raw); i++ {
		cmd := bo.Uint32(raw[off:])
		size := int(bo.Uint32(raw[off+4:]))
		if size < 8 || off+size > len(raw) {
			break
		}
		if machoStringCmd(cmd) {
			strOff := int(bo.Uint32(raw[off+8:]))
			start, end := off+strOff, off+size
			if strOff >= 8 && start <= end {
				old := cstr(raw[start:end])
				if nw := visit(cmd, old); nw != old {
					if len(nw) >= end-start {
						extra, err := growMachoCmd(raw, bo, hdr, ncmd, off, strOff+len(nw)+1)
						if err != nil {
							return changed, err
						}
						size += extra
						end = off + size
					}
					for j := start; j < end; j++ {
						raw[j] = 0
					}
					copy(raw[start:], nw)
					changed = true
				}
			}
		}
		off += size
	}
	return changed, nil
}

// growMachoCmd lengthens one load command in place so a longer string fits,
// and reports by how much.
//
// A Mach-O's load commands live in a contiguous run between the header and the
// first section's file data, and the linker leaves slack there — 8284 bytes in
// our published zstd dylib, 5604 in its `zstd` binary, 2072 in upstream pkgx's
// copy of the same library. So a command CAN be made longer: raise its
// cmdsize, slide every command after it down, raise the header's sizeofcmds.
// Nothing else moves — no section, no segment, no offset recorded anywhere
// else in the file — because the run only grows into space that was already
// reserved for it.
//
// This is what makes an install name fixable at all. An install name is not
// invented: it is derived from where the file already is, and the correct value
// (@rpath/facebook.com/zstd/v1.5.7/lib/libzstd.1.5.7.dylib) is LONGER than the
// wrong one CMake writes by default (@rpath/libzstd.1.dylib). Refusing to grow
// meant refusing to fix it, silently — see #125, where a bare install name
// aborted every consumer of the zstd artifact at dyld time.
//
// It is NOT a way around the LC_RPATH rule. An rpath must still be linked in at
// build time, because its VALUE — how deep the package installs — is not
// recoverable from the binary; the constraint there was never the byte count.
func growMachoCmd(raw []byte, bo binary.ByteOrder, hdr, ncmd, off, want int) (int, error) {
	// 32-bit slices are not grown: their segment/section structs have a
	// different shape and no darwin target we build for is 32-bit. Refusing is
	// the same answer as before this function existed. (hdr is the header SIZE:
	// 32 for a 64-bit Mach-O, 28 for a 32-bit one.)
	if hdr != 32 {
		return 0, ErrNoSpace
	}
	size := int(bo.Uint32(raw[off+4:]))
	grown := (want + 7) &^ 7
	if grown <= size {
		return 0, nil
	}
	extra := grown - size
	sizeofcmds := int(bo.Uint32(raw[20:]))
	end := hdr + sizeofcmds
	limit, ok := machoCmdLimit(raw, bo, hdr, ncmd)
	if !ok || end+extra > limit || end+extra > len(raw) {
		return 0, ErrNoSpace
	}
	copy(raw[off+size+extra:end+extra], raw[off+size:end])
	for j := off + size; j < off+size+extra; j++ {
		raw[j] = 0
	}
	bo.PutUint32(raw[off+4:], uint32(grown))
	bo.PutUint32(raw[20:], uint32(sizeofcmds+extra))
	return extra, nil
}

// machoCmdLimit returns the file offset the load commands must not reach: the
// lowest file offset of any section that has one. A zero offset means a
// zero-fill section (__bss and friends), which occupies no file bytes and
// bounds nothing.
func machoCmdLimit(raw []byte, bo binary.ByteOrder, hdr, ncmd int) (int, bool) {
	const (
		lcSegment64 = 0x19
		segHdr      = 72 // segment_command_64 up to the first section
		sectSize    = 80 // section_64
		sectOffset  = 48 // section_64.offset
	)
	limit, found := 0, false
	off := hdr
	for i := 0; i < ncmd && off+8 <= len(raw); i++ {
		cmd := bo.Uint32(raw[off:])
		size := int(bo.Uint32(raw[off+4:]))
		if size < 8 || off+size > len(raw) {
			return 0, false
		}
		if cmd == lcSegment64 && size >= segHdr {
			nsects := int(bo.Uint32(raw[off+64:]))
			for j := 0; j < nsects; j++ {
				so := off + segHdr + j*sectSize
				if so+sectSize > off+size {
					return 0, false
				}
				fo := int(bo.Uint32(raw[so+sectOffset:]))
				if fo == 0 {
					continue
				}
				if !found || fo < limit {
					limit, found = fo, true
				}
			}
		}
		off += size
	}
	return limit, found
}

// ReadMachoStrings returns the install name, dylib references and rpaths of a
// Mach-O (LC_ID_DYLIB, LC_LOAD_DYLIB and friends, LC_RPATH), from every
// architecture slice of a fat binary.
func ReadMachoStrings(path string) ([]string, error) {
	raw, slices, err := machoInfo(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, sl := range slices {
		walkMachoStrings(raw[sl.off:sl.off+sl.size], sl.bo, sl.hdr, sl.ncmd, func(_ uint32, s string) string {
			out = append(out, s)
			return s
		})
	}
	return out, nil
}

// MachoNeeded is what a Mach-O LOADS: its LC_LOAD_DYLIB, weak and re-export
// entries, and nothing else.
//
// ReadMachoStrings returns every load-command string, which includes the
// file's OWN install name (LC_ID_DYLIB) and its LC_RPATH entries. Counting the
// install name as a dependency makes a library appear to depend on wherever it
// happens to live — the ELF side has had ReadNeeded for exactly this reason,
// and the Mach-O side had no equivalent.
func MachoNeeded(path string) ([]string, error) {
	raw, slices, err := machoInfo(path)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, sl := range slices {
		walkMachoStrings(raw[sl.off:sl.off+sl.size], sl.bo, sl.hdr, sl.ncmd, func(cmd uint32, s string) string {
			switch cmd {
			case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib:
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
			return s
		})
	}
	return out, nil
}

// RewriteMachoStrings rewrites every dylib-name/rpath string in a Mach-O in
// place by applying fn — every architecture slice of a fat binary. It cannot
// grow a string (Mach-O load commands are a fixed size), so a longer
// replacement returns ErrNoSpace; a shorter one is zero-padded. Stripping a
// staging suffix (…+brewing) always shrinks, so fits.
//
// Any slice it changes is re-signed (see machosign.go): an edited Mach-O whose
// signature still describes the old bytes is not a binary with a stale
// signature, it is a binary that cannot run at all.
func RewriteMachoStrings(path string, fn func(string) string) error {
	return rewriteMachoStringsCmd(path, func(_ uint32, s string) string { return fn(s) })
}

// rewriteMachoStringsCmd is RewriteMachoStrings with the load command in hand:
// an rpath and an install name are both strings in the same kind of slot, and
// what each may be rewritten to is not the same.
func rewriteMachoStringsCmd(path string, fn func(uint32, string) string) error {
	return editMacho(path, func(slice []byte, sl machoSlice) (bool, int, error) {
		ch, err := walkMachoStrings(slice, sl.bo, sl.hdr, sl.ncmd, fn)
		return ch, sl.ncmd, err
	})
}

// editMacho applies edit to every architecture slice of a Mach-O, re-signs each
// slice it changed, and writes the file back if anything changed. edit returns
// whether it changed the slice and the slice's load-command count afterwards
// (the signature walk needs the CURRENT count, and a command removal alters it).
func editMacho(path string, edit func(slice []byte, sl machoSlice) (bool, int, error)) error {
	raw, slices, err := machoInfo(path)
	if err != nil {
		return err
	}
	changed := false
	for i, sl := range slices {
		slice := raw[sl.off : sl.off+sl.size]
		ch, ncmd, err := edit(slice, sl)
		changed = changed || ch
		if err != nil {
			return err
		}
		// A rewritten slice no longer matches its own signature, and on Apple
		// silicon the kernel kills such a binary outright — with no message, no
		// dyld error, just exit 137. Restate the hashes over what we just wrote.
		if ch {
			if _, err := resignSlice(slice, sl.bo, sl.hdr, ncmd); err != nil {
				return sliceErr(path, i, len(slices), err)
			}
		}
	}
	if !changed {
		return nil
	}
	mode, err := modeOf(path)
	if err != nil {
		return err
	}
	restore, err := ensureWritable(path)
	if err != nil {
		return err
	}
	defer restore()
	return osWriteFile(path, raw, mode)
}

// ErrMachoCmds means the load-command run of a Mach-O is not shaped the way
// the format says, so a command cannot be removed from it safely.
var ErrMachoCmds = errors.New("fixup: malformed Mach-O load commands")

// dropRpathCmds deletes, from one thin slice, every LC_RPATH whose path drop
// accepts, and reports how many it removed and the load-command count left.
//
// <mach-o/loader.h> defines a load command by (cmd, cmdsize) and the header by
// (ncmds, sizeofcmds); nothing else records where a command sits, so removing
// one is: slide the later commands down over it, zero the vacated tail, lower
// both header counts. No section, segment or offset elsewhere in the file moves,
// because the run only SHRINKS — the freed bytes become more of the padding the
// linker leaves after the commands. (Compare growMachoCmd, which needs that
// padding.) The header and the commands are inside the first hashed page, so the
// caller re-signs.
func dropRpathCmds(slice []byte, bo binary.ByteOrder, hdr, ncmd int, drop func(string) bool) (removed, left int, err error) {
	end := hdr + int(bo.Uint32(slice[20:]))
	if end > len(slice) {
		return 0, ncmd, fmt.Errorf("%w: sizeofcmds runs past the %d-byte slice", ErrMachoCmds, len(slice))
	}
	read, write := hdr, hdr
	for i := 0; i < ncmd; i++ {
		if read+8 > end {
			return 0, ncmd, fmt.Errorf("%w: command %d of %d starts past the command run", ErrMachoCmds, i, ncmd)
		}
		cmd := bo.Uint32(slice[read:])
		size := int(bo.Uint32(slice[read+4:]))
		if size < 8 || read+size > end {
			return 0, ncmd, fmt.Errorf("%w: command %d of %d has cmdsize %d", ErrMachoCmds, i, ncmd, size)
		}
		if cmd == lcRpath {
			if strOff := int(bo.Uint32(slice[read+8:])); strOff >= 8 && strOff <= size && drop(cstr(slice[read+strOff:read+size])) {
				read += size
				removed++
				continue
			}
		}
		copy(slice[write:], slice[read:read+size])
		write += size
		read += size
	}
	if removed == 0 {
		return 0, ncmd, nil
	}
	for j := write; j < end; j++ {
		slice[j] = 0
	}
	left = ncmd - removed
	bo.PutUint32(slice[16:], uint32(left))
	bo.PutUint32(slice[20:], uint32(write-hdr))
	return removed, left, nil
}

// dropMachoRpaths removes the LC_RPATH entries of every slice that drop
// accepts, re-signs what it changed, and returns how many entries it removed.
func dropMachoRpaths(path string, drop func(string) bool) (int, error) {
	total := 0
	err := editMacho(path, func(slice []byte, sl machoSlice) (bool, int, error) {
		n, left, err := dropRpathCmds(slice, sl.bo, sl.hdr, sl.ncmd, drop)
		total += n
		return n > 0, left, err
	})
	return total, err
}

// dropRpaths is a seam so the removal's failure is reachable from rewriteMacho.
var dropRpaths = dropMachoRpaths

// builderRpath reports whether an LC_RPATH is an ABSOLUTE path into the
// builder's store — $ZPKG_DIR as the build ran, never a literal. On the
// machine that built the artifact it is a fallback that resolves; anywhere else
// it resolves to nothing and only says where the builder keeps its files
// (go-zpkg/bk#395). A path outside the store is somebody else's decision and is
// not touched here.
func builderRpath(rpath, store string) bool {
	if store == "" || !filepath.IsAbs(rpath) {
		return false
	}
	clean, dir := filepath.Clean(rpath), filepath.Clean(store)
	if clean == dir {
		return true
	}
	_, under := underDir(clean, dir)
	return under
}

// machoID returns a Mach-O's LC_ID_DYLIB, or "" for a file that has none
// (an executable, a loadable bundle, or anything unreadable).
func machoID(path string) string {
	raw, slices, err := machoInfo(path)
	if err != nil {
		return ""
	}
	id := ""
	for _, sl := range slices {
		walkMachoStrings(raw[sl.off:sl.off+sl.size], sl.bo, sl.hdr, sl.ncmd, func(cmd uint32, s string) string {
			if cmd == lcIDDylib && id == "" {
				id = s
			}
			return s
		})
	}
	return id
}

// machoRpaths returns a Mach-O's LC_RPATH entries.
func machoRpaths(path string) ([]string, error) {
	raw, slices, err := machoInfo(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, sl := range slices {
		walkMachoStrings(raw[sl.off:sl.off+sl.size], sl.bo, sl.hdr, sl.ncmd, func(cmd uint32, s string) string {
			if cmd == lcRpath {
				out = append(out, s)
			}
			return s
		})
	}
	return out, nil
}

// rpathReaches reports whether any of a Mach-O's rpaths resolves to dir once
// the binary sits at exe. @loader_path is resolved against the file's own
// directory — which, fixup running after the staging tree has been renamed
// into place, is where it will actually be.
func rpathReaches(exe, dir string, rpaths []string) bool {
	want := filepath.Clean(dir)
	for _, r := range rpaths {
		var got string
		switch {
		case strings.HasPrefix(r, "@loader_path/"), strings.HasPrefix(r, "@executable_path/"):
			_, rel, _ := strings.Cut(r, "/")
			got = filepath.Join(filepath.Dir(exe), rel)
		case filepath.IsAbs(r):
			got = filepath.Clean(r)
		default:
			continue
		}
		if got == want {
			return true
		}
	}
	return false
}

// underDir reports whether p names something inside dir, and what it is called
// there. A prefix match alone would accept "/x/pkgxdirty" for "/x/pkgxdir".
func underDir(p, dir string) (string, bool) {
	if dir == "" {
		return "", false
	}
	dir = filepath.Clean(dir) + string(filepath.Separator)
	if !strings.HasPrefix(p, dir) || len(p) == len(dir) {
		return "", false
	}
	return filepath.ToSlash(p[len(dir):]), true
}

// relativeRpath turns an ABSOLUTE rpath pointing inside $ZPKG_DIR into the
// @loader_path one that means the same thing, and reports whether it changed.
//
// This is the third defect of a darwin artifact, distinct from a bare install
// name and from an absolute reference: the REFERENCE is relocated and the
// SEARCH ROOT is not. gnu.org/help2man's perl XS records
//
//	@rpath/gnu.org/gettext/v1/lib/libintl.8.dylib
//
// — correct, relocatable, qualified — and carries exactly two rpaths, both of
// them paths on the machine that built it (/Users/runner/.pkgx and
// .../gnu.org/gettext/v1.0.0/lib). Off that machine the reference resolves
// against nothing, and on darwin there is no second chance: dyld ignores
// LD_LIBRARY_PATH, SIP strips DYLD_LIBRARY_PATH, and pkgx's --library-path
// branch is linux-only. The artifact's own rpaths are the whole mechanism.
//
// It cannot be repaired by linking deeper rpaths in: bk emits @loader_path
// depths 4 through 8, measured for <prefix>/bin and <prefix>/lib, and this
// bundle installs NINE levels below its prefix
// (lib/perl5/darwin-thread-multi-2level/auto/Locale/gettext/). No fixed set of
// depths covers where a package chooses to put things.
//
// It is not the LC_RPATH rule either. That rule refuses to INVENT an rpath,
// because how deep a package installs is not recoverable from a binary. Here
// nothing is invented: the absolute rpath states the target and the file's own
// location states the depth, so the relative spelling is derived from two
// things already in hand — the same footing as deriving an install name from
// where the file is.
func relativeRpath(exe, rpath, zpkgDir string) (string, bool) {
	// exe must be absolute too, not merely under an absolute dir: it is what
	// makes the filepath.Rel below total, so the call needs no error branch —
	// and a branch no test can reach is a line the coverage gate is right to
	// refuse.
	if zpkgDir == "" || !filepath.IsAbs(rpath) || !filepath.IsAbs(exe) {
		return rpath, false
	}
	clean := filepath.Clean(rpath)
	dir := filepath.Clean(zpkgDir)
	if _, under := underDir(clean, dir); !under && clean != dir {
		return rpath, false
	}
	// A file outside $ZPKG_DIR would get a relative path climbing out of the
	// tree, which is neither shorter nor more portable than what it replaces.
	if _, under := underDir(exe, dir); !under {
		return rpath, false
	}
	rel, _ := filepath.Rel(filepath.Dir(exe), clean)
	if rel == "." {
		return "@loader_path", true
	}
	return "@loader_path/" + filepath.ToSlash(rel), true
}

// rewriteMacho strips the +brewing staging prefix from a Mach-O's install name
// and dep references (buildInstall → prefix), the darwin analogue of the .pc /
// .cmake path rewrite. Removing +brewing shrinks the string, so it always fits.
func rewriteMacho(exe string, opts Options) error {
	if !isMachO(exe) {
		return nil
	}
	if err := rewriteMachoRefs(exe, opts); err != nil {
		return err
	}
	// What rewriteRefs could not restate relatively is still the builder's path
	// (a duplicate of an entry bk linked in, or a file that is not under the
	// store yet). It is a search root that only means something on the build
	// machine, so it goes: the relative entries are the mechanism (go-zpkg/bk#395).
	n, err := dropRpaths(exe, func(s string) bool { return builderRpath(s, opts.ZpkgDir) })
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	opts.log("macho %s: removed %d absolute rpath(s) into the builder's store %s", exe, n, opts.ZpkgDir)
	// Removing every rpath of a file that still names @rpath/… would leave it
	// unloadable anywhere; say so now rather than at someone's dyld.
	return checkRpathResolvable(exe, opts)
}

// rewriteMachoRefs is the install-name / reference / rpath-relativising half of
// rewriteMacho.
func rewriteMachoRefs(exe string, opts Options) error {
	// A darwin binary names its dependencies by ABSOLUTE install name — the
	// LC_ID_DYLIB the dependency was built with, which is a path on the machine
	// that built it:
	//
	//   Library not loaded: /Users/runner/.pkgx/libssh2.org/v1.11.1/lib/libssh2.1.dylib
	//
	// That is what makes a darwin artifact unusable anywhere but its build
	// machine, and no rpath rescues it: an absolute reference never consults
	// one. Rewriting those into @rpath/… is what makes the artifact relocatable.
	//
	// But ONLY if this file carries an rpath that reaches $ZPKG_DIR. Turning a
	// reference that works on the build machine into an @rpath one that
	// resolves nowhere would trade an artifact that works in one place for a
	// artifact that works in none — so it is measured per file, not assumed.
	toRpath := false
	// Whether any rpath is a builder path we can restate relatively. It is
	// tracked apart from toRpath because the two are independent: a file can
	// carry an rpath that reaches $ZPKG_DIR on the builder and nowhere else,
	// which is precisely the case worth repairing.
	relocRpath := false
	// Every rpath spelling the file already carries. Relativising an absolute
	// one can land on a string that is ALREADY there — bk links in
	// @loader_path/../../../.. itself, and a file four levels below $ZPKG_DIR
	// whose build also recorded the absolute path produces exactly that — and a
	// duplicate LC_RPATH is not cosmetic:
	//
	//	ld: duplicate LC_RPATH '@loader_path/../../../..' in
	//	    .../facebook.com/folly/v2026.09.14.00/lib/libfolly.0.58.0-dev.dylib
	//	c++: error: linker command failed with exit code 1
	//
	// Every dependent then fails to link. Measured on the folly artifact this
	// factory published: 2 × @loader_path/../../../.. where one is bk's and one
	// came from the rewrite. Leaving the absolute entry alone keeps a builder
	// path in the artefact, which is a leak; writing the duplicate breaks
	// everything downstream, which is a break. The leak is the better trade,
	// and the reaching relative rpath the guard asks for is present either way.
	taken := map[string]bool{}
	if opts.ZpkgDir != "" {
		rpaths, err := machoRpaths(exe)
		if err != nil {
			return err
		}
		toRpath = rpathReaches(exe, opts.ZpkgDir, rpaths)
		for _, r := range rpaths {
			taken[r] = true
		}
		for _, r := range rpaths {
			rel, ok := relativeRpath(exe, r, opts.ZpkgDir)
			if ok && !taken[rel] {
				relocRpath = true
				break
			}
		}
		if !toRpath {
			opts.log("macho %s: no rpath reaching %s, leaving install names absolute", exe, opts.ZpkgDir)
		}
	}
	// An install name says where THIS file is; whether it resolves depends on
	// the CONSUMER's rpath, not on this file's. So it is fixed even for a
	// library that needs no rpath of its own — sourceware.org/bzip2's
	// libbz2.1.0.8.dylib links nothing but libSystem, therefore never gets a
	// $ZPKG_DIR-reaching rpath, therefore kept its unresolvable "libbz2.dylib"
	// id through a rebuild that was meant to repair exactly that. Qualifying it
	// is never worse than leaving it: a consumer without a $ZPKG_DIR rpath
	// fails on either spelling.
	fixableID := false
	if _, ok := qualifyID(exe, machoID(exe), opts); ok {
		fixableID = true
	}
	// A BARE reference to a file this package ships is repairable even here,
	// with @loader_path, which needs no rpath. Without this term the file took
	// the "nothing to rewrite" exit below and met the guard instead — which is
	// how mpdecimal's rebuild was refused with no way forward.
	fixableSibling := false
	if refs, rerr := readMachoRefs(exe); rerr == nil {
		for _, r := range refs {
			if _, ok := loaderPathRef(exe, r, opts); ok {
				fixableSibling = true
				break
			}
		}
	}
	if opts.BuildInstall == "" && !toRpath && !fixableID && !relocRpath && !fixableSibling {
		// Nothing to rewrite — but a file that already references @rpath with no
		// LC_RPATH is dead however little we touch it, and this is the branch it
		// arrives on.
		return checkRpathResolvable(exe, opts)
	}
	// The initial rpath set, kept so the second pass below starts where the
	// first did rather than from what the first pass left behind.
	taken0 := make(map[string]bool, len(taken))
	for k := range taken {
		taken0[k] = true
	}
	// An ABI line is LONGER than the major directory it replaces
	// (abi-libxml2.16.dylib against v2), and a load-command string cannot grow
	// past the header padding the linker left. Where it does not fit, the
	// answer is the major — not nothing: skipping the file would give up the
	// relocation that was already working and leave a builder path in the
	// artifact.
	useABI := true
	rewrite := func(cmd uint32, s string) string {
		if opts.BuildInstall != "" {
			s = strings.ReplaceAll(s, opts.BuildInstall, opts.Prefix)
		}
		if cmd == lcIDDylib {
			if q, ok := qualifyID(exe, s, opts); ok {
				return q
			}
		}
		// An rpath is a search ROOT, not a reference: @rpath means nothing
		// inside one, and the relative entries were linked in already. The one
		// thing worth saying about a search root is where it is: an absolute
		// one names a directory on the build machine.
		if cmd == lcRpath {
			r, ok := relativeRpath(exe, s, opts.ZpkgDir)
			if ok && !taken[r] {
				taken[r] = true
				return r
			}
			return s
		}
		if !toRpath {
			// No rpath reaches $ZPKG_DIR — often no LC_RPATH at all — so
			// nothing below can help: an @rpath reference rewritten to another
			// @rpath reference still resolves nowhere. A SIBLING needs no
			// rpath, though. mpdecimal's C++ library records
			//
			//	@rpath/libmpdec.3.dylib
			//
			// for a file sitting beside it, and the build has been refused
			// since the guard went in — correctly, and with no way forward.
			// @loader_path answers it exactly, and is independent of where the
			// store is mounted.
			if lp, ok := loaderPathRef(exe, s, opts); ok {
				return lp
			}
			return s
		}
		// A reference that is ALREADY @rpath/… — because the dependency was
		// itself built with an @rpath install name — never passed through the
		// absolute-path branch below, so its version stayed whole. Measured on
		// the grep artifact rebuilt once pcre2 had been: it recorded
		// @rpath/pcre.org/v2/v10.48/lib/libpcre2-8.0.dylib, which breaks again
		// the day pcre2 reaches 10.49. The relocation was right and the version
		// was not.
		if rest, ok := strings.CutPrefix(s, "@rpath/"); ok && cmd != lcRpath {
			// A BARE @rpath/<soname> — no directory — is the consumer half of
			// the defect qualifyID fixes on the producer. Qualifying the
			// library's own install name only helps what is linked AFTER; every
			// dependent already carries the bare string, and nothing rewrote it.
			//
			// It resolves nowhere: an rpath entry points at $ZPKG_DIR or at a
			// package root, never at some other package's lib dir, so dyld
			// joins the soname onto a directory that does not contain it.
			// Measured on the published catalogue — the reference and the file
			// it wants are in the SAME package, three of them:
			//
			//   libjpeg-turbo.org  bin/cjpeg  -> @rpath/libjpeg.8.dylib
			//   bytereef.org/mpdecimal  lib/libmpdec++.2.5.1.dylib -> @rpath/libmpdec.3.dylib
			//
			// cjpeg cannot start at all; the mpdecimal one waits for whoever
			// loads the C++ library. Both ship the file one directory away.
			//
			// Only a name that is really there is rewritten — the package's own
			// lib dir, or the referring file's — so this can invent nothing. A
			// bare name whose file belongs to a DEPENDENCY is left alone: which
			// package it came from is not something to guess at.
			if q, ok := qualifyRef(exe, rest, opts); ok {
				return q
			}
			full := filepath.Join(opts.ZpkgDir, rest)
			t := abiOrMajor(full, opts, useABI)
			if short, ok := underDir(t, opts.ZpkgDir); ok {
				return "@rpath/" + short
			}
			return s
		}
		if _, ok := underDir(s, opts.ZpkgDir); ok {
			// Major-versioned, exactly as the ELF side does to its RUNPATH
			// entries, and for the reason measured on the published grep artifact:
			// it named
			//
			//   /Users/runner/.pkgx/pcre.org/v2/v10.47/lib/libpcre2-8.0.dylib
			//
			// and the machine had pcre2 v10.48. grep could not start, so curl's
			// configure reported "'grep' utility not found in 'PATH'" — a
			// dependency's MINOR upgrade orphaning its dependents, reported as
			// a missing tool.
			//
			// pkgx installs each version in its own directory AND links the
			// major (v1 -> v1.3.2, v3 -> v3.6.4 — measured in an installed
			// tree), so v10 resolves to whatever 10.x is there. A package's own
			// libraries keep their full version: they ship together and cannot
			// disagree.
			t := abiOrMajor(s, opts, useABI)
			rest, _ := underDir(t, opts.ZpkgDir)
			return "@rpath/" + rest
		}
		return s
	}
	err := rewriteMachoStringsCmd(exe, rewrite)
	if errors.Is(err, ErrNoSpace) && useABI {
		useABI = false
		taken = taken0
		opts.log("macho %s: the ABI line does not fit the header padding, binding to the major instead", exe)
		err = rewriteMachoStringsCmd(exe, rewrite)
	}
	if errors.Is(err, ErrNoSpace) {
		opts.log("skip macho for %s: %v", exe, err)
		return nil
	}
	if err != nil {
		return err
	}
	return checkRpathResolvable(exe, opts)
}

// qualifyID gives a BARE @rpath install name the directory the file is actually
// in, and reports whether it changed anything.
//
// CMake's default on darwin (MACOSX_RPATH) writes the install name as
// @rpath/<soname> — no directory at all. Every branch below leaves that alone,
// because it already starts with @rpath and "libzstd.1.dylib" joined onto
// $ZPKG_DIR is, technically, under $ZPKG_DIR. It is also nowhere: a consumer's
// rpath points at $ZPKG_DIR, not at zstd's lib dir, so dyld aborts:
//
//	dyld: Library not loaded: @rpath/libzstd.1.dylib
//	  Referenced from: …/build/bin/llvm-min-tblgen
//	  Reason: tried: '/Users/runner/.pkgx/libzstd.1.dylib' (no such file), …
//
// That is #125: our published facebook.com/zstd artifact carries the bare form
// where upstream pkgx's artifact for the SAME version carries
// @rpath/facebook.com/zstd/v1.5.7/lib/libzstd.1.5.7.dylib, and llvm.org could
// not build on either darwin arch because of it.
//
// The LEAF is kept, not replaced with the file's own name: it is the soname the
// build chose, and the symlink carrying it ships in the same directory — so a
// consumer keeps binding to libzstd.1.dylib rather than to libzstd.1.5.7.dylib.
// Kept only if that file is really there; a soname with no symlink beside it
// would be a reference we invented, so the file's own name is used instead.
// Only a name with no directory is touched: one that names a directory was
// either written correctly or is handled by the absolute branch, and an
// @loader_path/@executable_path one is already anchored to something real.
func qualifyID(exe, id string, opts Options) (string, bool) {
	if opts.ZpkgDir == "" {
		return "", false
	}
	// Two spellings of the same defect. @rpath/<soname> is CMake's; a plain
	// <soname> with no prefix at all is what a hand-written Makefile leaves —
	// sourceware.org/bzip2 ships libbz2.1.0.8.dylib whose install name is the
	// bare string "libbz2.dylib". Neither resolves in the pkgx layout, and
	// bzip2's own binary hides it by linking the static archive: only a package
	// that links libbz2 ever finds out.
	rest := id
	if r, ok := strings.CutPrefix(id, "@rpath/"); ok {
		rest = r
	} else if strings.HasPrefix(id, "@") || strings.HasPrefix(id, "/") {
		// @loader_path/@executable_path are already anchored to something real,
		// and an absolute name is the branch above this one.
		return "", false
	}
	if rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	self := unstage(exe, opts)
	dir := filepath.Dir(self)
	if _, err := osStat(filepath.Join(dir, rest)); err != nil {
		rest = filepath.Base(self)
	}
	rel, ok := underDir(filepath.Join(dir, rest), opts.ZpkgDir)
	if !ok {
		return "", false
	}
	return "@rpath/" + rel, true
}

// qualifyRef gives a BARE @rpath/<soname> REFERENCE the directory the file is
// actually in, when that file ships in the SAME package. It is qualifyID's
// mirror image: qualifyID fixes what a library calls itself, this fixes what
// its consumers ask for.
//
// The two directories tried are the only ones a bare name can honestly mean:
// beside the referring file, and the package's own lib. Anything else would be
// a guess about which package a soname came from, and an invented reference is
// worse than the bare one — it would point somewhere plausible and wrong.
func qualifyRef(exe, soname string, opts Options) (string, bool) {
	if opts.ZpkgDir == "" || soname == "" || strings.Contains(soname, "/") {
		return "", false
	}
	self := unstage(exe, opts)
	// filepath.Dir never answers "" and Join never does either, so there is no
	// empty-directory case to guard against here.
	for _, dir := range []string{filepath.Dir(self), filepath.Join(opts.Prefix, "lib")} {
		cand := filepath.Join(dir, soname)
		// The file may be at the final prefix already (fixup runs after the
		// install) or still under the staging prefix whose path was baked into
		// the binaries. Which one holds bytes is not worth a guess: try both,
		// and name the final one either way.
		if !exists(cand) && !exists(staged(cand, opts)) {
			continue
		}
		if rel, ok := underDir(cand, opts.ZpkgDir); ok {
			return "@rpath/" + rel, true
		}
	}
	// Not ours. A bare soname can still be a DEPENDENCY's, and which one is a
	// question the closure answers rather than a guess: the library is staged
	// under $ZPKG_DIR, and if exactly one project there ships that file, that
	// is the project it came from.
	//
	// Measured over the installed closures of 44 packages — 1135 Mach-O files,
	// 124 bare references, 102 that nothing could resolve:
	//
	//	76  exactly one owning project in the closure
	//	 0  more than one
	//	26  no owner (libjvm.dylib, which openjdk ships in lib/server/)
	//
	// 60 of the 76 are libzstd.1.dylib: zstd's bare install name, recorded by
	// every consumer linked before qualifyID gave it a directory, still being
	// carried by artifacts built since.
	if proj, ok := closureOwner(soname, opts); ok {
		return proj, true
	}
	return "", false
}

// closureOwner finds the one project under $ZPKG_DIR that ships soname in its
// lib dir, and names it the way a sibling reference is named everywhere else:
// through transformRpath, so the MAJOR version directory is used and a
// dependency's minor upgrade does not orphan its dependents.
//
// Ambiguity is not resolved, it is declined. Two projects shipping one soname
// is a question about which one this binary was linked against, and nothing in
// a Mach-O records the answer — so the reference is left bare, which is at
// least honest about not knowing.
func closureOwner(soname string, opts Options) (string, bool) {
	var hits []string
	seen := map[string]bool{}
	for _, depth := range []string{"*/v*/lib/", "*/*/v*/lib/"} {
		matches, err := filepathGlob(filepath.Join(opts.ZpkgDir, depth+soname))
		if err != nil {
			continue
		}
		for _, m := range matches {
			// …/<project>/v<ver>/lib/<soname> — the project is two levels above lib
			proj := filepath.Dir(filepath.Dir(filepath.Dir(m)))
			if seen[proj] {
				continue
			}
			seen[proj] = true
			hits = append(hits, m)
		}
	}
	if len(hits) != 1 {
		return "", false
	}
	// The hit came out of a glob rooted at $ZPKG_DIR and transformRpath only
	// rewrites the version segment, so the result is still under it: there is
	// no not-under-$ZPKG_DIR case to handle, and a branch no test can reach is
	// a line the coverage gate is right to refuse.
	t := transformRpath(hits[0], filepath.Dir(opts.Prefix))
	rel, _ := underDir(t, opts.ZpkgDir)
	return "@rpath/" + rel, true
}

// exists reports whether a path is there, through the stat seam the tests
// inject on.
func exists(p string) bool {
	_, err := osStat(p)
	return err == nil
}

// staged is unstage's inverse: the path a file is at RIGHT NOW, while the build
// is still writing into +brewing. qualifyRef has to stat the file that exists,
// and name the one that will.
func staged(p string, opts Options) string {
	if opts.BuildInstall == "" || !strings.HasPrefix(p, opts.Prefix) {
		return p
	}
	return opts.BuildInstall + strings.TrimPrefix(p, opts.Prefix)
}

// ErrDeadRpath means a Mach-O references @rpath/… and carries no LC_RPATH at
// all, so nothing can ever resolve it.
var ErrDeadRpath = errors.New("fixup: @rpath reference with no LC_RPATH")

// ErrBuilderOnlyRpath means a Mach-O reaches a SIBLING package only through an
// absolute LC_RPATH — the build machine's own pkgx directory. It runs there and
// nowhere else.
var ErrBuilderOnlyRpath = errors.New("fixup: sibling package reachable only through an absolute rpath")

// checkRpathResolvable refuses a binary whose @rpath references nothing can
// satisfy.
//
// A dependency's install name is what its DEPENDENTS record, so the day a
// library is rebuilt with an @rpath install name, everything linking it starts
// recording @rpath/… too — including a package whose own link did not put an
// LC_RPATH in. The result loads nowhere:
//
//	dyld: Library not loaded: @rpath/tukaani.org/xz/v5.8.3/lib/liblzma.5.dylib
//	  Referenced from: …/pkgx.sh/v2.11.0/bin/pkgx
//	  Reason: no LC_RPATH's found
//
// Found in the published registry, on an artifact that builds, signs, attests and
// publishes without a complaint. There is nothing to guess at here — no rpath
// and an @rpath reference is dead in every environment — so it stops the build
// rather than becoming someone's dyld error weeks later.
func checkRpathResolvable(exe string, opts Options) error {
	strs, err := readMachoRefs(exe)
	if err != nil {
		return err
	}
	rpaths, err := machoRpaths(exe)
	if err != nil {
		return err
	}
	for _, s := range strs {
		if !strings.HasPrefix(s, "@rpath/") {
			continue
		}
		if len(rpaths) == 0 {
			return fmt.Errorf("%w: %s references %s", ErrDeadRpath, exe, s)
		}
		if siblingRef(s) && opts.ZpkgDir != "" && !relRpathReaches(exe, opts.ZpkgDir, rpaths) {
			return fmt.Errorf("%w: %s references %s but its only rpaths are %s",
				ErrBuilderOnlyRpath, exe, s, strings.Join(rpaths, ", "))
		}
	}
	return nil
}

// readMachoRefs returns the strings that are REFERENCES — what this file asks
// dyld to find — and not its own name.
//
// LC_ID_DYLIB is not a reference. It is what this dylib calls itself, recorded
// by whoever links against it; dyld never resolves it against this file's own
// rpaths. Counting it made a self-contained library fail its own guard the
// moment its id was qualified: libbz2 links nothing but libSystem, needs no
// rpath, and would have been reported as "@rpath reference with no LC_RPATH"
// against itself.
func readMachoRefs(path string) ([]string, error) {
	raw, slices, err := machoInfo(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, sl := range slices {
		walkMachoStrings(raw[sl.off:sl.off+sl.size], sl.bo, sl.hdr, sl.ncmd, func(cmd uint32, s string) string {
			if cmd != lcIDDylib && cmd != lcRpath {
				out = append(out, s)
			}
			return s
		})
	}
	return out, nil
}

// siblingRef reports whether an @rpath reference names ANOTHER package rather
// than this one's own libraries.
//
// The two shapes differ by a version directory: a package's own library is
// @rpath/libLLVM.dylib or @rpath/lib/foo.dylib, reached from @loader_path/../lib;
// a sibling is @rpath/zlib.net/v1.3.1/lib/libz.1.3.1.dylib, reachable only from
// the pkgx root. Only the second needs an rpath that climbs out of the package.
func siblingRef(s string) bool {
	for _, seg := range strings.Split(strings.TrimPrefix(s, "@rpath/"), "/") {
		if len(seg) > 1 && seg[0] == 'v' && seg[1] >= '0' && seg[1] <= '9' {
			return true
		}
	}
	return false
}

// relRpathReaches is rpathReaches restricted to RELATIVE entries.
//
// An absolute rpath is not relocatability. It names the directory the build
// machine happened to use, and llvm.org's darwin artifact is what that produces:
// 118 of its 118 Mach-O files that reference a sibling carry
// "/Users/runner/.pkgx" and "@loader_path/../lib", so every one of them loads
// on the CI runner and on nothing else —
//
//	dyld: Library not loaded: @rpath/zlib.net/v1.3.1/lib/libz.1.3.1.dylib
//	  tried: '/Users/runner/.pkgx/zlib.net/…' (no such file)
//
// — while it built, signed, attested and published without a complaint.
//
// Measured before this was made an error rather than a warning: of six sampled
// darwin artifacts only llvm.org is in that state. zlib.net, sqlite.org and
// gnome.org/libxml2 carry the absolute entry too but keep relative ones that
// reach, so they leak a build path rather than break; openssl.org and curl.se
// carry neither. Refusing the build therefore stops exactly the packages that
// were already shipping something unusable.
func relRpathReaches(exe, dir string, rpaths []string) bool {
	var rel []string
	for _, r := range rpaths {
		if strings.HasPrefix(r, "@loader_path/") || strings.HasPrefix(r, "@executable_path/") {
			rel = append(rel, r)
		}
	}
	return rpathReaches(exe, dir, rel)
}

// cstr reads a NUL-terminated string from the front of b.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
