package fixup

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Sentinels returned by SetRunpath.
var (
	// ErrNoRunpath means the ELF has neither DT_RUNPATH nor DT_RPATH, so there
	// is no string slot to overwrite in place.
	ErrNoRunpath = errors.New("fixup: ELF has no DT_RUNPATH/DT_RPATH entry")
	// ErrNoSpace means the new RUNPATH is longer than the existing string slot.
	// A pure-Go in-place rewrite cannot grow .dynstr; link the binary with a
	// longer -Wl,-rpath placeholder so the final value fits.
	ErrNoSpace = errors.New("fixup: new RUNPATH longer than existing slot")
)

// ReadRunpath returns the DT_RUNPATH (preferred) or DT_RPATH of an ELF, or ""
// if it has neither.
func ReadRunpath(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if v, err := f.DynString(elf.DT_RUNPATH); err == nil && len(v) > 0 {
		return v[0], nil
	}
	if v, err := f.DynString(elf.DT_RPATH); err == nil && len(v) > 0 {
		return v[0], nil
	}
	return "", nil
}

// ReadNeeded returns the DT_NEEDED shared-library names of an ELF.
func ReadNeeded(path string) ([]string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.DynString(elf.DT_NEEDED)
}

// isDynamicELF reports whether path is a dynamically-linked ELF (has a
// .dynamic section) that carries a symbol table worth relocating.
func isDynamicELF(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Section(".dynamic") != nil && f.Section(".dynstr") != nil
}

// SetRunpath overwrites an ELF's existing DT_RUNPATH/DT_RPATH string in place.
// It is pure-Go (no patchelf): it locates the string offset in .dynstr and
// overwrites the bytes, zero-padding any slack. It cannot grow .dynstr, so it
// returns ErrNoSpace when value is longer than the current slot and ErrNoRunpath
// when there is no rpath entry at all.
func SetRunpath(path, value string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	class, order := f.Class, f.ByteOrder
	dynSec := f.Section(".dynamic")
	strSec := f.Section(".dynstr")
	if dynSec == nil || strSec == nil {
		f.Close()
		return ErrNoRunpath
	}
	dyn, err := dynSec.Data()
	if err != nil {
		f.Close()
		return err
	}
	f.Close()

	strOff, rpathAt, ok := runpathStrOffset(dyn, class, order)
	if !ok {
		return ErrNoRunpath
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

	// measure the existing slot: bytes from the string start to its NUL.
	base := int64(strSec.Offset) + int64(strOff)
	slot := make([]byte, 4096)
	n, _ := fh.ReadAt(slot, base)
	oldLen := 0
	for oldLen < n && slot[oldLen] != 0 {
		oldLen++
	}
	if len(value) > oldLen {
		return ErrNoSpace
	}
	// The TAG first, when the slot we are about to write into is a DT_RPATH.
	// Writing the value and leaving the tag is how this function put its own
	// `$ORIGIN/..` into a tag that must not be there:
	//
	//	$ readelf -d …/gnu.org/glibc/v2.44/lib/glibc-2.44/libc.so.6
	//	0x…0f (RPATH)  Library rpath: [$ORIGIN/..]
	//	ld.so: elf_get_dynamic_info: Assertion `info[DT_RPATH] == NULL' failed!
	//
	// glibc's own loader refuses a DT_RPATH on the objects it processes, so a
	// libc bottle fixed up this way cannot load its own libc — and since
	// gnu.org/glibc provides bin/ldd and bottle puts glibc in every linux
	// closure, `ldd` stops working for everything we publish there
	// (go-zpkg/bk#256).
	//
	// Converting rather than removing, and measured rather than assumed: of
	// 393 shared objects in the s390x store, 295 already carry DT_RUNPATH and
	// 71 carry DT_RPATH, none both. DT_RUNPATH is what three quarters of the
	// fleet already depends on, so this moves the minority onto the majority's
	// semantics rather than inventing one. What differs is that DT_RUNPATH
	// does not apply to a dependency's own dependencies — which those 295 have
	// never had either.
	//
	// AFTER the ErrNoSpace check, so a value that cannot fit leaves the file
	// untouched rather than half-converted; and BEFORE the string write, so
	// the two error arms are reachable one at a time. One word, in place:
	// nothing moves and no other offset changes.
	if rpathAt >= 0 {
		if _, err := fh.WriteAt(dynTagBytes(class, order, elf.DT_RUNPATH), int64(dynSec.Offset)+int64(rpathAt)); err != nil {
			return err
		}
	}

	buf := make([]byte, oldLen+1) // value + NUL, zero-padded to the old length
	copy(buf, value)
	if _, err := fh.WriteAt(buf, base); err != nil {
		return err
	}
	return nil
}

// dynTagBytes encodes one d_tag for this ELF class and byte order. A 32-bit
// entry is two 4-byte words and a 64-bit one two 8-byte words, so writing
// eight bytes over a 32-bit tag would take the d_val with it.
func dynTagBytes(class elf.Class, order binary.ByteOrder, tag elf.DynTag) []byte {
	if class == elf.ELFCLASS32 {
		b := make([]byte, 4)
		order.PutUint32(b, uint32(tag))
		return b
	}
	b := make([]byte, 8)
	order.PutUint64(b, uint64(tag))
	return b
}

// runpathStrOffset scans a raw .dynamic section for DT_RUNPATH (preferred) or
// DT_RPATH and returns its d_val (a .dynstr byte offset).
//
// rpathAt is the byte offset WITHIN .dynamic of a DT_RPATH tag that was used
// for want of a DT_RUNPATH, and -1 otherwise. SetRunpath converts it; see
// there for why writing a value into DT_RPATH is not enough.
func runpathStrOffset(dyn []byte, class elf.Class, order binary.ByteOrder) (val uint64, rpathAt int, ok bool) {
	var rpath uint64
	rpathIdx := -1
	haveRPath := false
	step := 16
	if class == elf.ELFCLASS32 {
		step = 8
	}
	for i := 0; i+step <= len(dyn); i += step {
		var tag int64
		var val uint64
		if class == elf.ELFCLASS64 {
			tag = int64(order.Uint64(dyn[i:]))
			val = order.Uint64(dyn[i+8:])
		} else {
			tag = int64(int32(order.Uint32(dyn[i:])))
			val = uint64(order.Uint32(dyn[i+4:]))
		}
		switch elf.DynTag(tag) {
		case elf.DT_RUNPATH:
			return val, -1, true // RUNPATH wins outright, and needs no conversion
		case elf.DT_RPATH:
			rpath, rpathIdx, haveRPath = val, i, true
		case elf.DT_NULL:
			// end of the dynamic array
			if haveRPath {
				return rpath, rpathIdx, true
			}
			return 0, -1, false
		}
	}
	if haveRPath {
		return rpath, rpathIdx, true
	}
	return 0, -1, false
}

// fixRpaths walks bin/lib/libexec and rewrites each dynamic ELF's RUNPATH to
// $ORIGIN-relative references to the package's own libs and its deps.
func fixRpaths(opts Options) error {
	switch opts.Platform {
	case "linux":
		if has(opts.Skips, "fix-patchelf") {
			opts.log("skipping rpath fixes for %s", opts.Prefix)
			return nil
		}
		return walkExes(opts.Prefix, func(exe string) error {
			return rewriteRunpath(exe, opts)
		})
	case "darwin":
		if has(opts.Skips, "fix-machos") {
			opts.log("skipping mach-o fixes for %s", opts.Prefix)
			return nil
		}
		return walkExes(opts.Prefix, func(exe string) error {
			return rewriteMacho(exe, opts)
		})
	default:
		return nil
	}
}

func rewriteRunpath(exe string, opts Options) error {
	if !isDynamicELF(exe) {
		return nil
	}
	exeDir := filepath.Dir(exe)
	projectDir := filepath.Dir(opts.Prefix) // …/project (parent of vX.Y.Z)

	var rpaths []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			rpaths = append(rpaths, s)
		}
	}
	// After relocation every RUNPATH entry must be $ORIGIN-relative. Keep the
	// build's own $ORIGIN entries and any pointing into this package's project
	// dir (rewritten $ORIGIN-relative); DROP foreign absolute entries — a
	// build-time path or the link-time placeholder is meaningless at runtime
	// and would blow the in-place slot budget.
	if cur, err := ReadRunpath(exe); err == nil && cur != "" {
		for _, p := range strings.Split(cur, ":") {
			switch {
			case strings.HasPrefix(p, "$ORIGIN"):
				add(p)
			case p != "" && strings.HasPrefix(p, projectDir):
				add(originRel(unstage(p, opts), exeDir))
			}
		}
	}
	// Always reference the package's OWN lib dir $ORIGIN-relative, so a bottle
	// binary finds its sibling shared libs (…/lib) from a FROM-scratch image with
	// no LD_LIBRARY_PATH. From bin/ this is $ORIGIN/../lib; from lib/ itself it is
	// $ORIGIN/. — both resolve to the package lib dir. Deduped if already present.
	add(originRel(filepath.Join(opts.Prefix, "lib"), exeDir))
	for _, dep := range opts.DepPaths {
		add(originRel(transformRpath(dep, projectDir), exeDir))
	}
	err := SetRunpath(exe, strings.Join(rpaths, ":"))
	if errors.Is(err, ErrNoRunpath) || errors.Is(err, ErrNoSpace) {
		// tolerant, like patchelf on statically-linked/oddball inputs
		opts.log("skip rpath for %s: %v", exe, err)
		return nil
	}
	return err
}

// versionRE matches a version directory name — v1.2.3, and also v10.47, which
// the earlier `v(\d+)\.(\d+\.)+\d+` did NOT: it required three components.
// Two-component versions are ordinary here (curl.se v8.20, pcre.org/v2 v10.47),
// and leaving them whole is what let a dependency's minor upgrade orphan its
// dependents. Measured on the published gnu.org/grep bottle, which named
// pcre2 v10.47 on a machine that had v10.48: grep could not start, and curl's
// configure reported it as "'grep' utility not found in 'PATH'".
//
// A leading `v` is required, so a soname (libpcre2-8.0.dylib) is not a version.
var versionRE = regexp.MustCompile(`v(\d+)(\.\d+)+[a-z]?`)

// transformRpath major-versions a full version path so bottles survive minor
// upgrades without a re-sign; $ORIGIN paths and references into the package's
// own project dir are left untouched.
func transformRpath(input, projectDir string) string {
	if strings.HasPrefix(input, "$ORIGIN") {
		return input
	}
	if strings.HasPrefix(input, projectDir) {
		return input
	}
	return versionRE.ReplaceAllString(input, "v$1")
}

// unstage maps a path under the +brewing staging prefix onto the final one.
//
// The build's own RUNPATH names the prefix it was configured with, and that is
// the STAGING directory: an autotools package built with
// --prefix=…/v1.22.0+brewing bakes …/v1.22.0+brewing/lib into every binary.
// The entry starts with the project dir, so it was kept and made
// $ORIGIN-relative verbatim — preserving a directory that ceases to exist the
// moment the build is renamed into place:
//
//	$ORIGIN/../../v1.22.0+brewing/lib:$ORIGIN/../lib
//
// Measured on published bottles: openucx.org has it in 11 of its 13 ELFs and
// sqlite.org in both of its. Neither is broken, because the entry that follows
// resolves — but a dead entry costs a slot in a budget the in-place rewriter
// has to fit, and it puts a build directory's name in an artefact we sign.
//
// Every other consumer of a staged path already gets this treatment: .pc files,
// .cmake files, staged scripts and Mach-O install names all have the staging
// prefix rewritten. The ELF RUNPATH was the one that did not.
func unstage(p string, opts Options) string {
	if opts.BuildInstall == "" || !strings.HasPrefix(p, opts.BuildInstall) {
		return p
	}
	return opts.Prefix + strings.TrimPrefix(p, opts.BuildInstall)
}

// originRel makes an absolute path $ORIGIN-relative to exeDir; $ORIGIN paths
// pass through unchanged.
func originRel(p, exeDir string) string {
	if strings.HasPrefix(p, "$ORIGIN") {
		return p
	}
	rel, err := filepath.Rel(exeDir, p)
	if err != nil {
		return p
	}
	return "$ORIGIN/" + filepath.ToSlash(rel)
}

// walkExes visits regular (non-symlink) files under bin/lib/libexec.
func walkExes(prefix string, fn func(string) error) error {
	for _, sub := range []string{"bin", "lib", "libexec"} {
		d := filepath.Join(prefix, sub)
		if !isDir(d) {
			continue
		}
		err := filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !e.Type().IsRegular() {
				return nil
			}
			switch filepath.Ext(p) {
			case ".py", ".pyc", ".pl", ".h", ".a", ".la", ".pc":
				return nil
			}
			return fn(p)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// majorLeaf reduces a reference's FILENAME to the soname its major line
// guarantees, for a path whose directory transformRpath has just majored.
//
// transformRpath majors the directory of a reference into another package —
// v1.3.1 becomes v1 — so the reference follows that package's patch releases.
// The leaf was carried over whole, and a full-version leaf undoes exactly what
// majoring the directory bought. Measured on the published cairo 1.18.4 bottle:
//
//	libcairo.2.dylib -> @rpath/zlib.net/v1/lib/libz.1.3.1.dylib
//
// zlib.net/v1 now resolves to 1.3.2, whose lib dir holds libz.1.3.2.dylib with
// libz.1.dylib and libz.dylib beside it — and no libz.1.3.1.dylib. The
// directory moved with the upgrade, as intended; the filename did not, so the
// reference resolves nowhere. Seven closures carried it: cairo's own and the
// six that pull cairo in (pango, poppler, graphviz, harfbuzz, ffmpeg, openjdk).
//
// Only a symlink that really sits beside the target AND really points at it is
// used, so this invents nothing: a library that ships no soname link keeps the
// name the build chose. The link must also keep a numeric component — libz.1 is
// the major line we just bound to, while libz would bind across majors, which
// is a wider promise than the directory makes.
//
// The package's own libraries never reach here: transformRpath returns those
// unchanged, and they ship together, so their full version cannot drift.
func majorLeaf(orig string) string {
	dir, leaf := filepath.Split(orig)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return leaf
	}
	real, err := filepath.EvalSymlinks(orig)
	if err != nil {
		return leaf
	}
	best := ""
	for _, e := range ents {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		n := e.Name()
		if !isMajorSoname(leaf, n) {
			continue
		}
		tgt, err := filepath.EvalSymlinks(filepath.Join(dir, n))
		if err != nil || tgt != real {
			continue
		}
		if best == "" || len(n) < len(best) {
			best = n
		}
	}
	if best == "" {
		return leaf
	}
	return best
}

// isMajorSoname reports whether cand is leaf truncated at a dot boundary with
// at least one numeric component left — libz.1.dylib for libz.1.3.1.dylib, but
// not libz.dylib, and not a different library's name.
func isMajorSoname(leaf, cand string) bool {
	const ext = ".dylib"
	l, ok := strings.CutSuffix(leaf, ext)
	if !ok {
		return false
	}
	c, ok := strings.CutSuffix(cand, ext)
	if !ok {
		return false
	}
	if !strings.HasPrefix(l, c+".") {
		return false
	}
	i := strings.LastIndex(c, ".")
	if i < 0 {
		return false
	}
	last := c[i+1:]
	if last == "" {
		return false
	}
	for _, r := range last {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// abiLine rewrites a majored reference to bind to the dependency's ABI LINE
// instead of its package major, when the store offers one.
//
// `v<major>` holds one version, so a project that changes its soname INSIDE a
// major cannot have both lines installed. Measured with both of libxml2's:
//
//	v2      -> v2.15.4      (and nothing can reach 2.13.9's libxml2.2.dylib)
//	v2.13   -> v2.13.9
//	v2.15   -> v2.15.4
//
// ICU has the same shape and no such problem, because it bumps its major with
// its soname. libxml2 does not, so `open-mpi.org` — which needs hwloc's
// libxml2.16 and gettext's libxml2.2 at once — has no closure at all.
//
// bottle now installs an `abi-<soname>` link beside the version aliases, from
// what the bottle DECLARES it provides. Naming that instead of v<major> gives
// the same late binding — a patch or minor upgrade within the line still moves
// the link — keyed on the thing that decides whether a consumer can load it.
//
// Only when the link is really there. A dependency published before bottle
// wrote them, or one whose soname this build did not name, keeps the v<major>
// form and behaves exactly as before.
func abiLine(orig, leaf, zpkgDir string) (string, bool) {
	if zpkgDir == "" || leaf == "" {
		return "", false
	}
	rest, ok := underDir(orig, zpkgDir)
	if !ok {
		return "", false
	}
	// <project>/v<version>/<tail...> — the project may itself contain slashes,
	// so the version directory is the only reliable boundary.
	slash := filepath.ToSlash(rest)
	m := abiVersionDirRE.FindStringSubmatch(slash)
	if m == nil {
		return "", false
	}
	project := m[1]
	tail := slash[len(m[1])+1+len(m[2]):]
	link := filepath.Join(zpkgDir, filepath.FromSlash(project), "abi-"+leaf)
	// osStat, not Lstat: a dangling link is not a line anybody can bind to,
	// and following it is the same question dyld will ask.
	if _, err := osStat(link); err != nil {
		return "", false
	}
	return filepath.Join(zpkgDir, filepath.FromSlash(project), "abi-"+leaf, filepath.FromSlash(tail)), true
}

// abiVersionDirRE finds the /v<version>/ boundary in a store-relative path.
var abiVersionDirRE = regexp.MustCompile(`^(.+?)/(v[0-9][^/]*/)`)

// abiOrMajor reduces an absolute store path to what a reference should bind
// to: the ABI LINE when the dependency offers one, the major directory
// otherwise, and the path unchanged when it is not a store reference at all.
//
// It exists because there are TWO doors to this question and the ABI half was
// put through only one of them. A Mach-O records a dependency either as an
// absolute path or as @rpath/<rest>, and which one it is depends on the
// dependency's own install name, not on anything the consumer chose. hwloc
// comes through the @rpath door — libxml2's install name is already @rpath —
// so #183 rewrote nothing for it, and the rebuilt bottle still recorded
//
//	@rpath/gnome.org/libxml2/v2/lib/libxml2.16.dylib
//
// which dies the moment v2 names the 2.13 line. One function, both doors.
// useABI is false on the second pass, where the first ran out of header
// padding: the major form is shorter, and keeping the relocation matters more
// than binding to the line.
func abiOrMajor(full string, opts Options, useABI bool) string {
	t := transformRpath(full, filepath.Dir(opts.Prefix))
	if t == full {
		return t
	}
	leaf := majorLeaf(full)
	if a, ok := abiLine(full, leaf, opts.ZpkgDir); ok && useABI {
		return a
	}
	return filepath.Join(filepath.Dir(t), leaf)
}

// loaderPathRef answers a BARE @rpath/<name> reference with a path relative to
// the referring file, when the named file ships in the same package.
//
// It exists for a file that carries no usable rpath. Every other repair here
// produces another @rpath reference, which is no help: @rpath is a search
// through LC_RPATH entries, and a file with none searches nowhere. dyld
// resolves @loader_path against the referring file's own directory instead, so
// it needs no load command and survives the store being mounted anywhere.
//
// Only a name with NO directory is answered, and only when the file is really
// there — in the referring file's own directory, or the package's lib dir.
// Inventing a location for a dependency's library is what the closure-owner
// search is for, and that one needs an rpath.
func loaderPathRef(exe, ref string, opts Options) (string, bool) {
	name, ok := strings.CutPrefix(ref, "@rpath/")
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	self := unstage(exe, opts)
	for _, dir := range []string{filepath.Dir(self), filepath.Join(opts.Prefix, "lib")} {
		cand := filepath.Join(dir, name)
		// Fixup runs after the install, but the staging prefix is what was
		// baked into the binaries: which one holds bytes is not worth a guess.
		if !exists(cand) && !exists(staged(cand, opts)) {
			continue
		}
		rel, err := filepath.Rel(filepath.Dir(self), cand)
		if err != nil {
			continue
		}
		return "@loader_path/" + filepath.ToSlash(rel), true
	}
	return "", false
}
