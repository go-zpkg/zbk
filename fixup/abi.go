package fixup

import (
	"bytes"
	"debug/elf"
	"path/filepath"
	"sort"
)

// SonameOf returns the ABI name an in-memory shared library calls itself by —
// LC_ID_DYLIB's basename on darwin, DT_SONAME on ELF — or "" for anything that
// is not a shared library (an executable, a loadable bundle, an archive, a
// script).
//
// This is the key a dependent actually binds to, and the one a pkgx constraint
// cannot express. libxml2 states its own ABI line in configure.ac as
// LIBXML_MINOR_COMPAT=14, and the soname is CURRENT − AGE = MAJOR +
// MINOR_COMPAT: 2.13.9 ships libxml2.2.dylib and every 2.14+ ships
// libxml2.16.dylib. Both answer `^2`. An artifact that records what it provides
// lets a checker decide, from published metadata alone, whether a declared
// constraint can honour the references its dependents record — which is the
// question go-zpkg/packages#207 asks and nothing can currently answer.
//
// The basename, not the whole install name: the path is where this build put
// it, the basename is what dyld and ld.so match on.
func SonameOf(raw []byte) string {
	if len(raw) >= 4 && bytes.Equal(raw[:4], []byte("\x7fELF")) {
		f, err := elf.NewFile(bytes.NewReader(raw))
		if err != nil {
			return ""
		}
		defer f.Close()
		ss, err := f.DynString(elf.DT_SONAME)
		if err != nil || len(ss) == 0 {
			return ""
		}
		return filepath.Base(ss[0])
	}
	id := machoIDBytes(raw)
	if id == "" {
		// filepath.Base("") is ".", which would read as a soname.
		return ""
	}
	return filepath.Base(id)
}

// machoIDBytes is machoID for bytes already in hand.
func machoIDBytes(raw []byte) string {
	slices, err := machoSlices(raw)
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

// SortedUnique is the shape an annotation is written in: one sorted list, no
// repeats, so the same tree always produces the same string.
func SortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
