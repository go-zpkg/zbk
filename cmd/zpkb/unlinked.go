package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/fixup"
)

// Seams, the same two `undeclared` has, so both commands can be driven
// without a network and neither grows a private copy that drifts.
var (
	unlinkedGraph             = artifact.GraphFor
	unlinkedInstall           = artifact.CompleteClosureFor
	unlinkedTempDir           = os.MkdirTemp
	unlinkedStdin   io.Reader = os.Stdin
)

// runUnlinked implements `bk unlinked`: which projects does an artifact DECLARE
// and never link?
//
// ⛔ IT IS `undeclared` READ BACKWARDS, AND THE BACKWARDS DIRECTION IS THE
// ONE NOTHING CHECKED. `bk undeclared` finds an edge the artefact has and
// the recipe does not; `bk unresolved` and the soname sweep find references
// that cannot be satisfied. All three look for something PRESENT and wrong.
// A dependency that is declared, resolved, installed — and then not used —
// is absent from every one of them, and absence is what they cannot see.
//
// Two real cases, both found by hand in one afternoon and neither by a tool:
//
//	rpm.org/rpm-sequoia  declares openssl.org ^3 and links no libssl at all:
//	                     a rebuild STATICALLY linked openssl 3.6.4 into the
//	                     library. The artifact grew 4.2MB -> 12.6MB and carries
//	                     openssl's own version banner inside the .so.
//	gnu.org/libiconv     declares gnu.org/gettext ^1 on darwin and links
//	                     nothing but libSystem. Every darwin consumer installs
//	                     gettext for a link that is not there.
//
// They are different defects — one vendors a library we publish, the other
// declares an edge that no longer exists — and this one check finds both,
// because both leave the same trace: a declared provider of libraries whose
// libraries nobody loads.
//
// ⛔ WHY THE VENDORING CASE IS THE SERIOUS ONE. A broken reference is
// VISIBLE: `libssl.so.1.1` is an unresolvable soname that a sweep counts. A
// vendored copy is invisible — the manifest still says `openssl.org ^3`, and
// when openssl ships a fix, updating the openssl artifact does not change the
// artifact that embedded it, while its own version does not move either. A
// dependency-shaped CVE audit has nothing to compare.
func runUnlinked(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("unlinked", flag.ContinueOnError)
	fset.SetOutput(stderr)
	store := fset.String("store", "", "install into this directory (default: a temporary one, removed after)")
	failOn := fset.Bool("fail", false, "exit 1 if anything is found")
	// ⛔ A PLATFORM, because the answer is per-platform and the interesting
	// cases are not on the machine asking. rpm.org/rpm-sequoia — the one
	// confirmed vendoring case — is published for linux and not for darwin,
	// so a host-only command cannot look at the very artifact it was written
	// for. artifact.CompleteClosureFor stages another platform's tree, which
	// is what lets a mac audit linux.
	platform := fset.String("platform", "", "audit this os/arch instead of the host's")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	projects, err := undeclaredProjects(fset.Args(), unlinkedStdin)
	if err != nil {
		fmt.Fprintln(stderr, "unlinked:", err)
		return 1
	}
	if len(projects) == 0 {
		fmt.Fprintln(stderr, "unlinked: no projects (name them, or pipe them in)")
		return 2
	}

	dir := *store
	if dir == "" {
		d, err := unlinkedTempDir("", "bk-unlinked-")
		if err != nil {
			fmt.Fprintln(stderr, "unlinked:", err)
			return 1
		}
		dir = d
		defer os.RemoveAll(dir)
	}

	osn, arch := artifact.HostSlug()
	if *platform != "" {
		o, a, ok := strings.Cut(*platform, "/")
		if !ok || o == "" || a == "" {
			fmt.Fprintf(stderr, "unlinked: --platform %q is not os/arch\n", *platform)
			return 2
		}
		osn, arch = o, a
	}
	total := 0
	for _, p := range projects {
		roots := map[string]string{p: "*"}
		g, err := unlinkedGraph(roots, osn, arch)
		if err != nil {
			fmt.Fprintf(stderr, "unlinked: %s: %v\n", p, err)
			continue
		}
		if _, err := unlinkedInstall(roots, dir, osn, arch); err != nil {
			fmt.Fprintf(stderr, "unlinked: %s: %v\n", p, err)
			continue
		}
		for _, f := range unlinkedOf(p, dir, g) {
			total++
			fmt.Fprintf(stdout, "%-34s declares %s, which ships %s, and links none of them\n",
				f.Project, f.Dependency, strings.Join(f.Libraries, ", "))
		}
	}
	fmt.Fprintf(stdout, "\n%d declared-and-unlinked edge(s)\n", total)
	fmt.Fprintln(stdout, "a finding is a CANDIDATE: a vendored copy, or an edge that is simply no longer needed")
	if *failOn && total > 0 {
		return 1
	}
	return 0
}

// Unlinked is one declared dependency whose libraries the dependent ignores.
type Unlinked struct {
	Project    string
	Dependency string
	Libraries  []string // the shared libraries that dependency ships
}

// unlinkedOf reports each DIRECT declared dependency of project that ships
// shared libraries none of which project references.
//
// ⛔ DIRECT ONLY, which is the opposite choice from undeclaredOf and for the
// same reason it made the transitive one. There, reachability had to be
// transitive or a real declaration one hop out read as a defect. Here a
// TRANSITIVE dependency is one nobody promised to link — curl.se brings
// openssl, and a package that declares curl.se and links no openssl has done
// nothing wrong. Only what a recipe named ITSELF is a claim about itself.
func unlinkedOf(project, dir string, g *artifact.Graph) []Unlinked {
	refs := referencedProjects(project, dir)
	var out []Unlinked
	for _, e := range g.Deps[project] {
		if refs[e.On] {
			continue
		}
		libs := sharedLibrariesOf(e.On, dir)
		if len(libs) == 0 {
			// Ships no libraries, so there is nothing to link and the
			// declaration says something else: a program run at runtime, a
			// data set like curl.se/ca-certs, a interpreter. Silence here is
			// most of what keeps the list readable.
			continue
		}
		out = append(out, Unlinked{Project: project, Dependency: e.On, Libraries: libs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dependency < out[j].Dependency })
	return out
}

// referencedProjects is every project the given project's own files name, by
// either platform's spelling.
//
// Mach-O says `@rpath/<project>/v…/lib/libfoo.dylib` — the project is IN the
// reference. ELF says only `libfoo.so.3`, so the project has to be recovered
// by finding which installed artifact ships that soname; doing it by filename
// is what makes this work on both without two separate commands.
func referencedProjects(project, dir string) map[string]bool {
	owners := sonameOwners(dir)
	out := map[string]bool{}
	root := filepath.Join(dir, filepath.FromSlash(project))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if strs, serr := fixup.MachoNeeded(p); serr == nil {
			for _, s := range strs {
				if m := rpathRefRE.FindStringSubmatch(s); m != nil {
					out[m[1]] = true
				}
				for _, o := range owners[filepath.Base(s)] {
					out[o] = true
				}
			}
			return nil
		}
		if strs, serr := artifact.ELFNeeded(p); serr == nil {
			for _, s := range strs {
				for _, o := range owners[s] {
					out[o] = true
				}
			}
		}
		return nil
	})
	delete(out, "")
	return out
}

// sonameOwners maps a shared library's FILE NAME to EVERY project that ships
// a file of that name, so an ELF `NEEDED libssl.so.3` can be attributed.
//
// ⛔ A SONAME CAN HAVE MORE THAN ONE OWNER, and assuming otherwise fabricated
// findings in bulk. This returned map[string]string and wrote `out[name] =
// owner`, so the last project walked won. With one project staged there is no
// collision and it looked right; over a shared store of 189 it was wrong
// everywhere. Measured 2026-10-28:
//
//	ovstore/gnu.org/gcc/v16.2.0/lib/libstdc++.so.6
//	ovstore/gnu.org/gcc/libstdcxx/v14.4.0/lib/libstdc++.so.6
//
// `facebook.com/folly` NEEDs `libstdc++.so.6` in every one of its libraries.
// Attributed to whichever of those two was walked last, its declaration of
// gnu.org/gcc/libstdcxx read as unlinked — and so did nine other C++ projects,
// each of which obviously links a C++ runtime.
//
// ⛔ AND WHY ALL OWNERS, NOT A CLEVERER CHOICE. Resolving a soname properly
// means replaying the dynamic loader's search order, which this command has no
// business doing. Naming every candidate can only ever SUPPRESS a finding, and
// the two directions are not equally expensive: a missed candidate costs a
// defect we were not going to notice anyway, while a fabricated one costs
// somebody reading a correct recipe looking for a fault that is not there. A
// list of candidates is worth nothing once a reader has to doubt it.
func sonameOwners(dir string) map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isSharedLibrary(p, d.Name()) {
			return nil
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, dir), string(filepath.Separator))
		owner, ok := ownerOf(rel)
		if !ok {
			return nil
		}
		// One project shipping the same soname at several versions is one
		// owner, not several: openssl.org alone staged 39 copies of
		// libssl.so.3 in that same sweep.
		if key := d.Name() + "\x00" + owner; !seen[key] {
			seen[key] = true
			out[d.Name()] = append(out[d.Name()], owner)
		}
		return nil
	})
	return out
}

// sharedLibrariesOf is the shared libraries one installed project ships,
// which is what makes "declared and not linked" answerable at all: a
// dependency with none of them cannot be linked and is not a finding.
func sharedLibrariesOf(project, dir string) []string {
	var out []string
	seen := map[string]bool{}
	root := filepath.Join(dir, filepath.FromSlash(project))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || seen[d.Name()] || !isSharedLibrary(p, d.Name()) {
			return nil
		}
		seen[d.Name()] = true
		out = append(out, d.Name())
		return nil
	})
	sort.Strings(out)
	return out
}

// isSharedLibrary says whether a file in the store is a shared library, by
// its NAME and then by its BYTES.
//
// ⛔ THE NAME ALONE CANNOT DECIDE, and two releases proved it in opposite
// directions over one day.
//
// v0.43 asked whether what follows `.so` begins with a dot, and counted
// `libstdc++.so.6.0.33-gdb.py` — a GDB pretty-printer, a PYTHON SCRIPT.
// v0.44.0 tightened it to require dot-separated NUMBERS, and stopped counting
// `libfolly.so.0.58.0-dev`, which `file(1)` calls an "ELF 64-bit LSB shared
// object" and which every library facebook.com/fbthrift ships names in its own
// DT_NEEDED. The first mistake invented libraries, the second hid them, and
// both were a guess about a filename standing in for a fact about a file.
//
// Each error cost findings in bulk. A dependency whose libraries are all
// unrecognised looks like one that ships NONE, which this command deliberately
// stays silent about; and a reference to an unrecognised soname cannot be
// attributed to its owner, so a project that does link it reads as one that
// does not. Five of facebook.com/folly's dependents were reported as not
// linking folly.
//
// So the name is a cheap prefilter and the magic number is the answer. A
// static archive is excluded by both: it is not `.dylib`, and `!<arch>` is
// neither ELF nor Mach-O.
func isSharedLibrary(path, name string) bool {
	return looksLikeSharedLibrary(name) && hasObjectMagic(path)
}

// looksLikeSharedLibrary is the prefilter: broad enough to admit any spelling
// a linker produces, so that the magic number is what actually decides.
func looksLikeSharedLibrary(name string) bool {
	if strings.HasSuffix(name, ".a") {
		return false
	}
	return strings.HasSuffix(name, ".dylib") || strings.Contains(name, ".so")
}

// machoMagics are the Mach-O and universal-binary magic numbers. Both byte
// orders are compared, which covers the CIGAM spellings without listing them.
var machoMagics = []uint32{0xfeedface, 0xfeedfacf, 0xcafebabe}

// hasObjectMagic reports whether the file begins with an ELF or Mach-O magic
// number. A file it cannot read is not a library: this walks a store, where an
// unreadable entry is a reason to say nothing, never to guess.
func hasObjectMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [4]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return false
	}
	if b == [4]byte{0x7f, 'E', 'L', 'F'} {
		return true
	}
	le, be := binary.LittleEndian.Uint32(b[:]), binary.BigEndian.Uint32(b[:])
	for _, m := range machoMagics {
		if le == m || be == m {
			return true
		}
	}
	return false
}
