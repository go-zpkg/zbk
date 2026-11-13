package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/go-zpkg/bottle"
)

// writeStoreFile stages an ordinary file: data, a header, something that is
// NOT a library. Use writeLib for a library.
func writeStoreFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeLib stages a REAL shared library — a Mach-O for a `.dylib`, an ELF for
// a `.so` — through the same builders the rest of this package uses.
//
// ⛔ EVERY LIBRARY IN THESE TESTS USED TO CONTAIN THE BYTE "x", and that
// fiction is precisely what let a name-only rule look correct here while it
// got two real filenames wrong in the registry: it counted
// `libstdc++.so.6.0.33-gdb.py`, a Python script, and then refused
// `libfolly.so.0.58.0-dev`, an ELF shared object. A fixture that cannot tell
// a library from a text file cannot witness a check that has to.
func writeLib(t *testing.T, path string, refs ...string) {
	t.Helper()
	if strings.HasSuffix(path, ".dylib") {
		writeMachOAt(t, path, refs...)
		return
	}
	writeELFNeeded(t, path, refs...)
}

// ⛔ THE PLANTED POSITIVE IS THE REAL ONE: gnu.org/libiconv declares
// gnu.org/gettext on darwin, gettext ships libintl and friends, and the
// published libiconv links nothing but libSystem and itself. Every darwin
// consumer installs gettext for a link that is not there.
//
// The other real case has the same shape and a worse cause:
// rpm.org/rpm-sequoia declares openssl.org ^3 and links no libssl, because
// a rebuild linked openssl 3.6.4 STATICALLY into the library.
func TestUnlinkedFindsADeclaredDependencyNothingLinks(t *testing.T) {
	dir := t.TempDir()
	// The dependency ships shared libraries…
	writeLib(t, filepath.Join(dir, "gnu.org/gettext/v1.0.0/lib/libintl.dylib"))
	writeLib(t, filepath.Join(dir, "gnu.org/gettext/v1.0.0/lib/libgettextlib.dylib"))
	// …and the dependent ships one that references only itself.
	writeLib(t, filepath.Join(dir, "gnu.org/libiconv/v1.19/lib/libiconv.2.dylib"))

	g := &bottle.Graph{Deps: map[string][]bottle.Edge{
		"gnu.org/libiconv": {{On: "gnu.org/gettext"}},
	}}
	got := unlinkedOf("gnu.org/libiconv", dir, g)
	if len(got) != 1 {
		t.Fatalf("want the gettext edge reported, got %d: %+v", len(got), got)
	}
	if got[0].Dependency != "gnu.org/gettext" {
		t.Fatalf("got %+v", got[0])
	}
	if len(got[0].Libraries) != 2 {
		t.Errorf("want both of gettext's libraries named, got %v", got[0].Libraries)
	}
}

// ⛔ THE CONTROL THAT KEEPS THE LIST READABLE: a dependency that ships NO
// shared library cannot be linked, so declaring it says something else — a
// program run at runtime, a data set like curl.se/ca-certs, an interpreter.
// Reporting those would bury the real ones.
func TestUnlinkedIsQuietAboutADependencyWithNoLibraries(t *testing.T) {
	dir := t.TempDir()
	writeStoreFile(t, filepath.Join(dir, "curl.se/ca-certs/v2026.10.20/ssl/cert.pem"), []byte("x"))
	writeLib(t, filepath.Join(dir, "acme.org/tool/v1.0.0/lib/libtool.dylib"))

	g := &bottle.Graph{Deps: map[string][]bottle.Edge{
		"acme.org/tool": {{On: "curl.se/ca-certs"}},
	}}
	if got := unlinkedOf("acme.org/tool", dir, g); len(got) != 0 {
		t.Fatalf("a data-only dependency is not a finding, got %+v", got)
	}
}

// ⛔ DIRECT EDGES ONLY, the opposite choice from undeclaredOf and for the
// same reason it made the transitive one: a TRANSITIVE dependency is one
// nobody promised to link. curl.se brings openssl; a package declaring
// curl.se and linking no openssl has done nothing wrong.
func TestUnlinkedDoesNotReportATransitiveDependency(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, filepath.Join(dir, "openssl.org/v3.6.4/lib/libssl.dylib"))
	writeLib(t, filepath.Join(dir, "curl.se/v8.17.0/lib/libcurl.dylib"))
	writeStoreFile(t, filepath.Join(dir, "acme.org/app/v1.0.0/bin/app"), []byte("x"))

	g := &bottle.Graph{Deps: map[string][]bottle.Edge{
		"acme.org/app": {{On: "curl.se"}},
		"curl.se":      {{On: "openssl.org"}},
	}}
	got := unlinkedOf("acme.org/app", dir, g)
	for _, f := range got {
		if f.Dependency == "openssl.org" {
			t.Fatalf("a transitive dependency was reported: %+v", f)
		}
	}
}

// withUnlinkedSeams replaces the two seams that need a network, so the whole
// command is drivable without one.
func withUnlinkedSeams(t *testing.T, g *bottle.Graph, gerr error, ierr error, stage func(dir string)) {
	t.Helper()
	pg, pi, pt := unlinkedGraph, unlinkedInstall, unlinkedTempDir
	unlinkedGraph = func(map[string]string, string, string) (*bottle.Graph, error) { return g, gerr }
	unlinkedInstall = func(_ map[string]string, dir, _, _ string) ([]bottle.Resolved, error) {
		if ierr != nil {
			return nil, ierr
		}
		if stage != nil {
			stage(dir)
		}
		return nil, nil
	}
	t.Cleanup(func() { unlinkedGraph, unlinkedInstall, unlinkedTempDir = pg, pi, pt })
}

// The whole command on the shape it was written for.
func TestUnlinkedRunReportsAVendoredDependency(t *testing.T) {
	g := &bottle.Graph{Deps: map[string][]bottle.Edge{
		"rpm.org/rpm-sequoia": {{On: "openssl.org"}},
	}}
	withUnlinkedSeams(t, g, nil, nil, func(dir string) {
		writeLib(t, filepath.Join(dir, "openssl.org/v3.6.4/lib/libssl.so.3"))
		writeLib(t, filepath.Join(dir, "rpm.org/rpm-sequoia/v1.10.3/lib/librpm_sequoia.so"))
	})
	code, out, _ := run2(t, "unlinked", "--store", t.TempDir(), "rpm.org/rpm-sequoia")
	if code != 0 {
		t.Fatalf("want 0 without --fail, got %d: %s", code, out)
	}
	for _, want := range []string{"rpm.org/rpm-sequoia", "openssl.org", "libssl.so.3", "CANDIDATE"} {
		if !strings.Contains(out, want) {
			t.Errorf("output omits %q:\n%s", want, out)
		}
	}
	// --fail is what a gate uses.
	code, _, _ = run2(t, "unlinked", "--store", t.TempDir(), "--fail", "rpm.org/rpm-sequoia")
	if code != 1 {
		t.Fatalf("--fail must exit 1 on a finding, got %d", code)
	}
}

// Nothing found is green even with --fail, or a gate could never pass.
func TestUnlinkedRunIsGreenWhenThereIsNothing(t *testing.T) {
	g := &bottle.Graph{Deps: map[string][]bottle.Edge{}}
	withUnlinkedSeams(t, g, nil, nil, nil)
	if code, out, _ := run2(t, "unlinked", "--store", t.TempDir(), "--fail", "acme.org"); code != 0 {
		t.Fatalf("want 0, got %d: %s", code, out)
	}
}

func TestUnlinkedRunRejectsBadInput(t *testing.T) {
	withUnlinkedSeams(t, &bottle.Graph{}, nil, nil, nil)
	for _, c := range []struct {
		what string
		args []string
		want int
	}{
		{"an unknown flag", []string{"unlinked", "--nope"}, 2},
		{"a platform that is not os/arch", []string{"unlinked", "--platform", "linux", "a.org"}, 2},
		{"an empty arch", []string{"unlinked", "--platform", "linux/", "a.org"}, 2},
	} {
		if code, _, _ := run2(t, c.args...); code != c.want {
			t.Errorf("%s: want %d, got %d", c.what, c.want, code)
		}
	}
}

// A project list is required, and an empty stdin is not a list.
func TestUnlinkedRunNeedsProjects(t *testing.T) {
	prev := unlinkedStdin
	unlinkedStdin = strings.NewReader("")
	defer func() { unlinkedStdin = prev }()
	if code, _, errb := run2(t, "unlinked"); code != 2 {
		t.Fatalf("want 2, got %d: %s", code, errb)
	}
}

// ⛔ A PROJECT THAT CANNOT BE READ IS SAID AND SKIPPED, not fatal: a sweep
// over a recipe list must not stop at the first project the registry cannot
// answer for, or one gap costs the whole run.
func TestUnlinkedRunCarriesOnPastAProjectItCannotRead(t *testing.T) {
	withUnlinkedSeams(t, nil, errors.New("no such project"), nil, nil)
	code, _, errb := run2(t, "unlinked", "--store", t.TempDir(), "a.org")
	if code != 0 {
		t.Fatalf("want 0, got %d", code)
	}
	if !strings.Contains(errb, "no such project") {
		t.Errorf("the failure was not reported: %s", errb)
	}
}

func TestUnlinkedRunReportsAnInstallThatFailed(t *testing.T) {
	withUnlinkedSeams(t, &bottle.Graph{}, nil, errors.New("disk full"), nil)
	code, _, errb := run2(t, "unlinked", "--store", t.TempDir(), "a.org")
	if code != 0 {
		t.Fatalf("want 0, got %d", code)
	}
	if !strings.Contains(errb, "disk full") {
		t.Errorf("the failure was not reported: %s", errb)
	}
}

func TestUnlinkedRunReportsATempDirItCannotMake(t *testing.T) {
	withUnlinkedSeams(t, &bottle.Graph{}, nil, nil, nil)
	prev := unlinkedTempDir
	unlinkedTempDir = func(string, string) (string, error) { return "", errors.New("nowhere to write") }
	defer func() { unlinkedTempDir = prev }()
	code, _, errb := run2(t, "unlinked", "a.org")
	if code != 1 {
		t.Fatalf("want 1, got %d", code)
	}
	if !strings.Contains(errb, "nowhere to write") {
		t.Errorf("the failure was not reported: %s", errb)
	}
}

// referencedProjects has to read BOTH spellings: Mach-O carries the project
// inside the reference, ELF carries only a soname and the project has to be
// recovered from which bottle ships that file.
func TestReferencedProjectsHandlesAStoreWithNoReadableBinaries(t *testing.T) {
	dir := t.TempDir()
	writeStoreFile(t, filepath.Join(dir, "a.org/v1.0.0/share/readme.txt"), []byte("not a binary"))
	if got := referencedProjects("a.org", dir); len(got) != 0 {
		t.Fatalf("a tree with no binaries references nothing, got %v", got)
	}
}

func TestSonameOwnersAttributesALibraryToItsProject(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, filepath.Join(dir, "openssl.org/v3.6.4/lib/libssl.so.3"))
	writeStoreFile(t, filepath.Join(dir, "openssl.org/v3.6.4/include/ssl.h"), []byte("x"))
	got := sonameOwners(dir)
	if len(got["libssl.so.3"]) != 1 || got["libssl.so.3"][0] != "openssl.org" {
		t.Errorf("libssl.so.3 -> %v, want [openssl.org]", got["libssl.so.3"])
	}
	if _, ok := got["ssl.h"]; ok {
		t.Errorf("a header is not a shared library")
	}
	// ⛔ AND A LIBRARY NOBODY OWNS IS DROPPED, not attributed to "". A store
	// holds more than bottles — a staging directory, a stray file — and a
	// path with no `v<version>` segment names no project. Recording it under
	// the empty project would make the empty project "referenced", which
	// satisfies nothing and silently suppresses real findings.
	writeLib(t, filepath.Join(dir, "loose/libstray.so.1"))
	if owners := sonameOwners(dir)["libstray.so.1"]; len(owners) != 0 {
		t.Errorf("a library outside any bottle was attributed to %v", owners)
	}
}

// ⛔ THE TEST THAT WAS MISSING, AND THE SHAPE IT COULD NOT HAVE. Every other
// fixture here stages ONE project, and a one-project store has no collision —
// so `out[name] = owner` looked right in all of them and was wrong in bulk the
// first time a real store was swept. A soname with two owners is the case, and
// it is the ordinary case: in a 189-project store, `libstdc++.so.6` is shipped
// by gnu.org/gcc AND gnu.org/gcc/libstdcxx.
func TestSonameOwnersKeepsEveryOwnerOfAColliding(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, filepath.Join(dir, "gnu.org/gcc/v16.2.0/lib/libstdc++.so.6"))
	writeLib(t, filepath.Join(dir, "gnu.org/gcc/libstdcxx/v14.4.0/lib/libstdc++.so.6"))
	// The same project at several versions is ONE owner, not several:
	// openssl.org alone staged 39 copies of libssl.so.3 in that sweep.
	writeLib(t, filepath.Join(dir, "openssl.org/v3.6.4/lib/libssl.so.3"))
	writeLib(t, filepath.Join(dir, "openssl.org/v3.5.8/lib/libssl.so.3"))

	got := sonameOwners(dir)
	owners := append([]string(nil), got["libstdc++.so.6"]...)
	sort.Strings(owners)
	want := []string{"gnu.org/gcc", "gnu.org/gcc/libstdcxx"}
	if len(owners) != 2 || owners[0] != want[0] || owners[1] != want[1] {
		t.Errorf("libstdc++.so.6 -> %v, want %v", owners, want)
	}
	if len(got["libssl.so.3"]) != 1 {
		t.Errorf("one project at two versions is one owner, got %v", got["libssl.so.3"])
	}
}

// ⛔ AND THE CONSEQUENCE, which is the part that mattered: a C++ library that
// NEEDs libstdc++.so.6 must not be reported as linking none of libstdcxx just
// because another project ships a file of the same name. This is
// facebook.com/folly, reduced: it was reported, and its own DT_NEEDED names
// libstdc++.so.6 in every library it ships.
func TestACollidingSonameDoesNotFabricateAFinding(t *testing.T) {
	dir := t.TempDir()
	writeELFNeeded(t, filepath.Join(dir, "gnu.org/gcc/v16.2.0/lib/libstdc++.so.6"))
	writeELFNeeded(t, filepath.Join(dir, "gnu.org/gcc/libstdcxx/v14.4.0/lib/libstdc++.so.6"))
	writeELFNeeded(t, filepath.Join(dir, "facebook.com/folly/v2026.8.24.0/lib/libfolly.so"),
		"libstdc++.so.6", "libc.so.6")

	g := &bottle.Graph{Deps: map[string][]bottle.Edge{
		"facebook.com/folly": {{On: "gnu.org/gcc/libstdcxx"}},
	}}
	if got := unlinkedOf("facebook.com/folly", dir, g); len(got) != 0 {
		t.Fatalf("a C++ library that NEEDs libstdc++.so.6 was reported as linking none: %+v", got)
	}
}

// ⛔ THE BRANCH THAT DECIDED A RETRACTION. I reported that
// `gnu.org/libiconv` links no gettext, and it was false: I had inspected
// `v1.19.0` from my local store while what a consumer resolves is `v1.19`,
// whose `bin/iconv` carries `@rpath/gnu.org/gettext/v1/lib/libintl.8.dylib`.
// The code that reads that load command is these eight lines, so they get a
// real Mach-O and both answers — a reference seen, and a reference absent —
// rather than a fixture that can only ever agree with me.
func TestReferencedProjectsReadsRealMachOLoadCommands(t *testing.T) {
	// The real v1.19 shape, verbatim from `otool -L`.
	links := []string{
		"@rpath/gnu.org/gettext/v1/lib/libintl.8.dylib",
		"@rpath/gnu.org/libiconv/v1.19/lib/libiconv.2.dylib",
		"/usr/lib/libSystem.B.dylib",
	}
	// And v1.19.0, the bottle I actually looked at: no gettext.
	noGettext := links[1:]

	for _, c := range []struct {
		what  string
		loads []string
		want  bool
	}{
		{"the published v1.19", links, true},
		{"the v1.19.0 I misread", noGettext, false},
	} {
		dir := t.TempDir()
		writeLib(t, filepath.Join(dir, "gnu.org/gettext/v1/lib/libintl.8.dylib"))
		writeMachOAt(t, filepath.Join(dir, "gnu.org/libiconv/v1.19/bin/iconv"), c.loads...)

		got := referencedProjects("gnu.org/libiconv", dir)
		if got["gnu.org/gettext"] != c.want {
			t.Errorf("%s: gettext referenced = %v, want %v (%v)", c.what, got["gnu.org/gettext"], c.want, got)
		}
		// Either way the host's own library is not one of ours, and the
		// project's self-reference must not read as a dependency edge.
		if got[""] {
			t.Errorf("%s: the empty project leaked into the set: %v", c.what, got)
		}

		// ⛔ AND THE WHOLE ANSWER, not just the map: with the reference
		// present, a declared gettext is satisfied and SILENCE is correct —
		// that silence is the finding I should have trusted the first time.
		g := &bottle.Graph{Deps: map[string][]bottle.Edge{
			"gnu.org/libiconv": {{On: "gnu.org/gettext"}},
		}}
		findings := unlinkedOf("gnu.org/libiconv", dir, g)
		if c.want && len(findings) != 0 {
			t.Errorf("%s: links gettext and was reported anyway: %+v", c.what, findings)
		}
		if !c.want && len(findings) != 1 {
			t.Errorf("%s: links no gettext and was not reported: %+v", c.what, findings)
		}
	}
}

// ⛔ THE @rpath PARSE, ISOLATED. In the test above, gettext IS staged, so
// the basename lookup would have answered too and either line alone would
// have passed it — the two are redundant on that fixture and neither is
// witnessed. Here NOTHING of the referenced project is staged, so the owner
// map is empty and only the project name carried INSIDE the reference can
// answer. A partially staged tree is the case that makes this matter.
func TestReferencedProjectsReadsTheProjectInsideAnRpathWithNothingStaged(t *testing.T) {
	dir := t.TempDir()
	writeMachOAt(t, filepath.Join(dir, "acme.org/app/v1.0.0/bin/app"),
		"@rpath/other.org/dep/v2/lib/libdep.2.dylib")

	got := referencedProjects("acme.org/app", dir)
	if !got["other.org/dep"] {
		t.Errorf("the project inside the @rpath was not read: %v", got)
	}
}

// ⛔ A MACH-O REFERENCE THAT IS NOT @rpath STILL NAMES A PROJECT. An absolute
// install name (`/opt/.../libfoo.dylib`, or a bottle built before the fix-ups
// rewrote it) carries no project, so the owner has to come from the FILE NAME
// the way the ELF half does. Without this, such a bottle looks like it links
// nothing and every one of its declarations reads as a finding.
func TestReferencedProjectsAttributesANonRpathDylibByName(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, filepath.Join(dir, "gnu.org/gettext/v1/lib/libintl.8.dylib"))
	writeMachOAt(t, filepath.Join(dir, "acme.org/app/v1.0.0/bin/app"),
		"/opt/homebrew/lib/libintl.8.dylib")

	if got := referencedProjects("acme.org/app", dir); !got["gnu.org/gettext"] {
		t.Errorf("an absolute install name was not attributed to its owner: %v", got)
	}
}

// ⛔ THE ELF HALF, which is the half that matters: rpm.org/rpm-sequoia — the
// one confirmed vendoring case — is published for linux and not for darwin,
// so on this machine the Mach-O branch can never reach it. ELF carries only
// a soname, so the project comes from whichever bottle ships that file.
func TestReferencedProjectsRecoversAProjectFromAnELFSoname(t *testing.T) {
	dir := t.TempDir()
	writeELFNeeded(t, filepath.Join(dir, "openssl.org/v3.6.4/lib/libssl.so.3"))
	writeELFNeeded(t, filepath.Join(dir, "openssl.org/v3.6.4/lib/libcrypto.so.3"))

	// A library that links openssl, and the one that vendored it.
	writeELFNeeded(t, filepath.Join(dir, "good.org/v1.0.0/lib/libgood.so"), "libssl.so.3", "libc.so.6")
	writeELFNeeded(t, filepath.Join(dir, "rpm.org/rpm-sequoia/v1.10.3/lib/librpm_sequoia.so"), "libc.so.6")

	if got := referencedProjects("good.org", dir); !got["openssl.org"] {
		t.Errorf("NEEDED libssl.so.3 was not attributed to openssl.org: %v", got)
	}
	// ⛔ libc.so.6 is NEEDED by both and owned by nobody staged here. An
	// unattributable soname must be dropped, not recorded as a reference to
	// the empty project — which would then satisfy every declaration.
	if got := referencedProjects("rpm.org/rpm-sequoia", dir); len(got) != 0 {
		t.Errorf("the vendoring case referenced something: %v", got)
	}
}

// Two findings, so the ordering the report promises is actually exercised.
func TestUnlinkedSortsItsFindingsByDependency(t *testing.T) {
	dir := t.TempDir()
	writeLib(t, filepath.Join(dir, "zlib.net/v1.3.2/lib/libz.1.dylib"))
	writeLib(t, filepath.Join(dir, "openssl.org/v3.6.4/lib/libssl.3.dylib"))
	writeMachOAt(t, filepath.Join(dir, "acme.org/app/v1.0.0/bin/app"), "/usr/lib/libSystem.B.dylib")

	g := &bottle.Graph{Deps: map[string][]bottle.Edge{
		"acme.org/app": {{On: "zlib.net"}, {On: "openssl.org"}},
	}}
	got := unlinkedOf("acme.org/app", dir, g)
	if len(got) != 2 {
		t.Fatalf("want both reported, got %+v", got)
	}
	if got[0].Dependency != "openssl.org" || got[1].Dependency != "zlib.net" {
		t.Errorf("not sorted by dependency: %+v", got)
	}
}

// --platform is the flag that lets a mac audit linux, which is the only way
// to reach rpm-sequoia at all. A test that never passes a valid one leaves
// the assignment that makes it work unexecuted.
func TestUnlinkedRunHonoursAValidPlatform(t *testing.T) {
	var sawOS, sawArch string
	// withUnlinkedSeams first, so its Cleanup captures the REAL seams and the
	// probe below is what gets restored over, not under.
	withUnlinkedSeams(t, &bottle.Graph{}, nil, nil, nil)
	unlinkedGraph = func(_ map[string]string, osn, arch string) (*bottle.Graph, error) {
		sawOS, sawArch = osn, arch
		return &bottle.Graph{}, nil
	}

	if code, _, errb := run2(t, "unlinked", "--store", t.TempDir(), "--platform", "linux/x86-64", "a.org"); code != 0 {
		t.Fatalf("want 0, got %d: %s", code, errb)
	}
	if sawOS != "linux" || sawArch != "x86-64" {
		t.Errorf("the graph was asked for %s/%s, want linux/x86-64", sawOS, sawArch)
	}
}

// A project list that cannot be READ is not an empty list, and the two must
// not share an exit status: 2 is a usage error the caller can fix, 1 is a
// read that failed under them.
func TestUnlinkedRunReportsAProjectListItCannotRead(t *testing.T) {
	prev := unlinkedStdin
	unlinkedStdin = iotest.ErrReader(errors.New("pipe broke"))
	defer func() { unlinkedStdin = prev }()
	code, _, errb := run2(t, "unlinked")
	if code != 1 {
		t.Fatalf("want 1 (a failed read, not a usage error), got %d: %s", code, errb)
	}
	if !strings.Contains(errb, "pipe broke") {
		t.Errorf("the failure was not reported: %s", errb)
	}
}

// ⛔ THE CONSEQUENCE OF THE v0.44.0 REGRESSION, end to end. A soname the
// check does not recognise cannot be attributed to its owner, so a project
// that DOES link it reads as one that does not. Reduced from the second
// sweep, where facebook.com/fbthrift, wangle, fizz, edencommon and fb303 —
// five libraries built ON folly — were each reported as linking none of it.
func TestASonameWithANonNumericVersionIsStillAttributed(t *testing.T) {
	dir := t.TempDir()
	writeELFNeeded(t, filepath.Join(dir, "facebook.com/folly/v2026.8.24.0/lib/libfolly.so.0.58.0-dev"))
	writeELFNeeded(t, filepath.Join(dir, "facebook.com/fbthrift/v2026.8.24.0/lib/libthriftcpp2.so"),
		"libfolly.so.0.58.0-dev", "libc.so.6")

	g := &bottle.Graph{Deps: map[string][]bottle.Edge{
		"facebook.com/fbthrift": {{On: "facebook.com/folly"}},
	}}
	if got := unlinkedOf("facebook.com/fbthrift", dir, g); len(got) != 0 {
		t.Fatalf("a library that NEEDs libfolly.so.0.58.0-dev was reported as linking none of folly: %+v", got)
	}
}

// ⛔ THE NAME IS A PREFILTER, THE BYTES DECIDE — and the two filenames that
// made that necessary are both here, as real files.
//
// `libstdc++.so.6.0.33-gdb.py` is a GDB pretty-printer: `file(1)` calls it
// "Python script text executable". v0.43 counted it as a library, because
// what follows `.so` begins with a dot.
//
// `libfolly.so.0.58.0-dev` is an "ELF 64-bit LSB shared object", named in the
// DT_NEEDED of every library facebook.com/fbthrift ships. v0.44.0 REFUSED it,
// because what follows `.so` is not dot-separated numbers — and five of
// folly's dependents were then reported as not linking folly.
//
// One rule invented libraries and the next hid them. Both were a guess about
// a filename standing in for a fact about a file.
func TestIsSharedLibraryAsksTheBytesNotTheName(t *testing.T) {
	dir := t.TempDir()
	lib := func(name string) string { return filepath.Join(dir, name) }

	for _, yes := range []string{
		"libiconv.2.dylib", "libintl.dylib",
		"libssl.so", "libssl.so.3", "libssl.so.1.1",
		"libstdc++.so.6", "libstdc++.so.6.0.33", "libgcc_s.so.1",
		// ⛔ THE REGRESSION v0.44.0 SHIPPED: a real ELF with a non-numeric
		// version suffix.
		"libfolly.so.0.58.0-dev",
	} {
		writeLib(t, lib(yes))
		if !isSharedLibrary(lib(yes), yes) {
			t.Errorf("%q is a shared library", yes)
		}
	}

	// A file whose NAME could pass but whose bytes are not an object: the GDB
	// script, a linker script spelled `.so`, an archive, ordinary data.
	for _, no := range []struct{ name, body string }{
		{"libstdc++.so.6.0.33-gdb.py", "# -*- python -*-\nimport gdb\n"},
		{"libgcc_s_asneeded.so", "/* GNU ld script */\nOUTPUT_FORMAT(elf64-x86-64)\n"},
		{"libiconv.a", "!<arch>\n"},
		{"iconv.h", "#define ICONV_H\n"},
		{"libiconv.mo", "\xde\x12\x04\x95"},
		{"README.sofar", "notes\n"},
		// Shorter than a magic number — an interrupted write, a truncated
		// unpack. Too short to read is not "assume it is a library".
		{"libtruncated.so.1", "\x7fE"},
		{"libempty.so", ""},
	} {
		writeStoreFile(t, lib(no.name), []byte(no.body))
		if isSharedLibrary(lib(no.name), no.name) {
			t.Errorf("%q is not a shared library", no.name)
		}
	}

	// A name the prefilter rejects outright never reaches the disk, and must
	// not be admitted by a file that happens to exist beside it.
	writeLib(t, lib("libreal.so"))
	if isSharedLibrary(lib("libreal.so"), "libreal.a") {
		t.Errorf("a .a name was admitted because an unrelated file is an ELF")
	}
	// And a name that passes the prefilter with nothing behind it is not a
	// library either: an unreadable entry is a reason to say nothing.
	if isSharedLibrary(lib("libabsent.so"), "libabsent.so") {
		t.Errorf("a file that is not there was called a shared library")
	}
}
