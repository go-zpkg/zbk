package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-attest/sbom"
	"github.com/go-attest/sign"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// catbed is a pantry and an overlay with a few recipes in each, plus the
// frozen clock and captured write the other command tests use.
func catbed(t *testing.T, pantry, overlay map[string]string) (string, string, *map[string][]byte) {
	t.Helper()
	write := func(root string, recipes map[string]string) string {
		dir := t.TempDir()
		for proj, body := range recipes {
			p := filepath.Join(dir, "projects", proj)
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "package.yml"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	p := write("pantry", pantry)
	o := ""
	if overlay != nil {
		o = write("overlay", overlay)
	}
	prevNow, prevWrite := catalogNow, osWriteFile
	catalogNow = func() time.Time { return time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC) }
	files := map[string][]byte{}
	osWriteFile = func(name string, b []byte, _ os.FileMode) error { files[name] = b; return nil }
	t.Cleanup(func() { catalogNow, osWriteFile = prevNow, prevWrite })
	return p, o, &files
}

const catRecipe = "versions:\n  - 1.0.0\nbuild: make\n"

// The UNION of pantry and overlay, because both are real: a project in only
// one of them is still a project somebody can ask for.
func TestCatalogIsTheUnionOfPantryAndOverlay(t *testing.T) {
	p, o, _ := catbed(t,
		map[string]string{"zlib.net": catRecipe, "gnu.org/bash": catRecipe},
		map[string]string{"gnu.org/bash": catRecipe, "curl.se/ca-certs": catRecipe})
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--overlay", o}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	cat, err := artifact.UnmarshalCatalog(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, pr := range cat.Projects {
		names = append(names, pr.Project)
	}
	if strings.Join(names, " ") != "curl.se/ca-certs gnu.org/bash zlib.net" {
		t.Errorf("projects = %v (the union, sorted, deduplicated)", names)
	}
	if cat.Generated != "2026-10-05T09:00:00Z" {
		t.Errorf("generated = %q", cat.Generated)
	}
}

// go-zpkg/packages#387: the first wasip1/wasm catalogue listed 6 of the 7
// projects the wasm lanes build. The seventh, github.com/simdjson/simdjson,
// has its recipe ONLY in packages/wasip1/recipes — neither the pantry nor the
// overlay carries it — so a catalogue read from those two could never name a
// artifact that is published and installable. The fixture has the real shape: a
// `github.com/<org>/<repo>` slug in a FLAT tree (no `projects/` level), beside
// projects BOTH trees have (lua.org, zlib.net, filippo.io/age), whose LANE
// recipe wins since go-zpkg/bk#376 (#375 had the pantry winning).
func TestCatalogNamesAProjectOnlyAPlatformLaneBuilds(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{
		"lua.org": "versions:\n  - 5.4.9\ndependencies:\n  gnu.org/readline: '*'\nbuild: make\n",
		// The HOST recipe of a library: no command at all (go-zpkg/bk#376).
		"zlib.net": "versions:\n  - 1.3.2\nbuild: make\n",
		// The HOST recipe builds both commands; the lane builds one.
		"filippo.io/age": "versions:\n  - 1.2.1\nprovides:\n  - bin/age\n  - bin/age-keygen\nbuild: make\n",
	}, nil)
	flat := t.TempDir()
	for slug, body := range map[string]string{
		"github.com/simdjson/simdjson": "versions:\n  - 5.0.5\ndependencies:\n  zlib.net: '*'\nbuild: make\n",
		"lua.org":                      "versions:\n  - 5.4.9\nbuild: make\n",
		"zlib.net":                     "versions:\n  - 1.3.2\nbuild: make\nprovides:\n  - bin/minigzip\n",
		"filippo.io/age":               "versions:\n  - 1.2.1\nprovides:\n  - bin/age\nbuild: make\n",
	} {
		d := filepath.Join(flat, filepath.FromSlash(slug))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "package.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prevV, prevP := versionsFor, publishedTagFor
	versionsFor = func(project, osn, arch string) ([]artifact.Ver, bool, error) {
		return []artifact.Ver{artifact.ParseVer("5.0.5")}, true, nil
	}
	publishedTagFor = func(project string, v artifact.Ver, osn, arch string) (string, bool, error) {
		return "v" + v.Raw, true, nil
	}
	t.Cleanup(func() { versionsFor, publishedTagFor = prevV, prevP })

	var out, errb bytes.Buffer
	args := []string{"--pantry", p, "--platform", "wasip1/wasm", "--versions", "--recipes", flat}
	if code := runCatalog(args, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	cat, err := artifact.UnmarshalCatalog(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sj, ok := cat.Lookup("github.com/simdjson/simdjson")
	if !ok {
		t.Fatalf("github.com/simdjson/simdjson missing from the catalogue; got %d project(s)", len(cat.Projects))
	}
	if strings.Join(sj.Versions, " ") != "5.0.5" || strings.Join(sj.Deps, " ") != "zlib.net" {
		t.Errorf("simdjson = versions %v deps %v; want [5.0.5] [zlib.net]", sj.Versions, sj.Deps)
	}
	// go-zpkg/bk#376: a project in BOTH trees is described by the LANE's
	// recipe, in both directions.
	if lua, _ := cat.Lookup("lua.org"); len(lua.Deps) != 0 {
		t.Errorf("lua.org deps = %v; the lane declares none and its recipe is the one for this platform", lua.Deps)
	}
	if z, _ := cat.Lookup("zlib.net"); strings.Join(z.Provides, " ") != "minigzip" {
		t.Errorf("zlib.net provides = %v; the lane's minigzip was hidden by a host recipe that provides nothing", z.Provides)
	}
	if a, _ := cat.Lookup("filippo.io/age"); strings.Join(a.Provides, " ") != "age" {
		t.Errorf("filippo.io/age provides = %v; age-keygen is the host recipe's, not the lane's", a.Provides)
	}
	if len(cat.Projects) != 4 {
		t.Errorf("projects = %d, want 4 (deduplicated)", len(cat.Projects))
	}
}

// A flat tree named on the command line that cannot be walked is an error:
// unlike an absent overlay, somebody asked for it.
func TestCatalogRefusesAnUnreadableRecipesTree(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"a.org": catRecipe}, nil)
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--recipes", filepath.Join(t.TempDir(), "nope")}, &out, &errb); code != 1 {
		t.Fatalf("code=%d, want 1", code)
	}
}

// An empty catalogue would be published and believed. A pantry that reads as
// empty is a mistyped path far more often than an empty pantry.
func TestCatalogRefusesToBuildNothing(t *testing.T) {
	// A pantry that EXISTS and holds no recipe. Not a bare temp dir: a
	// directory with no `projects/` at all is unreadable, not empty, and
	// the next assertion is precisely that the two differ.
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "projects"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", empty}, &out, &errb); code != 1 {
		t.Fatalf("an empty pantry exited %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "not a result") {
		t.Errorf("stderr=%q", errb.String())
	}
	// A pantry path that does not exist is a DIFFERENT failure and must say
	// so. Both exit 1; only the message tells the user which mistake they
	// made, and for a while both said "an empty catalogue is not a result".
	errb.Reset()
	missing := filepath.Join(t.TempDir(), "nope")
	if code := runCatalog([]string{"--pantry", missing}, &out, &errb); code != 1 {
		t.Errorf("an absent pantry exited %d", code)
	}
	if strings.Contains(errb.String(), "not a result") {
		t.Errorf("an unreadable pantry was reported as an empty one: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "no such file") {
		t.Errorf("it does not say what went wrong: %q", errb.String())
	}
}

// A file that is not a recipe is skipped rather than taken for a project.
func TestCatalogIgnoresWhatIsNotARecipe(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"zlib.net": catRecipe}, nil)
	for _, name := range []string{"README.md", "test.c"} {
		if err := os.WriteFile(filepath.Join(p, "projects", "zlib.net", name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	cat, _ := artifact.UnmarshalCatalog(out.Bytes())
	if len(cat.Projects) != 1 || cat.Projects[0].Project != "zlib.net" {
		t.Errorf("projects = %+v", cat.Projects)
	}
}

func TestCatalogRefusesABadPlatformAndBadFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--platform", "linux"}, &out, &errb); code != 2 {
		t.Errorf("a platform with no slash exited %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "wants os/arch") {
		t.Errorf("stderr=%q", errb.String())
	}
	if code := runCatalog([]string{"--nope"}, &out, &errb); code != 2 {
		t.Errorf("an unknown flag exited %d, want 2", code)
	}
}

func TestCatalogWritesAFile(t *testing.T) {
	p, _, files := catbed(t, map[string]string{"zlib.net": catRecipe}, nil)
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "-o", "/tmp/c.json"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	if _, ok := (*files)["/tmp/c.json"]; !ok {
		t.Fatalf("nothing written; %v", *files)
	}
	if out.Len() != 0 {
		t.Errorf("it wrote the file AND stdout: %q", out.String())
	}
	if !strings.Contains(errb.String(), "1 project(s)") {
		t.Errorf("no count: %q", errb.String())
	}
	// A write that fails is a failure.
	prev := osWriteFile
	osWriteFile = func(string, []byte, os.FileMode) error { return os.ErrPermission }
	t.Cleanup(func() { osWriteFile = prev })
	if code := runCatalog([]string{"--pantry", p, "-o", "/tmp/c.json"}, &out, &errb); code != 1 {
		t.Errorf("an unwritable file exited %d, want 1", code)
	}
}

// A catalogue that cannot be rendered is not published as a shorter one.
func TestCatalogReportsAMarshalFailure(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"zlib.net": catRecipe}, nil)
	prev := marshalCatalog
	marshalCatalog = func(artifact.Catalog) ([]byte, error) { return nil, errors.New("nope") }
	t.Cleanup(func() { marshalCatalog = prev })
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p}, &out, &errb); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(errb.String(), "nope") {
		t.Errorf("stderr=%q", errb.String())
	}
}

// A catalogue is published the way an artifact is published, SIGNATURE
// INCLUDED. A client with ZPKG_VERIFY on — the default — refuses an
// unsigned one, and rightly: the catalogue is the list of names a person
// then types, so deciding its contents is deciding what <TAB> offers.
func TestCatalogPublishes(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"zlib.net": catRecipe, "gnu.org/bash": catRecipe}, nil)
	var gotOS, gotArch, gotProject, gotVer, gotExt string
	var gotTgz []byte
	var gotRefs []artifact.Referrer
	prevP, prevK, prevT := ociPush, signingKey, catalogTarball
	ociPush = func(_, project, ver, osn, arch string, tgz []byte, ext string, refs []artifact.Referrer, _ map[string]string) (ocispec.Descriptor, error) {
		gotProject, gotVer, gotOS, gotArch, gotTgz, gotExt, gotRefs = project, ver, osn, arch, tgz, ext, refs
		return ocispec.Descriptor{}, nil
	}
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signingKey = func(string) (*sign.Keypair, error) { return kp, nil }
	t.Cleanup(func() { ociPush, signingKey, catalogTarball = prevP, prevK, prevT })

	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--platform", "linux/s390x", "--publish"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	if gotOS != "linux" || gotArch != "s390x" {
		t.Errorf("published for %s/%s", gotOS, gotArch)
	}
	if gotProject != artifact.CatalogProjectName || gotVer != artifact.CatalogVersion || gotExt != artifact.ExtTarGz {
		t.Errorf("published as %s v%s %s", gotProject, gotVer, gotExt)
	}
	cat, err := artifact.CatalogFromTarball(gotTgz)
	if err != nil {
		t.Fatalf("what was pushed is not a catalogue: %v", err)
	}
	if len(cat.Projects) != 2 {
		t.Errorf("published %d projects", len(cat.Projects))
	}
	// The signature, which is the point.
	signed := false
	for _, r := range gotRefs {
		if r.ArtifactType == artifact.ArtifactTypeSignature {
			signed = true
		}
	}
	if !signed {
		t.Error("the catalogue went out unsigned — a client with ZPKG_VERIFY on refuses it")
	}
	if !strings.Contains(errb.String(), "+signature") {
		t.Errorf("the publish does not say it signed: %q", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("a publish also wrote the body to stdout: %q", out.String())
	}

	// No key: it still publishes, because the sovereign seed registry has
	// none and ZPKG_VERIFY=0 there — but it says what that means, in terms
	// of what a client will do, not as advice about style.
	errb.Reset()
	signingKey = func(string) (*sign.Keypair, error) { return nil, nil }
	if code := runCatalog([]string{"--pantry", p, "--publish"}, &out, &errb); code != 0 {
		t.Fatalf("an unsigned publish exited %d: %s", code, errb.String())
	}
	for _, r := range gotRefs {
		if r.ArtifactType == artifact.ArtifactTypeSignature {
			t.Error("a signature appeared with no key")
		}
	}
	if !strings.Contains(errb.String(), "ZPKG_VERIFY") {
		t.Errorf("an unsigned publish does not say what a client will do: %q", errb.String())
	}

	// Every way it can fail, because a publish that reports success on a
	// registry that refused it is how an empty catalogue gets believed.
	signingKey = func(string) (*sign.Keypair, error) { return nil, errors.New("not a key") }
	if code := runCatalog([]string{"--pantry", p, "--publish"}, &out, &errb); code != 1 {
		t.Errorf("an unreadable key exited %d", code)
	}
	signingKey = func(string) (*sign.Keypair, error) { return nil, nil }

	catalogTarball = func(artifact.Catalog) ([]byte, error) { return nil, errors.New("cannot pack") }
	if code := runCatalog([]string{"--pantry", p, "--publish"}, &out, &errb); code != 1 {
		t.Errorf("an unpackable catalogue exited %d", code)
	}
	catalogTarball = prevT

	// A referrer that cannot be built: the attestations are not optional
	// decoration, they are what the thing is published WITH.
	prevSbom := sbomJSON
	sbomJSON = func(sbom.Document) ([]byte, error) { return nil, errors.New("no sbom") }
	if code := runCatalog([]string{"--pantry", p, "--publish"}, &out, &errb); code != 1 {
		t.Errorf("an unbuildable referrer exited %d", code)
	}
	sbomJSON = prevSbom

	ociPush = func(string, string, string, string, string, []byte, string, []artifact.Referrer, map[string]string) (ocispec.Descriptor, error) {
		return ocispec.Descriptor{}, errors.New("registry down")
	}
	if code := runCatalog([]string{"--pantry", p, "--publish"}, &out, &errb); code != 1 {
		t.Errorf("a failed push exited %d", code)
	}
}

// --versions is one request per project, so it SAYS how many before making
// them, and a project the registry cannot answer for is warned rather than
// taking the other 1907 down with it.
func TestCatalogVersionsIsOptInAndSurvivesOneFailure(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"a.org": catRecipe, "b.org": catRecipe}, nil)
	prevV, prevP := versionsFor, publishedTagFor
	versionsFor = func(project, osn, arch string) ([]artifact.Ver, bool, error) {
		switch project {
		case "a.org":
			return []artifact.Ver{artifact.ParseVer("1.0.0"), artifact.ParseVer("2.0.0")}, true, nil
		case "b.org":
			return nil, false, errors.New("not found")
		}
		return nil, false, nil
	}
	publishedTagFor = func(_ string, v artifact.Ver, _, _ string) (string, bool, error) {
		return v.Raw, true, nil
	}
	t.Cleanup(func() { versionsFor, publishedTagFor = prevV, prevP })

	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--versions"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "asking the registry about 2 project(s)") {
		t.Errorf("it did not say how many requests it would make: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "b.org: not found") {
		t.Errorf("the one failure was not warned: %q", errb.String())
	}
	cat, err := artifact.UnmarshalCatalog(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := cat.Lookup("a.org")
	if len(a.Versions) != 1 || a.Versions[0] != "2.0.0" {
		t.Errorf("a.org = %+v, want the newest version this platform carries", a)
	}
	b, _ := cat.Lookup("b.org")
	if len(b.Versions) != 0 {
		t.Errorf("b.org got versions from a failed call: %+v", b)
	}
	// And without --versions, nothing is asked at all.
	versionsFor = func(string, string, string) ([]artifact.Ver, bool, error) {
		t.Fatal("the registry was asked without --versions")
		return nil, false, nil
	}
	out.Reset()
	if code := runCatalog([]string{"--pantry", p}, &out, &errb); code != 0 {
		t.Fatalf("code=%d", code)
	}
}

// A project whose registry entry is empty keeps an empty Versions rather
// than an invented one.
func TestCatalogVersionsSkipsAnEmptyAnswer(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"a.org": catRecipe}, nil)
	prev := versionsFor
	versionsFor = func(string, string, string) ([]artifact.Ver, bool, error) { return nil, true, nil }
	t.Cleanup(func() { versionsFor = prev })
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--versions"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	cat, _ := artifact.UnmarshalCatalog(out.Bytes())
	if a, _ := cat.Lookup("a.org"); len(a.Versions) != 0 || len(a.Platforms) != 0 {
		t.Errorf("an empty answer invented something: %+v", a)
	}
}

// "Available" is a claim about ONE registry, and a version is a claim
// about ONE platform. Both were being made without being checked.
//
// borrowed  the list came from the upstream dist, because this registry
//
//	has never published the project. Named, no version: that is
//	the answer a person looking for doxygen.nl needs.
//
// elsewhere the tag is ours but the artifact is for another architecture —
//
//	a mirror wave that landed x86-64 and not s390x.
//
// older     the newest tag is not here but an older one is, so the walk
//
//	goes down and reports the version a reader would GET.
func TestCatalogRecordsOnlyWhatThisRegistryHasForThisPlatform(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{
		"borrowed.org": catRecipe, "elsewhere.org": catRecipe,
		"older.org": catRecipe, "here.org": catRecipe, "down.org": catRecipe,
	}, nil)
	prevV, prevP := versionsFor, publishedTagFor
	three := []artifact.Ver{artifact.ParseVer("1.0.0"), artifact.ParseVer("2.0.0"), artifact.ParseVer("3.0.0")}
	versionsFor = func(project, osn, arch string) ([]artifact.Ver, bool, error) {
		return three, project != "borrowed.org", nil
	}
	probes := map[string]int{}
	publishedTagFor = func(project string, v artifact.Ver, _, _ string) (string, bool, error) {
		probes[project]++
		switch project {
		case "elsewhere.org":
			return "", false, nil
		case "older.org":
			return v.Raw, v.Raw == "2.0.0", nil
		case "down.org":
			return "", false, errors.New("registry down")
		}
		return v.Raw, true, nil
	}
	t.Cleanup(func() { versionsFor, publishedTagFor = prevV, prevP })

	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--versions"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	cat, err := artifact.UnmarshalCatalog(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		project, version string
	}{
		{"borrowed.org", ""},
		{"elsewhere.org", ""},
		{"older.org", "2.0.0"},
		{"here.org", "3.0.0"},
		{"down.org", ""},
	} {
		got, ok := cat.Lookup(c.project)
		if !ok {
			t.Errorf("%s is not even NAMED — a reader cannot learn it exists", c.project)
			continue
		}
		have := ""
		if len(got.Versions) > 0 {
			have = got.Versions[0]
		}
		if have != c.version {
			t.Errorf("%s = %q, want %q", c.project, have, c.version)
		}
		if (len(got.Platforms) > 0) != (c.version != "") {
			t.Errorf("%s platforms %v disagree with version %q", c.project, got.Platforms, have)
		}
	}
	// A probe that FAILED is warned, and leaves the project bare rather
	// than silently indistinguishable from one with no artifact: "the
	// registry did not answer" and "the registry has nothing" are
	// different facts and only one of them is about the catalogue.
	if !strings.Contains(errb.String(), "down.org: registry down") {
		t.Errorf("a failed probe was swallowed: %q", errb.String())
	}

	// A borrowed list is not probed at all: there is nothing of ours to
	// probe, and 1900 pointless requests is the cost of asking anyway.
	if probes["borrowed.org"] != 0 {
		t.Errorf("a project we never published cost %d probe(s)", probes["borrowed.org"])
	}
	// The ordinary case costs ONE, which is the whole reason the walk
	// stops at the first hit.
	if probes["here.org"] != 1 {
		t.Errorf("the ordinary case cost %d probe(s)", probes["here.org"])
	}
}

// A project with no artifact here must not cost one request per tag: that
// is the normal state of a young lane, times two thousand projects.
func TestThePlatformProbeIsBounded(t *testing.T) {
	var vs []artifact.Ver
	for i := 1; i <= 40; i++ {
		vs = append(vs, artifact.ParseVer(fmt.Sprintf("%d.0.0", i)))
	}
	n := 0
	prev := publishedTagFor
	publishedTagFor = func(string, artifact.Ver, string, string) (string, bool, error) {
		n++
		return "", false, nil
	}
	t.Cleanup(func() { publishedTagFor = prev })
	if _, ok, err := newestHere("x.org", vs, "linux", "s390x"); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if n != platformProbes {
		t.Errorf("%d probe(s) over 40 versions, want %d", n, platformProbes)
	}

	// And a probe that fails is reported, not read as "not here": those
	// are different answers and only one of them is about the registry's
	// contents.
	publishedTagFor = func(string, artifact.Ver, string, string) (string, bool, error) {
		return "", false, errors.New("registry down")
	}
	if _, _, err := newestHere("x.org", vs, "linux", "s390x"); err == nil {
		t.Error("a failed probe reads as an absent artifact")
	}
}

// The version a reader is shown must be the NEWEST, and version order is
// not string order: a plain sort puts "1.9" above "1.10".
func TestNewestHereUsesVersionOrderNotStringOrder(t *testing.T) {
	vs := []artifact.Ver{artifact.ParseVer("1.9"), artifact.ParseVer("1.10")} // ascending, as artifact returns them
	prev := publishedTagFor
	publishedTagFor = func(_ string, v artifact.Ver, _, _ string) (string, bool, error) {
		return v.Raw, true, nil
	}
	t.Cleanup(func() { publishedTagFor = prev })
	got, ok, err := newestHere("x.org", vs, "linux", "x86-64")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got != "1.10" {
		t.Errorf("newest = %q, want 1.10 — a string sort would say 1.9", got)
	}
}

// TestCatalogDispatch covers the main-loop route.
func TestCatalogDispatch(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"zlib.net": catRecipe}, nil)
	code, out, errs := run2(t, "catalog", "--pantry", p)
	if code != 0 {
		t.Fatalf("code=%d %s", code, errs)
	}
	if !strings.Contains(out, `"zlib.net"`) {
		t.Errorf("out=%q", out)
	}
}

// One unreadable directory inside the pantry must not take the catalogue
// down with it: the other 1907 projects are still projects. Only a failure
// AT THE ROOT means the pantry could not be read.
func TestCatalogSurvivesOneUnreadableDirectory(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"zlib.net": catRecipe, "gnu.org/bash": catRecipe}, nil)
	locked := filepath.Join(p, "projects", "locked.org")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skip("cannot make a directory unreadable here:", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if f, err := os.Open(locked); err == nil { // running as root, say
		_ = f.Close()
		t.Skip("this user can read a 0000 directory")
	}

	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p}, &out, &errb); code != 0 {
		t.Fatalf("one unreadable directory failed the whole catalogue: %d %s", code, errb.String())
	}
	cat, err := artifact.UnmarshalCatalog(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Projects) != 2 {
		t.Errorf("projects = %+v", cat.Projects)
	}
}

// The dependency half of the catalogue: what a project NEEDS, reduced for
// the platform, read off the recipe already on disk.
func TestCatalogCarriesRuntimeDependencies(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{
		"app.org": "versions:\n  - 1.0.0\ndependencies:\n  lib.org: '*'\n  linux:\n    only-on-linux.org: '*'\nbuild:\n  dependencies:\n    buildonly.org: '*'\n  script: make\n",
		"lib.org": catRecipe,
	}, nil)
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--platform", "linux/x86-64"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	cat, err := artifact.UnmarshalCatalog(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	app, _ := cat.Lookup("app.org")
	if strings.Join(app.Deps, " ") != "lib.org only-on-linux.org" {
		t.Errorf("app.org deps = %v (sorted, platform-reduced)", app.Deps)
	}
	// BUILD dependencies are not in anybody's installed closure, so they
	// are not under the node a browser is looking at.
	for _, d := range app.Deps {
		if d == "buildonly.org" {
			t.Error("a build dependency reached the catalogue")
		}
	}
	// And the other platform's dependency is NOT there.
	out.Reset()
	if code := runCatalog([]string{"--pantry", p, "--platform", "darwin/aarch64"}, &out, &errb); code != 0 {
		t.Fatalf("darwin: code=%d", code)
	}
	dcat, _ := artifact.UnmarshalCatalog(out.Bytes())
	dapp, _ := dcat.Lookup("app.org")
	if strings.Join(dapp.Deps, " ") != "lib.org" {
		t.Errorf("darwin app.org deps = %v; the linux-only one leaked", dapp.Deps)
	}
}

// A project the walk NAMED and the reader cannot load is COUNTED, not
// silent. Listing it with no dependencies is a statement, and a false one.
func TestCatalogCountsProjectsItCannotRead(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"a.org": catRecipe, "b.org": catRecipe}, nil)
	prev := recipeLoader
	recipeLoader = func(set *logical.Set, overlay, pantry, proj string) (*pantry.Recipe, string, error) {
		if proj == "b.org" {
			return nil, "", errors.New("vanished")
		}
		return prev(set, overlay, pantry, proj)
	}
	t.Cleanup(func() { recipeLoader = prev })

	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p}, &out, &errb); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(errb.String(), "1 project(s) named but unreadable") {
		t.Errorf("the unreadable project was not counted: %q", errb.String())
	}
	// It is still LISTED — it exists, we just cannot say what it needs.
	if _, ok := (func() (artifact.CatalogProject, bool) {
		c, _ := artifact.UnmarshalCatalog(out.Bytes())
		return c.Lookup("b.org")
	}()); !ok {
		t.Error("an unreadable project was dropped from the catalogue entirely")
	}
}

// An unparseable --overrides is a startup error here too: the overrides
// change what a recipe DEPENDS ON, so a catalogue built without them would
// describe a different tree from the one the factory builds.
func TestCatalogRefusesUnparseableOverrides(t *testing.T) {
	p, _, _ := catbed(t, map[string]string{"a.org": catRecipe}, nil)
	ov := t.TempDir()
	if err := os.WriteFile(filepath.Join(ov, "broken.hcl"), []byte("project \"x\" {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runCatalog([]string{"--pantry", p, "--overrides", ov}, &out, &errb); code != 2 {
		t.Fatalf("code=%d, want 2 (stderr=%q)", code, errb.String())
	}
}
