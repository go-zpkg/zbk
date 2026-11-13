package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/target"
)

// fakePicker is the control. The live registry cannot plant a positive, and a
// detector exercised only against real data cannot be shown to SEE the thing
// it looks for — only to have not crashed.
type fakePicker struct {
	tags    map[string][]string
	missing map[string]bool // "project@tag" that is tagged but not published here
}

func (f fakePicker) Pick(project, constraint string) string {
	return newestPublished(f.tags[project], constraint, func(tag string) bool {
		return !f.missing[project+"@"+tag]
	})
}

// The real abseil tags, so the planted positive is the measured case rather
// than a convenient invention.
func abseilPicker() fakePicker {
	return fakePicker{tags: map[string][]string{
		"abseil.io": {"20260817.0", "20260526.0", "20250512.2.0", "20250127.2.0"},
	}}
}

// ⛔ THE PLANTED POSITIVE: protobuf.dev 36.2 as it actually read, which cost a
// 34-minute macOS build and a link error naming lts_20260817.
func TestDepsplitReportsTheProtobufShape(t *testing.T) {
	got := depsplitResolve([]Split{
		{Recipe: "protobuf.dev", Project: "abseil.io", Link: "", Tool: "^20260526"},
	}, abseilPicker())
	if len(got) != 1 {
		t.Fatalf("the protobuf shape must be reported, got %d: %+v", len(got), got)
	}
	if got[0].LinkVer != "20260817.0" || got[0].ToolVer != "20260526.0" {
		t.Fatalf("want link 20260817.0 / tool 20260526.0, got %s / %s", got[0].LinkVer, got[0].ToolVer)
	}
}

// The negative control that matters most: two constraints whose TEXT differs
// and whose ANSWER does not. Reporting those would drown the real ones, and is
// the first way this could become useless while still "finding things".
func TestDepsplitIsQuietWhenTheVersionsAgree(t *testing.T) {
	for _, c := range []struct{ link, tool string }{
		{"", "*"},
		{"", ">=20250127"},
		{"^20260817", ">=20260817"},
	} {
		got := depsplitResolve([]Split{
			{Recipe: "r", Project: "abseil.io", Link: c.link, Tool: c.tool},
		}, abseilPicker())
		if len(got) != 0 {
			t.Errorf("link %q vs tool %q select the same version; must be quiet, got %+v", c.link, c.tool, got)
		}
	}
}

// A constraint nothing satisfies is a GAP — depgaps' population — not a
// split. Mixing the two makes either count meaningless alone.
func TestDepsplitDoesNotReportAGap(t *testing.T) {
	got := depsplitResolve([]Split{
		{Recipe: "r", Project: "abseil.io", Link: "", Tool: "^19990101"},
	}, abseilPicker())
	if len(got) != 0 {
		t.Fatalf("an unsatisfiable constraint is a gap, not a split; got %+v", got)
	}
}

// ⛔ A TAG IS NOT A PLATFORM, from the run that found it: openssl.org 1.1.1w
// is tagged and published for darwin/aarch64 ALONE. Without the platform
// check this reported github.com/awslabs/dynein as linking 1.1.1w on
// linux/x86-64 — a version no build there can obtain, so the "difference"
// was the tool's own. It took linux from 10 pairs to 7.
func TestDepsplitAsksWhetherTheVersionIsPublishedHere(t *testing.T) {
	p := fakePicker{
		tags:    map[string][]string{"openssl.org": {"4.0.2", "3.5.0", "1.1.1w"}},
		missing: map[string]bool{"openssl.org@1.1.1w": true},
	}
	if got := p.Pick("openssl.org", "^1.1"); got != "" {
		t.Errorf(`^1.1 has nothing published here; want "", got %q`, got)
	}
	// And it must not swallow the versions that ARE here.
	if got := p.Pick("openssl.org", ""); got != "4.0.2" {
		t.Errorf("want 4.0.2, got %q", got)
	}
	got := depsplitResolve([]Split{
		{Recipe: "github.com/awslabs/dynein", Project: "openssl.org", Link: "^1.1", Tool: ""},
	}, p)
	if len(got) != 0 {
		t.Errorf("an unobtainable link version is a gap, not a split; got %+v", got)
	}
}

// ⛔ NOT LEXICOGRAPHIC, and not re-derived here. bottle.VersionsFromTags
// applies the ordering, the glibc flavour filter and the 1.0/1.0.0/v1.0.0
// folding; re-deriving any of it locally is how pkgx's `request` reported
// nodejs 26.8.1 an hour after 26.12.1 shipped.
func TestNewestPublishedTakesTheNewest(t *testing.T) {
	p := abseilPicker()
	if got := p.Pick("abseil.io", ""); got != "20260817.0" {
		t.Errorf("unconstrained must give the newest, got %q", got)
	}
	if got := p.Pick("abseil.io", "^20250512"); got != "20250512.2.0" {
		t.Errorf("^20250512 must pin that LTS line, got %q", got)
	}
	if got := p.Pick("abseil.io", "^19990101"); got != "" {
		t.Errorf(`nothing satisfies ^19990101, want "", got %q`, got)
	}
}

const doubledRecipe = `distributable:
  url: https://example.com/v{{version}}.tgz
versions:
  - 36.2
dependencies:
  abseil.io: "*"
build:
  dependencies:
    abseil.io: ^20260526
  script:
    - make
`

const agreeingRecipe = `distributable:
  url: https://example.com/v{{version}}.tgz
versions:
  - 1.0
dependencies:
  abseil.io: ^20260526
build:
  dependencies:
    abseil.io: ^20260526
  script:
    - make
`

const oneListRecipe = `distributable:
  url: https://example.com/v{{version}}.tgz
versions:
  - 1.0
dependencies:
  zlib.net: "*"
build:
  dependencies:
    abseil.io: ^20260526
  script:
    - make
`

// The offline half. It must find the doubly-named project and, just as
// importantly, must not invent one: a project in only ONE list is the normal
// case and the overwhelming majority.
func TestDepsplitCandidatesFindOnlyTheDoubleNaming(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"protobuf.dev": doubledRecipe,
		"agreeing.org": agreeingRecipe,
		"onelist.org":  oneListRecipe,
	} {
		p := filepath.Join(dir, "projects", name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "package.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := depsplitCandidates(nil, dir, target.Target{Platform: "darwin", Arch: "aarch64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly the doubled recipe, got %d: %+v", len(got), got)
	}
	if got[0].Recipe != "protobuf.dev" || got[0].Project != "abseil.io" {
		t.Fatalf("got %+v", got[0])
	}
	if got[0].Link != "" || got[0].Tool != "^20260526" {
		t.Fatalf(`want link "" / tool ^20260526, got %q / %q`, got[0].Link, got[0].Tool)
	}
}

// ⛔ THE OVERRIDE IS APPLIED FIRST, and this is the reason: the fix for the
// one confirmed instance of this class is an override, so auditing the
// unpatched pantry would keep reporting a defect that is already repaired —
// and the operator would stop reading the list.
func TestDepsplitReadsTheOverriddenRecipe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "projects", "protobuf.dev")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "package.yml"), []byte(doubledRecipe), 0o644); err != nil {
		t.Fatal(err)
	}
	ov := t.TempDir()
	if err := os.WriteFile(filepath.Join(ov, "protobuf.dev.hcl"), []byte(
		`project = "protobuf.dev"
why     = "runtime abseil must match the build line"
edits = [
  {
    path = "dependencies[\"abseil.io\"]"
    set  = "^20260526"
  },
]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	tgt := target.Target{Platform: "darwin", Arch: "aarch64"}
	// Without the override it is a candidate…
	bare, err := depsplitCandidates(nil, dir, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(bare) != 1 {
		t.Fatalf("baseline must see the split, got %+v", bare)
	}
	// …and with it, the two lists agree, so there is nothing to report.
	set, err := logical.LoadDir(ov)
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := depsplitCandidates(set, dir, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 0 {
		t.Fatalf("the override makes the lists agree; want nothing, got %+v", fixed)
	}
}

func TestReportSplitsNamesBothVersionsAndSaysTheyAreCandidates(t *testing.T) {
	var b strings.Builder
	reportSplits(&b, []Split{{
		Recipe: "protobuf.dev", Project: "abseil.io",
		Link: "", Tool: "^20260526",
		LinkVer: "20260817.0", ToolVer: "20260526.0",
	}}, "darwin/aarch64")
	out := b.String()
	// The two versions are the whole point: a report naming the recipe and
	// not the versions sends a reader back to the build log.
	for _, want := range []string{
		"protobuf.dev", "abseil.io", "20260817.0", "20260526.0", "darwin/aarch64",
		"CANDIDATE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report omits %q:\n%s", want, out)
		}
	}
}

// ⛔ A NAMED OVERRIDES DIRECTORY THAT IS NOT THERE IS AN ERROR, because
// logical.LoadDir tolerates it and returns an empty set — and the audit would
// then run against the UNPATCHED pantry and report the one instance of this
// class that an override already fixes.
func TestDepsplitRefusesAnUnreadableOverrideDir(t *testing.T) {
	code, _, errb := run2(t, "depsplit", "--overrides", "/definitely/not/here", "--pantry", t.TempDir())
	if code == 0 {
		t.Fatalf("want a non-zero exit, got %d: %s", code, errb)
	}
	if !strings.Contains(errb, "UNPATCHED") {
		t.Errorf("the refusal must say what it is protecting against: %s", errb)
	}
}

func TestDepsplitRejectsBadFlags(t *testing.T) {
	if code, _, _ := run2(t, "depsplit", "--nonsense"); code != 2 {
		t.Fatalf("want 2, got %d", code)
	}
}

func TestDepsplitRefusesAnUnparsableOverride(t *testing.T) {
	ov := t.TempDir()
	if err := os.WriteFile(filepath.Join(ov, "bad.hcl"), []byte("project = \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb := run2(t, "depsplit", "--overrides", ov, "--pantry", t.TempDir())
	if code != 2 {
		t.Fatalf("want 2, got %d: %s", code, errb)
	}
}

// splitRegistry drives the resolution pass without a network.
type splitRegistry struct {
	tags    map[string][]string
	plats   map[string][]string // "project@tag" -> platforms
	tagsErr error
	hasErr  error
}

func (f splitRegistry) ListTags(project string) ([]string, error) {
	if f.tagsErr != nil {
		return nil, f.tagsErr
	}
	return f.tags[project], nil
}

func (f splitRegistry) HasPlatform(project, version, osn, arch string) (bool, error) {
	if f.hasErr != nil {
		return false, f.hasErr
	}
	for _, p := range f.plats[project+"@"+version] {
		if p == osn+"/"+arch {
			return true, nil
		}
	}
	return len(f.plats) == 0, nil // no table means "published everywhere"
}

func withRegistry(t *testing.T, r depsplitRegistry, err error) {
	t.Helper()
	prev := newDepsplitRegistry
	newDepsplitRegistry = func(string) (depsplitRegistry, error) { return r, err }
	t.Cleanup(func() { newDepsplitRegistry = prev })
}

func writePantry(t *testing.T, bodies map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range bodies {
		p := filepath.Join(dir, "projects", name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "package.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The whole command, end to end, on the shape that cost a 34-minute build.
func TestDepsplitRunReportsTheSplit(t *testing.T) {
	withRegistry(t, splitRegistry{
		tags: map[string][]string{"abseil.io": {"20260817.0", "20260526.0"}},
	}, nil)
	dir := writePantry(t, map[string]string{"protobuf.dev": doubledRecipe})

	code, out, _ := run2(t, "depsplit", "--overrides", "", "--pantry", dir, "--platform", "darwin/aarch64")
	if code != 0 {
		t.Fatalf("want 0, got %d: %s", code, out)
	}
	for _, want := range []string{"protobuf.dev", "abseil.io", "20260817.0", "20260526.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output omits %q:\n%s", want, out)
		}
	}
	// --fail is what a CI gate uses.
	code, _, _ = run2(t, "depsplit", "--overrides", "", "--pantry", dir, "--platform", "darwin/aarch64", "--fail")
	if code != 1 {
		t.Fatalf("--fail must exit 1 when something is found, got %d", code)
	}
}

// Nothing found is exit 0 even with --fail, or the gate could never go green.
func TestDepsplitRunIsGreenWhenThereIsNothing(t *testing.T) {
	withRegistry(t, splitRegistry{}, nil)
	dir := writePantry(t, map[string]string{"agreeing.org": agreeingRecipe})
	code, out, _ := run2(t, "depsplit", "--overrides", "", "--pantry", dir, "--fail")
	if code != 0 {
		t.Fatalf("want 0, got %d: %s", code, out)
	}
}

func TestDepsplitRunReportsARegistryItCannotReach(t *testing.T) {
	withRegistry(t, nil, errors.New("no registry"))
	dir := writePantry(t, map[string]string{"protobuf.dev": doubledRecipe})
	code, _, errb := run2(t, "depsplit", "--overrides", "", "--pantry", dir)
	if code != 1 {
		t.Fatalf("want 1, got %d: %s", code, errb)
	}
}

func TestDepsplitRunReportsAWalkThatFailed(t *testing.T) {
	withRegistry(t, splitRegistry{}, nil)
	prev := filepathWalkDir
	filepathWalkDir = func(string, fs.WalkDirFunc) error { return errors.New("tree gone") }
	defer restoreWalk(prev)
	code, _, errb := run2(t, "depsplit", "--overrides", "", "--pantry", t.TempDir())
	if code != 1 {
		t.Fatalf("want 1, got %d: %s", code, errb)
	}
}

// ⛔ A TAG LIST WE COULD NOT READ IS SAID, and yields no version rather than
// a wrong one: the pair then drops out as a gap instead of being reported as
// a difference that is really a failed read.
func TestPickerSaysWhenItCannotListTags(t *testing.T) {
	var warn strings.Builder
	p := &registryPicker{
		c: splitRegistry{tagsErr: errors.New("boom")}, osn: "darwin", arch: "aarch64",
		tags: map[string][]string{}, has: map[string]bool{}, warn: &warn,
	}
	if got := p.Pick("abseil.io", ""); got != "" {
		t.Errorf(`want "", got %q`, got)
	}
	if !strings.Contains(warn.String(), "boom") {
		t.Errorf("the failure was not reported: %s", warn.String())
	}
}

// ⛔ AN INDEX WE COULD NOT READ IS NOT AN ABSENCE. Saying "not published"
// would walk on to an older version and report a difference that is an
// artefact of connectivity.
func TestPickerTreatsAnUnreadableIndexAsPublished(t *testing.T) {
	var warn strings.Builder
	p := &registryPicker{
		c:    splitRegistry{tags: map[string][]string{"a.org": {"2.0", "1.0"}}, hasErr: errors.New("timeout")},
		osn:  "darwin",
		arch: "aarch64",
		tags: map[string][]string{}, has: map[string]bool{}, warn: &warn,
	}
	if got := p.Pick("a.org", ""); got != "2.0" {
		t.Errorf("want the newest treated as published, got %q", got)
	}
	if !strings.Contains(warn.String(), "treated as published") {
		t.Errorf("the assumption was not stated: %s", warn.String())
	}
	// Cached: a second ask must not re-report it.
	before := warn.Len()
	p.Pick("a.org", "")
	if warn.Len() != before {
		t.Errorf("the per-version answer is not cached: %s", warn.String())
	}
}

// The platform filter, through the picker rather than the helper.
func TestPickerSkipsAVersionNotPublishedHere(t *testing.T) {
	p := &registryPicker{
		c: splitRegistry{
			tags:  map[string][]string{"a.org": {"2.0", "1.0"}},
			plats: map[string][]string{"a.org@1.0": {"darwin/aarch64"}, "a.org@2.0": {"linux/x86-64"}},
		},
		osn: "darwin", arch: "aarch64",
		tags: map[string][]string{}, has: map[string]bool{}, warn: io.Discard,
	}
	if got := p.Pick("a.org", ""); got != "1.0" {
		t.Errorf("want 1.0, the newest published HERE, got %q", got)
	}
}

// The overrides directory that IS there, read end to end through the command.
func TestDepsplitRunReadsAnOverridesDirectory(t *testing.T) {
	withRegistry(t, splitRegistry{
		tags: map[string][]string{"abseil.io": {"20260817.0", "20260526.0"}},
	}, nil)
	dir := writePantry(t, map[string]string{"protobuf.dev": doubledRecipe})
	ov := t.TempDir()
	if err := os.WriteFile(filepath.Join(ov, "protobuf.dev.hcl"), []byte(
		`project = "protobuf.dev"
why     = "runtime abseil must match the build line"
edits = [
  {
    path = "dependencies[\"abseil.io\"]"
    set  = "^20260526"
  },
]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run2(t, "depsplit", "--overrides", ov, "--pantry", dir, "--platform", "darwin/aarch64", "--fail")
	if code != 0 {
		t.Fatalf("the override makes the lists agree; want 0, got %d:\n%s", code, out)
	}
	if strings.Contains(out, "protobuf.dev") {
		t.Errorf("a repaired recipe must not be reported:\n%s", out)
	}
}

// A recipe this cannot parse is the schema gate's business, not a split.
func TestDepsplitSkipsWhatItCannotParse(t *testing.T) {
	dir := writePantry(t, map[string]string{"broken.org": "{{{ not yaml"})
	got, err := depsplitCandidates(nil, dir, target.Target{Platform: "darwin", Arch: "aarch64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want nothing from an unparsable recipe, got %+v", got)
	}
}

// A recipe that says it does not target this platform is not a split on it —
// the same correction depgaps needed when four linux-only projects ranked as
// darwin gaps.
func TestDepsplitSkipsARecipeThatIsNotForThisPlatform(t *testing.T) {
	const linuxOnly = `distributable:
  url: https://example.com/v{{version}}.tgz
versions:
  - 1.0
platforms:
  - linux
dependencies:
  abseil.io: "*"
build:
  dependencies:
    abseil.io: ^20260526
  script:
    - make
`
	dir := writePantry(t, map[string]string{"linuxonly.org": linuxOnly})
	got, err := depsplitCandidates(nil, dir, target.Target{Platform: "darwin", Arch: "aarch64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a linux-only recipe is not a darwin split, got %+v", got)
	}
}

// A path the walk hands back that is not under the root cannot be made into a
// project name, and is skipped rather than guessed at.
func TestDepsplitSkipsAPathOutsideTheRoot(t *testing.T) {
	prev := filepathWalkDir
	filepathWalkDir = func(_ string, fn fs.WalkDirFunc) error {
		return fn(string(filepath.Separator)+"elsewhere"+string(filepath.Separator)+"package.yml", fakeDirEntry{name: "package.yml"}, nil)
	}
	defer restoreWalk(prev)
	got, err := depsplitCandidates(nil, "relative-root", target.Target{Platform: "linux", Arch: "x86-64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want nothing, got %+v", got)
	}
}

type fakeDirEntry struct{ name string }

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return false }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// The order is stable so a diff between two runs reads: by recipe, then by
// project within one recipe.
func TestReportSplitsOrdersByRecipeThenProject(t *testing.T) {
	var b strings.Builder
	reportSplits(&b, []Split{
		{Recipe: "zeta.org", Project: "a.org", LinkVer: "2", ToolVer: "1"},
		{Recipe: "alpha.org", Project: "z.org", LinkVer: "2", ToolVer: "1"},
		{Recipe: "alpha.org", Project: "b.org", LinkVer: "2", ToolVer: "1"},
	}, "linux/x86-64")
	out := b.String()
	alphaB, alphaZ, zeta := strings.Index(out, "b.org"), strings.Index(out, "z.org"), strings.Index(out, "zeta.org")
	if !(alphaB < alphaZ && alphaZ < zeta) {
		t.Fatalf("want alpha.org/b.org, alpha.org/z.org, zeta.org in that order:\n%s", out)
	}
}

// The seam's own body: constructing a client is local, so this costs no
// network and keeps the default path from being the one line nobody runs.
func TestNewDepsplitRegistryBuildsAClient(t *testing.T) {
	c, err := newDepsplitRegistry(bottle.DistBase)
	if err != nil {
		t.Fatalf("constructing a client for the default dist: %v", err)
	}
	if c == nil {
		t.Fatal("no client and no error")
	}
}

func TestQuoteConstraintSpellsTheUnconstrainedCase(t *testing.T) {
	if got := quoteConstraint(""); got != `"*"` {
		t.Errorf(`want "*", got %s`, got)
	}
	if got := quoteConstraint("^1"); got != `"^1"` {
		t.Errorf(`want "^1", got %s`, got)
	}
}
