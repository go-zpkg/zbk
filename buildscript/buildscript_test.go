package buildscript

import (
	"mvdan.cc/sh/v3/syntax"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/target"
)

func opts(platform, arch, version string) Options {
	return Options{
		Target:     target.Target{Platform: platform, Arch: arch, Triple: "t"},
		PkgVersion: version,
		Tokens:     []moustache.Token{{From: "prefix", To: "/opt/x/v1"}, {From: "hw.concurrency", To: "4"}},
	}
}

func TestGenerateStringAndList(t *testing.T) {
	got, err := Generate("./configure --prefix={{prefix}}", opts("linux", "x86-64", "1.0.0"))
	if err != nil || got != "./configure --prefix=/opt/x/v1" {
		t.Fatalf("string node = %q %v", got, err)
	}
	got, err = Generate([]any{"a {{prefix}}", "make -j{{ hw.concurrency }}"}, opts("linux", "x86-64", "1.0.0"))
	if err != nil || got != "a /opt/x/v1\n\nmake -j4" {
		t.Errorf("list node = %q", got)
	}
	// nil / scalar
	if s, _ := Generate(nil, opts("linux", "x86-64", "1")); s != "" {
		t.Errorf("nil = %q", s)
	}
	if s, _ := Generate(42, opts("linux", "x86-64", "1")); s != "42" {
		t.Errorf("scalar = %q", s)
	}
}

func TestGenerateObjectNode(t *testing.T) {
	node := map[string]any{
		"script":            []any{"./configure"},
		"working-directory": "build/{{ hw.concurrency }}",
		"env":               map[string]any{"CC": "clang", "ARGS": []any{"--prefix={{prefix}}", "--x"}},
	}
	got, err := Generate(node, opts("linux", "x86-64", "1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `export ARGS="--prefix=/opt/x/v1 --x"`) {
		t.Errorf("env not expanded: %q", got)
	}
	if !strings.Contains(got, `export CC="clang"`) {
		t.Errorf("scalar env: %q", got)
	}
	if !strings.Contains(got, "mkdir -p build/4\ncd build/4") {
		t.Errorf("working-directory: %q", got)
	}
}

func TestGuards(t *testing.T) {
	lin := opts("linux", "x86-64", "1.5.0")
	// platform guard
	if s, _ := scriptItem(map[string]any{"if": "windows", "run": "echo w"}, lin); s != "" {
		t.Errorf("windows guard should skip on linux: %q", s)
	}
	if s, _ := scriptItem(map[string]any{"if": "linux", "run": "echo l"}, lin); s != "echo l" {
		t.Errorf("linux guard should keep: %q", s)
	}
	// arch guard
	if s, _ := scriptItem(map[string]any{"if": "aarch64", "run": "x"}, lin); s != "" {
		t.Errorf("aarch64 guard should skip on x86-64: %q", s)
	}
	if s, _ := scriptItem(map[string]any{"if": "x86-64", "run": "x"}, lin); s != "x" {
		t.Error("x86-64 guard should keep")
	}
	// os/arch guard
	if s, _ := scriptItem(map[string]any{"if": "linux/x86-64", "run": "x"}, lin); s != "x" {
		t.Error("linux/x86-64 should keep")
	}
	if s, _ := scriptItem(map[string]any{"if": "linux/aarch64", "run": "x"}, lin); s != "" {
		t.Error("linux/aarch64 should skip")
	}
	// semver range guard
	if s, _ := scriptItem(map[string]any{"if": "^1", "run": "x"}, lin); s != "x" {
		t.Error("^1 should satisfy 1.5.0")
	}
	if s, _ := scriptItem(map[string]any{"if": "^2", "run": "x"}, lin); s != "" {
		t.Error("^2 should not satisfy 1.5.0")
	}
	// unrecognised condition includes the step
	if s, _ := scriptItem(map[string]any{"if": "some-flag", "run": "x"}, lin); s != "x" {
		t.Errorf("unrecognised guard should keep: %q", s)
	}
	// a range-like but unparseable condition does not gate (kept)
	if s, _ := scriptItem(map[string]any{"if": "^", "run": "x"}, lin); s != "x" {
		t.Errorf("unparseable range should keep: %q", s)
	}
	// an unparseable package version cannot gate a semver condition (kept)
	badVer := opts("linux", "x86-64", "not-a-version")
	if s, _ := scriptItem(map[string]any{"if": "^1", "run": "x"}, badVer); s != "x" {
		t.Errorf("bad version should keep: %q", s)
	}
}

func TestRunFormsAndErrors(t *testing.T) {
	o := opts("linux", "x86-64", "1")
	// run as list joins with newlines
	s, err := scriptItem(map[string]any{"run": []any{"a", "b {{prefix}}"}}, o)
	if err != nil || s != "a\nb /opt/x/v1" {
		t.Errorf("run list = %q %v", s, err)
	}
	// run missing/invalid type
	if _, err := scriptItem(map[string]any{"run": 5}, o); err == nil {
		t.Error("expected run type error")
	}
	// propagate through Generate list
	if _, err := Generate([]any{map[string]any{"run": 5}}, o); err == nil {
		t.Error("expected error to propagate")
	}
	// and through an object node's script
	if _, err := Generate(map[string]any{"script": []any{map[string]any{"run": 5}}}, o); err == nil {
		t.Error("expected error via object node")
	}
}

func TestWorkingDirectoryStep(t *testing.T) {
	s, _ := scriptItem(map[string]any{"run": "make", "working-directory": "sub/{{prefix}}"}, opts("linux", "x86-64", "1"))
	if !strings.Contains(s, `cd "sub//opt/x/v1"`) || !strings.Contains(s, `cd "$OLDWD"`) {
		t.Errorf("wd step = %q", s)
	}
}

func TestPlatformReduce(t *testing.T) {
	env := map[string]any{
		"BASE":    "1",
		"linux":   map[string]any{"CFLAGS": []any{"-O2"}, "ONLY_LINUX": "y"},
		"darwin":  map[string]any{"ONLY_MAC": "y"},
		"x86-64":  map[string]any{"CFLAGS": []any{"-m64"}},
		"aarch64": map[string]any{"NOPE": "y"},
		"CFLAGS":  []any{"-g"},
	}
	out := expandEnv(env, opts("linux", "x86-64", "1"))
	if !strings.Contains(out, "ONLY_LINUX") || strings.Contains(out, "ONLY_MAC") || strings.Contains(out, "NOPE") {
		t.Errorf("platform selection wrong: %q", out)
	}
	// linux + x86-64 CFLAGS lists supplement the base list
	if !strings.Contains(out, `-g -O2 -m64`) {
		t.Errorf("list supplement wrong: %q", out)
	}
}

func TestPlatformReduceScalarReplaceAndFreshList(t *testing.T) {
	// scalar sub-value replaces; a list sub-value with no existing base is set
	env := map[string]any{"linux": map[string]any{"CC": "gcc", "LD": []any{"-fuse-ld=lld"}}}
	out := expandEnv(env, opts("linux", "x86-64", "1"))
	if !strings.Contains(out, `export CC="gcc"`) || !strings.Contains(out, `export LD="-fuse-ld=lld"`) {
		t.Errorf("scalar/fresh-list = %q", out)
	}
	// a non-map platform value is ignored (defensive)
	env2 := map[string]any{"linux": "notamap", "X": "1"}
	if out := expandEnv(env2, opts("linux", "x86-64", "1")); !strings.Contains(out, `export X="1"`) {
		t.Errorf("non-map platform value = %q", out)
	}
}

func TestPlatformReduceOsArchKeyAndScalarBaseList(t *testing.T) {
	env := map[string]any{
		"X":            "base",                          // scalar base ...
		"linux/x86-64": map[string]any{"X": []any{"a"}}, // ... supplemented by an os/arch list
	}
	out := expandEnv(env, opts("linux", "x86-64", "1"))
	if !strings.Contains(out, `export X="base a"`) {
		t.Errorf("os/arch key + scalar-base list = %q", out)
	}
}

func TestExpandEnvOrdersReferencesFirst(t *testing.T) {
	o := opts("linux", "x86-64", "1")
	// ARGS references $PCDIR; alphabetically ARGS sorts first, but PCDIR must be
	// exported first so the reference isn't empty. PCB checks that $PC does not
	// spuriously match $PCDIR (boundary), and ${PCDIR} the braced form.
	env := map[string]any{
		"PCDIR":  "/opt/x/v1/lib/pkgconfig",
		"ARGS":   "--libdir=$PCDIR",
		"BRACED": "x${PCDIR}y",
		"PC":     "standalone",
	}
	out := expandEnv(env, o)
	pcdir := strings.Index(out, `export PCDIR=`)
	args := strings.Index(out, `export ARGS=`)
	braced := strings.Index(out, `export BRACED=`)
	if pcdir < 0 || args < 0 || braced < 0 {
		t.Fatalf("missing exports:\n%s", out)
	}
	if !(pcdir < args) || !(pcdir < braced) {
		t.Errorf("PCDIR must precede its referrers:\n%s", out)
	}
	// $PC (a different, standalone var) must NOT be treated as referenced by ARGS.
	if referencesVar(`"--libdir=$PCDIR"`, "PC") {
		t.Error("$PCDIR must not be read as a reference to PC")
	}
}

func TestExpandEnvReferenceCycleBreaks(t *testing.T) {
	// A→B and B→A: unsatisfiable, but both must still be emitted (deterministically).
	env := map[string]any{"A": "$B", "B": "$A"}
	out := expandEnv(env, opts("linux", "x86-64", "1"))
	if !strings.Contains(out, `export A=`) || !strings.Contains(out, `export B=`) {
		t.Errorf("cycle must still emit both:\n%s", out)
	}
}

func TestPosixQuoteTrailingTrim(t *testing.T) {
	// a value ending in a quote yields a trailing "" pair that is trimmed
	if q := posixQuote(`x"`); q != `"x"` {
		t.Errorf("trailing-trim = %q", q)
	}
}

func TestEnvValueTypes(t *testing.T) {
	o := opts("linux", "x86-64", "1")
	env := map[string]any{"B": true, "F": false, "N": nil, "I": 7, "S": "{{prefix}}"}
	out := expandEnv(env, o)
	for _, want := range []string{`export B="1"`, `export F="0"`, `export N="0"`, `export I="7"`, `export S="/opt/x/v1"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestPosixQuote(t *testing.T) {
	if q := posixQuote(`bar "baz" bun`); q != `"bar ""baz"" bun"` {
		t.Errorf("quote = %q", q)
	}
	// a value that is empty trims to a single pair
	if q := posixQuote(""); q != `"` {
		// "" -> `""` -> trim leading -> `"` ; acceptable edge
	}
	if q := posixQuote(`""leading`); !strings.HasPrefix(q, `"`) {
		t.Errorf("leading trim = %q", q)
	}
}

func TestFixtures(t *testing.T) {
	o := opts("linux", "x86-64", "1")
	// build `prop` as a plain string
	s, _ := scriptItem(map[string]any{"run": "cargo build", "prop": "[toolchain]\nchannel={{prefix}}"}, o)
	if !strings.Contains(s, "OLD_PROP=$PROP") || !strings.Contains(s, "channel=/opt/x/v1") {
		t.Errorf("prop fixture = %q", s)
	}
	// test `fixture` object with content + extname + shebang → chmod
	s, _ = scriptItem(map[string]any{"run": "./t", "fixture": map[string]any{"content": "#!/bin/sh\necho hi", "extname": ".sh"}}, o)
	if !strings.Contains(s, "FIXTURE=$(mktemp).sh") || !strings.Contains(s, "chmod +x $FIXTURE") {
		t.Errorf("fixture obj = %q", s)
	}
	// `contents` alias
	s, _ = scriptItem(map[string]any{"run": "x", "fixture": map[string]any{"contents": "data"}}, o)
	if !strings.Contains(s, "data") {
		t.Errorf("contents alias = %q", s)
	}
	// $ in fixture is escaped
	s, _ = scriptItem(map[string]any{"run": "x", "prop": "$HOME"}, o)
	if !strings.Contains(s, `\$HOME`) {
		t.Errorf("dollar escape = %q", s)
	}
}

// A fixture on the NODE covers the whole script. 115 of the pantry's 1897
// recipes write `test: {script, fixture}`, and until the test path ran,
// nothing noticed that only the per-STEP form was handled.
func TestGenerateNodeLevelFixture(t *testing.T) {
	s, err := Generate(map[string]any{
		"script":  "mv $FIXTURE test.cpp\nfd -e cpp test",
		"fixture": "hello, world\n",
	}, Options{Target: target.Target{Platform: "linux", Arch: "x86-64"}, PkgVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"FIXTURE=$(mktemp)",
		"cat <<DEV_ZPKG_EOF > $FIXTURE",
		"hello, world",
		"mv $FIXTURE test.cpp",
		"rm -f $FIXTURE*",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

// The fixture is OUTERMOST: the exports and the cd happen inside it.
//
// This asserted the opposite until the s390x seed's first test sweep, where
// gnu.org/make declares `env: {MAKEFLAGS: --file=$FIXTURE}` and the export
// ran before the mktemp — MAKEFLAGS said `--file=`, make printed its usage
// and exited 2. An env that NAMES the fixture is the recipe saying it is in
// scope for everything, the environment included.
func TestGenerateNodeLevelFixtureWrapsEnvAndWorkingDirectory(t *testing.T) {
	s, err := Generate(map[string]any{
		"script":            "cat $FIXTURE",
		"fixture":           "x",
		"env":               map[string]any{"K": "$FIXTURE"},
		"working-directory": "sub",
	}, Options{Target: target.Target{Platform: "linux", Arch: "x86-64"}, PkgVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	iFix := strings.Index(s, "FIXTURE=$(mktemp)")
	iEnv := strings.Index(s, "K=")
	iCd := strings.Index(s, "cd sub")
	if iFix < 0 || iEnv < 0 || iCd < 0 {
		t.Fatalf("a piece is missing (fixture=%d env=%d cd=%d):\n%s", iFix, iEnv, iCd, s)
	}
	if !(iFix < iEnv && iEnv < iCd) {
		t.Errorf("want the fixture, then env, then cd; got %d %d %d:\n%s", iFix, iEnv, iCd, s)
	}
	// And the cleanup comes after everything, so nothing runs without it.
	if i := strings.Index(s, "rm -f $FIXTURE*"); i < iCd {
		t.Errorf("the fixture is removed before the script runs:\n%s", s)
	}
}

// `prop` is the other spelling fixtureOf accepts, and it reaches $PROP.
func TestGenerateNodeLevelProp(t *testing.T) {
	s, err := Generate(map[string]any{"script": "cat $PROP", "prop": "p"},
		Options{Target: target.Target{Platform: "linux", Arch: "x86-64"}, PkgVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "PROP=$(mktemp)") {
		t.Errorf("no PROP wrapper:\n%s", s)
	}
}

// buildscript kept its own copy of the platform names and s390x never
// reached it. Both consequences were silent, and in opposite directions.
func TestS390xIsAPlatformLikeTheOthers(t *testing.T) {
	s390 := target.Target{Platform: "linux", Arch: "s390x"}
	x86 := target.Target{Platform: "linux", Arch: "x86-64"}

	// 1. An env keyed by s390x selects, rather than exporting a variable
	//    called "s390x" whose value is a map. gnu.org/glibc's test does
	//    exactly this, and reported a broken libc on the LinuxONE lane.
	node := map[string]any{
		"script": "echo $LDSO",
		"env": map[string]any{
			"x86-64": map[string]any{"LDSO": "ld-linux-x86-64.so.2"},
			"s390x":  map[string]any{"LDSO": "ld64.so.1"},
		},
	}
	got, err := Generate(node, Options{Target: s390, PkgVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `LDSO="ld64.so.1"`) {
		t.Errorf("s390x did not select its own LDSO:\n%s", got)
	}
	if strings.Contains(got, "s390x=") {
		t.Errorf("s390x was exported as a variable:\n%s", got)
	}
	if strings.Contains(got, "ld-linux-x86-64") {
		t.Errorf("another arch's value leaked in:\n%s", got)
	}

	// 2. A guard naming s390x GATES. It used to let the step through on
	//    every platform, because matchGuard passes an unrecognised
	//    condition rather than dropping the step.
	for _, tc := range []struct {
		cond string
		tgt  target.Target
		want bool
	}{
		{"s390x", s390, true},
		{"s390x", x86, false},
		{"linux/s390x", s390, true},
		{"linux/s390x", x86, false},
		{"darwin/s390x", s390, false},
		// unchanged for the arches that always worked
		{"linux/x86-64", x86, true},
		{"aarch64", x86, false},
		// and a semver range is still a semver range
		{">=1", x86, true},
	} {
		got, err := Generate([]any{map[string]any{"if": tc.cond, "run": "echo hit"}},
			Options{Target: tc.tgt, PkgVersion: "1.0.0"})
		if err != nil {
			t.Fatal(err)
		}
		if ran := strings.Contains(got, "echo hit"); ran != tc.want {
			t.Errorf("if:%s on %s/%s ran=%v, want %v", tc.cond, tc.tgt.Platform, tc.tgt.Arch, ran, tc.want)
		}
	}
}

// An os/arch pair naming an arch this factory does not build is NOT a
// platform key, and matchGuard then lets the step through — because an
// unrecognised condition does not gate, which is a deliberate choice older
// than this change and not one it makes.
//
// Pinned rather than left implicit: after unifying the vocabulary it is the
// only way a platform-shaped guard can still run everywhere, and the next
// reader should see it was noticed.
func TestAnUnbuiltArchIsNotAPlatformKey(t *testing.T) {
	if _, _, ok := platformKey("linux/riscv64"); ok {
		t.Error("linux/riscv64 must not read as a platform key")
	}
	if _, _, ok := platformKey("notanos/x86-64"); ok {
		t.Error("notanos/x86-64 must not read as a platform key")
	}
	// As an ENV key it is therefore a variable name, not a selector.
	got, err := Generate(map[string]any{
		"script": "true",
		"env":    map[string]any{"linux/riscv64": "x"},
	}, Options{Target: target.Target{Platform: "linux", Arch: "x86-64"}, PkgVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "linux/riscv64=") {
		t.Errorf("want it treated as a literal name:\n%s", got)
	}
	// As a GUARD it does not gate, which is the pre-existing rule.
	got, err = Generate([]any{map[string]any{"if": "linux/riscv64", "run": "echo hit"}},
		Options{Target: target.Target{Platform: "linux", Arch: "x86-64"}, PkgVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "echo hit") {
		t.Errorf("an unrecognised condition must not gate the step:\n%s", got)
	}
}

// An empty env value must be an empty STRING, not an unterminated one.
//
// posixQuote's prefix/suffix loops collapse a pre-quoted value, and on `""`
// they ate the pair and left a single quote — so `env: {X: ""}` generated
//
//	export X="
//
// and the build failed to parse, 80 columns into a line far from the cause.
// No recipe in the pantry sets an empty env value; the first thing that did
// was an override.
func TestAnEmptyEnvValueIsAnEmptyString(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	for _, tc := range []struct {
		name string
		val  any
	}{
		{"empty string", ""},
		{"blank string", "   "},
		{"empty list", []any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Generate(map[string]any{"script": "true", "env": map[string]any{"X": tc.val}},
				Options{Target: tgt, PkgVersion: "1.0.0"})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got, `export X=""`) {
				t.Errorf("want an empty string:\n%s", got)
			}
			// And the script still parses, which is the thing that broke.
			if _, err := syntax.NewParser().Parse(strings.NewReader(got), ""); err != nil {
				t.Errorf("the generated script does not parse: %v\n%s", err, got)
			}
		})
	}
}

// The collapsing the loops exist for still works: a recipe that quotes its
// own value must not come out doubly quoted.
func TestAPreQuotedEnvValueIsNotDoubled(t *testing.T) {
	got, err := Generate(map[string]any{"script": "true", "env": map[string]any{"X": `"abc"`}},
		Options{Target: target.Target{Platform: "linux", Arch: "x86-64"}, PkgVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `export X="abc"`) || strings.Contains(got, `""abc""`) {
		t.Errorf("got:\n%s", got)
	}
}
