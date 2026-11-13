package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestScriptCommandsFindsWhatARegexMisses.
//
// The first attempt at this question used a regex. It reported `grep` 1231
// times — counting the word in prose — and listed `int`, `return` and `elif`
// as commands. A parser finds a name wherever the shell would: behind a pipe,
// inside a substitution, after a conditional.
func TestScriptCommandsFindsWhatARegexMisses(t *testing.T) {
	got := scriptCommands(`
		VER=$(echo "$V" | tr -- . -)
		curl -fsSL "https://x/$VER" | tar xz
		if which ninja; then ninja install; fi
	`)
	idx := map[string]bool{}
	for _, c := range got {
		idx[c] = true
	}
	for _, want := range []string{"tr", "curl", "tar", "which", "ninja"} {
		if !idx[want] {
			t.Errorf("missing %q from %v", want, got)
		}
	}
}

// A shell builtin is answered by the shell, so nothing has to ship it — and
// mvdan.cc/sh implements them in Go, which is why a build can run with no
// /bin/sh at all.
func TestScriptCommandsSkipsBuiltins(t *testing.T) {
	for _, c := range scriptCommands("cd /tmp && echo hi && export A=1 && test -f x") {
		if shellBuiltin[c] {
			t.Errorf("%q is a builtin and must not be reported", c)
		}
	}
}

// A function the script DEFINES is not a dependency. Reporting it would put a
// name in the bootstrap surface that no image could ever satisfy.
func TestScriptCommandsSkipsItsOwnFunctions(t *testing.T) {
	got := scriptCommands("build_one() { gcc -c \"$1\"; }\nbuild_one a.c\nbuild_one b.c\n")
	for _, c := range got {
		if c == "build_one" {
			t.Errorf("a locally defined function must not be a dependency: %v", got)
		}
	}
	if len(got) != 1 || got[0] != "gcc" {
		t.Errorf("want just gcc, got %v", got)
	}
}

// A name that is not a literal cannot be reported honestly. `$TOOL --version`
// names something, and guessing which is worse than omitting it — a bootstrap
// surface that invents entries is not a surface.
func TestScriptCommandsOmitsWhatItCannotName(t *testing.T) {
	got := scriptCommands("$TOOL --version\n/usr/bin/strip x\nA=1 make\n")
	for _, c := range got {
		if strings.ContainsAny(c, "$/=") {
			t.Errorf("%q is not a bare command name: %v", c, got)
		}
	}
}

// An unparseable script yields nothing rather than a panic or a guess: a
// recipe bk cannot parse is one bk cannot run either, and that is somebody
// else's error to report.
func TestScriptCommandsOnGarbage(t *testing.T) {
	if got := scriptCommands("if [ -f x"); len(got) != 0 {
		t.Errorf("want nothing from an unparseable script, got %v", got)
	}
}

// End to end, with the two cases that prompted this: ca-certs shells out to
// `tr` to turn dots into dashes, and zstd needs cmake — the command that was
// not on the host, and produced `exit status 127` with nothing naming it.
func TestRunToolsOnARecipe(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "certs.org",
		"build:\n  script: |\n    V=$(echo 1.2.3 | tr -- . -)\n    curl -k \"https://x/$V.pem\"\n")
	var out, errb bytes.Buffer
	if code := runTools([]string{"--pantry", p, "--platform", "linux/x86-64", "certs.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{"tr", "curl", "1 project"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in:\n%s", want, got)
		}
	}
}

// Naming no projects and not asking for --all is a usage error, not an empty
// report: "0 commands" would read as an answer.
func TestRunToolsNeedsSomethingToLookAt(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runTools([]string{"--pantry", t.TempDir()}, &out, &errb); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "--all") {
		t.Errorf("the refusal must say how: %q", errb.String())
	}
}

// --all walks for the recipe FILE, so an HCL recipe is not invisible the way
// it was to depgaps.
func TestRunToolsAllFindsAnHCLRecipe(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "yml.org", "build:\n  script: make install\n")
	writeClosureRecipeNamed(t, p, "hcl.org", "package.hcl", "build { script = [\"ninja install\"] }\n")
	var out, errb bytes.Buffer
	if code := runTools([]string{"--pantry", p, "--platform", "linux/x86-64", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "ninja") {
		t.Errorf("an HCL recipe must be walked too:\n%s", got)
	}
	if !strings.Contains(got, "2 project") {
		t.Errorf("both projects must be counted:\n%s", got)
	}
}

// TestRunToolsByProject: the count says how MANY need a command; --by-project
// says which. Two commands at the same count also exercise the tie-break, so
// the order is the same on every run rather than the map's.
func TestRunToolsByProject(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "one.org", "build:\n  script: |\n    sed -i s/a/b/ x\n    awk '{print}' y\n")
	writeClosureRecipe(t, p, "two.org", "build:\n  script: |\n    sed -i s/c/d/ z\n")
	var out, errb bytes.Buffer
	if code := runTools([]string{"--pantry", p, "--platform", "linux/x86-64", "--by-project",
		"one.org", "two.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "one.org") || !strings.Contains(got, "two.org") {
		t.Errorf("--by-project must name them:\n%s", got)
	}
	// sed is needed by two projects and must sort above awk, which is needed
	// by one; awk and mkdir both have one and sort alphabetically.
	if strings.Index(got, "sed") > strings.Index(got, "awk") {
		t.Errorf("the most-needed command must come first:\n%s", got)
	}
}

// A project named twice is one project. Counting it twice would be the
// report's own arithmetic being wrong, which is worse than a missing entry
// because it looks like data.
func TestRunToolsCountsAProjectOnce(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "one.org", "build:\n  script: sed -i s/a/b/ x\n")
	var out, errb bytes.Buffer
	runTools([]string{"--pantry", p, "--platform", "linux/x86-64", "one.org", "one.org"}, &out, &errb)
	if !strings.Contains(out.String(), "1 command(s) across 1 project(s)") {
		t.Errorf("a project named twice is one project:\n%s", out.String())
	}
}

// A named project with no recipe is reported and skipped, not fatal: naming a
// set of projects is how this is used, and one absentee must not lose the rest.
func TestRunToolsSkipsAMissingRecipe(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "here.org", "build:\n  script: sed -i s/a/b/ x\n")
	var out, errb bytes.Buffer
	if code := runTools([]string{"--pantry", p, "--platform", "linux/x86-64", "here.org", "gone.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(errb.String(), "skip gone.org") {
		t.Errorf("the absentee must be named: %q", errb.String())
	}
	if !strings.Contains(out.String(), "sed") {
		t.Errorf("and the rest must still be reported:\n%s", out.String())
	}
}

func TestRunToolsFlagError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runTools([]string{"--nope"}, &out, &errb); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
}

// A command name built from more than one piece — `"gcc"-13`, `pre$VAR` — is
// not a bare name and must be omitted rather than half-reported.
func TestWordLiteralOnAMultiPartWord(t *testing.T) {
	got := scriptCommands("\"my\"tool --version\n")
	if len(got) != 0 {
		t.Errorf("a multi-part command name must be omitted, got %v", got)
	}
}

// And through the dispatch, so the subcommand is actually reachable.
func TestToolsDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"tools"}, &out, &errb); code != 2 {
		t.Errorf("code = %d, want the usage refusal", code)
	}
	if !strings.Contains(errb.String(), "--all") {
		t.Errorf("want the tools usage, got %q", errb.String())
	}
}

// The build surface and the test surface answer different questions, and
// pooling them hid one. serf's test calls pkg-config and its recipe declares
// it nowhere; pooled with the build's commands that reads as a build tool.
func TestRunToolsScopeSeparatesBuildFromTest(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "serf.org",
		"build:\n  script: scons install\ntest:\n  script: pkg-config --modversion serf-1\n")

	for _, tc := range []struct {
		scope        string
		want, absent string
	}{
		{"build", "scons", "pkg-config"},
		{"test", "pkg-config", "scons"},
		{"all", "pkg-config", ""},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := runTools([]string{"--pantry", p, "--platform", "linux/x86-64", "--scope", tc.scope, "serf.org"}, &out, &errb)
			if code != 0 {
				t.Fatalf("code = %d: %s", code, errb.String())
			}
			got := out.String()
			if !strings.Contains(got, tc.want) {
				t.Errorf("want %q in:\n%s", tc.want, got)
			}
			if tc.absent != "" && strings.Contains(got, tc.absent) {
				t.Errorf("%q leaked into the %s scope:\n%s", tc.absent, tc.scope, got)
			}
		})
	}
	// "all" is the default and must stay it, or every existing caller changes
	// meaning without being edited.
	var out, errb bytes.Buffer
	if code := runTools([]string{"--pantry", p, "--platform", "linux/x86-64", "serf.org"}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	for _, want := range []string{"scons", "pkg-config"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the default scope dropped %q:\n%s", want, out.String())
		}
	}
}

// An unknown scope is refused rather than silently treated as "all": a typo
// that reported the whole surface as the test surface would be a measurement
// nobody could tell was wrong.
func TestRunToolsRefusesAnUnknownScope(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runTools([]string{"--pantry", t.TempDir(), "--scope", "tests", "x.org"}, &out, &errb); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "unknown --scope") {
		t.Errorf("the refusal must name the flag: %q", errb.String())
	}
}
