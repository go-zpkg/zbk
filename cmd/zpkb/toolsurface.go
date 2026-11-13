package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/go-zpkg/zpkb/buildscript"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
	"mvdan.cc/sh/v3/syntax"
)

// runTools implements `bk tools`: which EXTERNAL COMMANDS a recipe set needs.
//
// This is the bootstrap surface. Every command a recipe invokes is something
// that must exist in the image the build runs in, and on a FROM-scratch image
// nothing exists until a bottle puts it there. It is why bk injects fifteen
// base-toolchain projects into every build, and it is what turned two s390x
// seed builds into `exit status 127` — cmake and ninja were left to the host,
// and the host did not have them.
//
// It PARSES rather than greps. A first attempt at this question with a regex
// reported grep 1231 times, counting the word in prose, and listed `int`,
// `return` and `elif` as commands. bk already depends on mvdan.cc/sh to RUN
// these scripts, so the same parser can be asked what they call — and a
// command name that only a parser can find, behind a pipe or inside a
// substitution, is exactly the one a survey misses.
//
// A command the script itself defines, or that the shell implements, is not a
// dependency: those are subtracted.
func runTools(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("tools", flag.ContinueOnError)
	fset.SetOutput(stderr)
	pantryDir := fset.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout dir")
	platform := fset.String("platform", envOr("PLATFORM", "linux/x86-64"), "target os/arch")
	all := fset.Bool("all", false, "every project in the pantry, rather than the ones named")
	byProject := fset.Bool("by-project", false, "list which projects need each command, not just the count")
	scope := fset.String("scope", "all", `which scripts to read: "build", "test" or "all"`)
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if *scope != "all" && *scope != "build" && *scope != "test" {
		fmt.Fprintf(stderr, "tools: unknown --scope %q (build, test or all)\n", *scope)
		return 2
	}
	osn, arch, _ := strings.Cut(*platform, "/")
	tgt := target.Target{Platform: osn, Arch: arch}

	projects := fset.Args()
	if *all {
		projects = allProjects(*pantryDir)
	}
	// Deduplicated once, here, rather than guarded at every append below: a
	// project named twice is one project, and a count that said otherwise
	// would be the report's own arithmetic being wrong.
	slices.Sort(projects)
	projects = slices.Compact(projects)
	if len(projects) == 0 {
		fmt.Fprintln(stderr, "tools: name some projects, or pass --all")
		return 2
	}

	needs := map[string][]string{}
	for _, proj := range projects {
		rec, err := recipefile.Load(*pantryDir, proj)
		if err != nil {
			fmt.Fprintf(stderr, "tools: skip %s: %v\n", proj, err)
			continue
		}
		for _, cmd := range recipeCommands(rec, tgt, *scope) {
			needs[cmd] = append(needs[cmd], proj)
		}
	}

	cmds := make([]string, 0, len(needs))
	for c := range needs {
		cmds = append(cmds, c)
	}
	sort.Slice(cmds, func(i, j int) bool {
		if len(needs[cmds[i]]) != len(needs[cmds[j]]) {
			return len(needs[cmds[i]]) > len(needs[cmds[j]])
		}
		return cmds[i] < cmds[j]
	})
	for _, c := range cmds {
		fmt.Fprintf(stdout, "%5d  %s\n", len(needs[c]), c)
		if *byProject {
			sort.Strings(needs[c])
			for _, p := range needs[c] {
				fmt.Fprintf(stdout, "         %s\n", p)
			}
		}
	}
	fmt.Fprintf(stdout, "\n%d command(s) across %d project(s)\n", len(cmds), len(projects))
	return 0
}

// recipeCommands is every external command a recipe's scripts call, for this
// target, within the chosen scope.
//
// The two scopes answer different questions and pooling them hid one of them.
// A build's surface is what the IMAGE must contain; a test's surface is what
// the package's own acceptance check needs in a sandbox that deliberately has
// neither the compiler nor the build dependencies — see buildscript.WrapTest.
//
// The question that wants it apart, from go-zpkg/bk#246: apache.org/serf's
// test runs `pkg-config --modversion serf-1`, and the recipe declares
// pkg-config in NO dependency map. Pooled with the build surface that reads
// as a build tool, which it also is, and the test's undeclared use of it
// disappears. It failed the first real sweep, and how many recipes do the
// same decides whether wiring tests into the factory drowns in them.
func recipeCommands(rec *pantry.Recipe, tgt target.Target, scope string) []string {
	var sources []any
	switch scope {
	case "build":
		sources = []any{rec.Build}
	case "test":
		sources = []any{rec.Test}
	default:
		sources = []any{rec.Build, rec.Test}
	}
	var out []string
	for _, src := range sources {
		script, err := buildscript.Generate(src, buildscript.Options{Target: tgt})
		if err != nil || strings.TrimSpace(script) == "" {
			continue
		}
		out = append(out, scriptCommands(script)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// scriptCommands walks a parsed script for the name in COMMAND position.
//
// A name the script defines as a function is not a dependency, so those are
// collected first and subtracted. Neither is a shell builtin, nor a name that
// is not a literal — `$TOOL --version` names nothing we can report, and
// guessing would be worse than omitting it.
func scriptCommands(script string) []string {
	f, err := syntax.NewParser().Parse(strings.NewReader(script), "")
	if err != nil {
		return nil
	}
	defined, called := map[string]bool{}, map[string]bool{}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.FuncDecl:
			defined[x.Name.Value] = true
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				return true
			}
			lit := wordLiteral(x.Args[0])
			if lit == "" || strings.ContainsAny(lit, "$/=") {
				// A path or an assignment is not a bare command name, and a
				// name built from a variable cannot be reported honestly.
				return true
			}
			called[lit] = true
		}
		return true
	})
	var out []string
	for c := range called {
		if defined[c] || shellBuiltin[c] {
			continue
		}
		out = append(out, c)
	}
	return out
}

// wordLiteral returns a word's text when it is a plain literal, and "" when it
// is anything else.
func wordLiteral(w *syntax.Word) string {
	if len(w.Parts) != 1 {
		return ""
	}
	l, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return ""
	}
	return l.Value
}

// shellBuiltin is what the shell itself answers, so it is not something an
// image must carry. mvdan.cc/sh implements these in Go, which is also why a
// build can run with no /bin/sh at all.
var shellBuiltin = map[string]bool{
	"cd": true, "echo": true, "export": true, "exit": true, "test": true,
	"true": true, "false": true, "set": true, "unset": true, "shift": true,
	"read": true, "eval": true, "exec": true, "source": true, ".": true,
	"return": true, "break": true, "continue": true, "local": true,
	"printf": true, "pwd": true, "umask": true, "wait": true, "trap": true,
	"alias": true, "unalias": true, "command": true, "type": true, "hash": true,
	"getopts": true, "shopt": true, "ulimit": true, "times": true, "jobs": true,
	"kill": true, "fg": true, "bg": true, "let": true, "declare": true,
	"typeset": true, "readonly": true,
}

// allProjects lists every project in a pantry checkout, found by the recipe
// FILE rather than by a directory shape — recipefile.IsRecipe decides what
// counts, so an HCL recipe is not invisible here the way it was to depgaps.
func allProjects(pantryDir string) []string {
	root := filepath.Join(pantryDir, "projects")
	var out []string
	_ = filepathWalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !recipefile.IsRecipe(d.Name()) {
			return nil
		}
		if rel, e := filepath.Rel(root, filepath.Dir(p)); e == nil {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}
