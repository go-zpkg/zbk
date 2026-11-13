// Package buildscript turns a recipe's build/test node into the shell script
// brewkit runs, a faithful port of libpkgx's usePantry.getScript: moustache
// expansion, `if:` guards evaluated against the build TARGET, platform-reduced
// env, working-directory wrapping and prop/fixture here-docs.
package buildscript

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/go-versions/semver"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/target"
)

// Options carries everything script generation needs beyond the node itself.
type Options struct {
	Target     target.Target     // the build-for platform/arch (guards key on this)
	PkgVersion string            // used to evaluate semver `if:` guards
	Tokens     []moustache.Token // prefix/version/deps/hw/pkgx/srcroot/props, pre-assembled
}

// rangeRE tells a semver condition from a platform one. The platform names
// themselves come from target, which is the only place that knows them —
// see target.IsPlatform for what the second copy here used to cost.
var rangeRE = regexp.MustCompile(`^[v0-9*^~<>=]`)

// Generate renders node (a recipe's build or test value) into a shell script.
func Generate(node any, opts Options) (string, error) {
	if m, ok := node.(map[string]any); ok {
		raw, err := scriptList(m["script"], opts)
		if err != nil {
			return "", err
		}
		if wd, ok := m["working-directory"].(string); ok && wd != "" {
			wd = moustache.Apply(wd, opts.Tokens)
			raw = fmt.Sprintf("mkdir -p %s\ncd %s\n\n%s", wd, wd, raw)
		}
		if env, ok := m["env"].(map[string]any); ok {
			raw = expandEnv(env, opts) + "\n\n" + raw
		}
		// A fixture declared on the NODE covers the whole script, where one
		// declared on a step covers that step. scriptItem has always handled
		// the second; this is the first, and it was missing. Nothing found it
		// because nothing ran a test: `test: {script, fixture}` is the shape
		// 115 of this pantry's 1897 recipes use, and ZERO use it on build
		// (measured on pantry 2df061b), which is also why this cannot change
		// what any recipe here compiles.
		//
		// OUTERMOST — after env and working-directory, not before them. The
		// first version wrapped the script alone, "the same nesting a
		// per-step fixture gets", and gnu.org/make failed the s390x seed's
		// first test sweep on it:
		//
		//	test:
		//	  env: {MAKEFLAGS: --file=$FIXTURE}
		//
		// The export ran before the mktemp, so MAKEFLAGS said `--file=` and
		// make printed its usage and exited 2. An env that names the fixture
		// is the recipe saying the fixture is in scope for everything,
		// including the environment.
		if fx, key := fixtureOf(m); fx != nil {
			raw = wrapFixture(fx, key, raw, opts)
		}
		return raw, nil
	}
	return scriptList(node, opts)
}

// scriptList renders a script value: a string, or a list whose items are
// strings or `{if,run,working-directory,prop/fixture}` objects.
func scriptList(input any, opts Options) (string, error) {
	switch v := input.(type) {
	case nil:
		return "", nil
	case string:
		return moustache.Apply(v, opts.Tokens), nil
	case []any:
		var parts []string
		for _, item := range v {
			s, err := scriptItem(item, opts)
			if err != nil {
				return "", err
			}
			if s = strings.TrimSpace(s); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n\n"), nil
	default:
		return moustache.Apply(fmt.Sprint(v), opts.Tokens), nil
	}
}

func scriptItem(item any, opts Options) (string, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return moustache.Apply(fmt.Sprint(item), opts.Tokens), nil
	}
	if cond, ok := m["if"]; ok {
		if !matchGuard(fmt.Sprint(cond), opts) {
			return "", nil
		}
	}
	run, err := renderRun(m["run"], opts)
	if err != nil {
		return "", err
	}
	if wd, ok := m["working-directory"].(string); ok && wd != "" {
		wd = moustache.Apply(wd, opts.Tokens)
		run = fmt.Sprintf("OLDWD=\"$PWD\"\nmkdir -p \"%s\"\ncd \"%s\"\n%s\ncd \"$OLDWD\"\nunset OLDWD", wd, wd, strings.TrimSpace(run))
	}
	if fx, key := fixtureOf(m); fx != nil {
		run = wrapFixture(fx, key, run, opts)
	}
	return run, nil
}

// renderRun expands a `run` value (string or list of strings joined by newlines).
func renderRun(run any, opts Options) (string, error) {
	switch v := run.(type) {
	case string:
		return moustache.Apply(v, opts.Tokens), nil
	case []any:
		var lines []string
		for _, x := range v {
			lines = append(lines, moustache.Apply(fmt.Sprint(x), opts.Tokens))
		}
		return strings.Join(lines, "\n"), nil
	default:
		return "", fmt.Errorf("buildscript: script step needs a `run` string or list")
	}
}

// matchGuard reports whether an `if:` condition selects for the build target.
// A platform/arch/os-arch that doesn't match the target, or a semver range the
// package version doesn't satisfy, returns false (the step is dropped).
func matchGuard(cond string, opts Options) bool {
	t := opts.Target
	if o, a, ok := platformKey(cond); ok {
		return (o == "" || t.Platform == o) && (a == "" || t.Arch == a)
	}
	if rangeRE.MatchString(cond) {
		ver, err := semver.ParseVersion(opts.PkgVersion)
		if err != nil {
			return true
		}
		rng, err := semver.ParseRange(cond)
		if err != nil {
			return true
		}
		return rng.Satisfies(ver)
	}
	return true // an unrecognised condition does not gate the step
}

// expandEnv renders an env map into `export KEY=value` lines, after reducing
// platform-keyed sub-maps against the target.
func expandEnv(env map[string]any, opts Options) string {
	reduced := platformReduce(env, opts.Target)
	keys := make([]string, 0, len(reduced))
	for k := range reduced {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable, deterministic base order
	// Render each value once; we both scan it for references and emit it.
	val := make(map[string]string, len(keys))
	for _, k := range keys {
		val[k] = posixQuote(envValue(reduced[k], opts))
	}
	var lines []string
	for _, k := range orderEnvKeys(keys, val) {
		lines = append(lines, "export "+k+"="+val[k])
	}
	return strings.Join(lines, "\n")
}

// orderEnvKeys orders env keys so that whenever one variable's value references
// another ($OTHER / ${OTHER}), the referenced variable is exported first. Bash
// assigns eagerly, so a forward reference otherwise expands to empty — e.g. a
// recipe declaring PCDIR and ARGS="… --with-pkg-config-libdir=$PCDIR" would, if
// sorted alphabetically (ARGS before PCDIR), pass an empty libdir. It falls back
// to the given (alphabetical) order for independent variables and to break any
// reference cycle, so output stays deterministic.
func orderEnvKeys(keys []string, val map[string]string) []string {
	deps := make(map[string]map[string]bool, len(keys))
	for _, a := range keys {
		set := map[string]bool{}
		for _, b := range keys {
			if a != b && referencesVar(val[a], b) {
				set[b] = true
			}
		}
		deps[a] = set
	}
	emitted := make(map[string]bool, len(keys))
	out := make([]string, 0, len(keys))
	for len(out) < len(keys) {
		progressed := false
		for _, k := range keys { // alphabetical scan keeps ties stable
			if emitted[k] {
				continue
			}
			ready := true
			for b := range deps[k] {
				if !emitted[b] {
					ready = false
					break
				}
			}
			if ready {
				out = append(out, k)
				emitted[k] = true
				progressed = true
			}
		}
		if !progressed { // reference cycle: emit the first remaining key, break it
			for _, k := range keys {
				if !emitted[k] {
					out = append(out, k)
					emitted[k] = true
					break
				}
			}
		}
	}
	return out
}

// referencesVar reports whether s contains a shell reference to name ($name or
// ${name}). A bare $name requires a non-identifier boundary after it so $PC does
// not match $PCDIR.
func referencesVar(s, name string) bool {
	if strings.Contains(s, "${"+name+"}") {
		return true
	}
	pat := "$" + name
	for i := 0; ; {
		j := strings.Index(s[i:], pat)
		if j < 0 {
			return false
		}
		end := i + j + len(pat)
		if end >= len(s) || !isIdentChar(s[end]) {
			return true
		}
		i = end
	}
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// platformReduce merges platform-keyed sub-maps (darwin|linux|windows[/arch] or
// bare arch) into the top level for the matching target and strips those keys.
// A sub-value given as a list supplements; a scalar replaces.
func platformReduce(env map[string]any, t target.Target) map[string]any {
	out := make(map[string]any, len(env))
	for k, v := range env {
		out[k] = v
	}
	// Merge platform sub-maps in a deterministic (sorted) key order: when two
	// platform keys supplement the SAME list (eg. linux CFLAGS and x86-64
	// CFLAGS), map iteration order would otherwise make the result unstable.
	pkeys := make([]string, 0, len(env))
	for k := range env {
		if _, _, ok := platformKey(k); ok {
			pkeys = append(pkeys, k)
		}
	}
	sort.Strings(pkeys)
	for _, k := range pkeys {
		v := env[k]
		os, arch, _ := platformKey(k)
		delete(out, k)
		if os != "" && os != t.Platform {
			continue
		}
		if arch != "" && arch != t.Arch {
			continue
		}
		sub, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for sk, sv := range sub {
			if list, isList := sv.([]any); isList {
				if ex, exists := out[sk]; exists {
					out[sk] = append(toList(ex), list...)
				} else {
					out[sk] = list
				}
			} else {
				out[sk] = sv
			}
		}
	}
	return out
}

func platformKey(k string) (os, arch string, ok bool) {
	if o, a, slash := strings.Cut(k, "/"); slash {
		if target.IsPlatform(o) && target.IsArch(a) {
			return o, a, true
		}
		return "", "", false
	}
	if target.IsPlatform(k) {
		return k, "", true
	}
	if target.IsArch(k) {
		return "", k, true
	}
	return "", "", false
}

// envValue renders an env value: a list joined by spaces, else a transformed
// scalar. Each element is moustache-expanded; bool→1/0, nil→0.
func envValue(v any, opts Options) string {
	if list, ok := v.([]any); ok {
		parts := make([]string, len(list))
		for i, e := range list {
			parts[i] = transformScalar(e, opts)
		}
		return strings.Join(parts, " ")
	}
	return transformScalar(v, opts)
}

func transformScalar(v any, opts Options) string {
	switch x := v.(type) {
	case nil:
		return "0"
	case bool:
		if x {
			return "1"
		}
		return "0"
	case string:
		return moustache.Apply(x, opts.Tokens)
	default:
		return fmt.Sprint(x)
	}
}

// posixQuote mirrors brewkit's env escaping: wrap in double quotes, double any
// embedded quote, then trim redundant leading/trailing empty-quote pairs.
func posixQuote(value string) string {
	// An EMPTY value is quoted and returned at once. The loops below collapse
	// a pre-quoted value — a recipe writing `"foo"` must not come out as
	// `""foo""` — and on `""` they eat the pair and leave ONE quote, which is
	// an unterminated string:
	//
	//	export LDFLAGS="
	//
	//	build.sh:115:82: a command can only contain words and redirects
	//
	// Latent until something set one: no recipe in the pantry assigns an empty
	// env value, and the first thing that did was an override clearing
	// LDFLAGS for gnu.org/glibc (go-zpkg/packages#291). The build failed to
	// PARSE, which is a long way from the line that caused it.
	if strings.TrimSpace(value) == "" {
		return `""`
	}
	value = `"` + strings.ReplaceAll(strings.TrimSpace(value), `"`, `""`) + `"`
	for strings.HasPrefix(value, `""`) {
		value = value[1:]
	}
	for strings.HasSuffix(value, `""`) {
		value = value[:len(value)-1]
	}
	return value
}

func toList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

// fixtureOf returns a step's fixture (build: `prop`, test: `fixture`) and the
// shell variable name it is exposed under (PROP / FIXTURE).
func fixtureOf(m map[string]any) (any, string) {
	if p, ok := m["prop"]; ok {
		return p, "PROP"
	}
	if f, ok := m["fixture"]; ok {
		return f, "FIXTURE"
	}
	return nil, ""
}

// wrapFixture writes the fixture contents to a temp file exposed as $key, runs
// the step, then restores the previous value — a port of add_fixture.
func wrapFixture(fx any, key, run string, opts Options) string {
	contents, extname := fixtureContents(fx)
	contents = moustache.Apply(contents, opts.Tokens)
	contents = strings.ReplaceAll(contents, "$", `\$`)
	ext := ""
	if extname != "" {
		ext = "." + strings.TrimLeft(extname, ".")
	}
	chmod := ""
	if strings.HasPrefix(contents, "#!") {
		chmod = fmt.Sprintf("chmod +x $%s\n", key)
	}
	return fmt.Sprintf(`OLD_%s=$%s
%s=$(mktemp)%s

cat <<DEV_ZPKG_EOF > $%s
%s
DEV_ZPKG_EOF
%s%s

rm -f $%s*

if test -n "$OLD_%s"; then
  %s=$OLD_%s
else
  unset %s
fi`, key, key, key, ext, key, contents, chmod, run, key, key, key, key, key)
}

func fixtureContents(fx any) (contents, extname string) {
	if m, ok := fx.(map[string]any); ok {
		if c, ok := m["content"].(string); ok {
			contents = c
		} else if c, ok := m["contents"].(string); ok {
			contents = c
		}
		extname, _ = m["extname"].(string)
		return contents, extname
	}
	return fmt.Sprint(fx), ""
}
