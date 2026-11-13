package schema_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/schema"
	"gopkg.in/yaml.v3"
)

// CorpusEnv names a pantry to survey: a directory holding projects/<slug>/
// package.yml or package.hcl.
const CorpusEnv = "ZPKB_PANTRY_CORPUS"

// ⛔⛔ "0 REJECTIONS OVER 1890 RECIPES" MEASURED NOTHING WHILE THE SCHEMA WAS
// OPEN. package.schema.json sets `"additionalProperties": true` at the root
// and in every nested object, so a recipe may carry any key at all and
// validate. A corpus passing such a schema is not evidence the schema
// describes the corpus — it is evidence the schema declined to ask.
//
// Worse than vacuous, it is misleading in the one direction that costs:
// a recipe may declare `sha256`, `license` or `provenance` and zpkb will
// ACCEPT it and silently drop it. To a reader of the recipe the source looks
// verified. Nothing anywhere says otherwise.
//
// This test asks the question the schema does not: which keys does a real
// pantry actually use, and which of them has the schema never heard of? It
// is the measurement that has to come before closing the schema, and the
// gate that keeps it closed afterwards.
func TestEveryKeyTheCorpusUsesIsEnumerated(t *testing.T) {
	dir := os.Getenv(CorpusEnv)
	if dir == "" {
		t.Skipf("%s is unset: no pantry to survey. Point it at a clone of a "+
			"pantry (projects/<slug>/package.yml) to run this.", CorpusEnv)
	}

	// ⛔ EVERY CONTAINER IS ASKED, NOT ONLY THE ROOT. `additionalProperties`
	// is true in the nested objects too, so closing the root alone would
	// leave `build`, `test`, `distributable` and `versions` accepting
	// anything — and closing them WITHOUT measuring them first would be the
	// same unmeasured change this test exists to prevent.
	containers := []container{
		{name: "(root)", pointer: nil},
		{name: "build", pointer: []string{"properties", "build", "oneOf", "1"}},
		{name: "test", pointer: []string{"properties", "test", "oneOf", "2"}},
		{name: "distributable", pointer: []string{"$defs", "distributableObject"}},
		{name: "versions", pointer: []string{"$defs", "versionSource"}},
	}
	for i, c := range containers {
		known, err := propertiesAt(schema.PackageJSON, c.pointer)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(known) == 0 {
			t.Fatalf("the schema enumerates no properties for %s: this test would then "+
				"report every key in the corpus as unknown, which is not a measurement", c.name)
		}
		containers[i].known = known
	}

	recipes, unreadable, err := walk(dir)
	if err != nil {
		t.Fatal(err)
	}
	// ⛔ A SURVEY THAT COULD NOT READ REPORTS A CLEAN CORPUS. Both numbers are
	// asserted, not just printed: zero recipes means the path is wrong, and an
	// unreadable one is a hole in the denominator rather than a nuisance.
	if len(recipes) == 0 {
		t.Fatalf("%s=%s holds no recipe: a survey of nothing reports nothing unknown", CorpusEnv, dir)
	}
	if unreadable > 0 {
		t.Errorf("%d recipe(s) could not be read; they are not in the counts below", unreadable)
	}

	t.Logf("%d recipe(s) in %s", len(recipes), dir)
	total := 0
	// ⛔ THE BLAST RADIUS IS A COUNT OF RECIPES, NOT OF KEYS. Per-key counts
	// answer "how much work"; closing the schema is decided on "how many
	// recipes stop validating", and one recipe can carry several unknown
	// keys. Summing the key counts would over-state it.
	affected := map[string]bool{}
	for _, c := range containers {
		// key -> how many recipes use it, within this container
		seen := map[string]int{}
		// ⛔ AND WHICH RECIPE. A count tells you there is work and not where
		// it is: "receipt, 1 recipe(s)" sent the reader to grep a corpus by
		// hand for the one file. The first example is named, which is enough
		// to open it.
		first := map[string]string{}
		for _, r := range recipes {
			for k := range r.keys[c.name] {
				seen[k]++
				if _, ok := first[k]; !ok {
					first[k] = r.path
				}
				if !c.known[k] {
					affected[r.path] = true
				}
			}
		}
		var unknown []string
		for k := range seen {
			if !c.known[k] {
				unknown = append(unknown, k)
			}
		}
		sort.Slice(unknown, func(i, j int) bool {
			if seen[unknown[i]] != seen[unknown[j]] {
				return seen[unknown[i]] > seen[unknown[j]]
			}
			return unknown[i] < unknown[j]
		})
		t.Logf("  %-14s %2d distinct key(s), %d not in the schema", c.name, len(seen), len(unknown))
		for _, k := range unknown {
			where, err := filepath.Rel(dir, first[k])
			if err != nil {
				where = first[k]
			}
			t.Logf("      %-24s %3d recipe(s), e.g. %s", k, seen[k], where)
		}
		total += len(unknown)
	}
	if total > 0 {
		t.Errorf("%d key(s) in %d of %d recipe(s) appear in the corpus and not in "+
			"package.schema.json — each is either a key we must enumerate or a key no "+
			"recipe should carry; with additionalProperties:true today, both are "+
			"accepted and ignored", total, len(affected), len(recipes))
	}
}

// container is one object in the schema whose properties are enumerated, and
// the corresponding place in a recipe.
type container struct {
	name    string
	pointer []string
	known   map[string]bool
}

// recipe holds, per container name, the keys this recipe declares there.
type recipe struct {
	path string
	keys map[string]map[string]bool
}

// walk reads every package.yml and package.hcl under dir. It returns the
// recipes it could read and a count of those it could not, so the caller can
// assert on the hole rather than inherit it.
func walk(dir string) (out []recipe, unreadable int, err error) {
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if base != "package.yml" && base != "package.hcl" {
			return nil
		}
		keys, rerr := rootKeys(path)
		if rerr != nil {
			unreadable++
			return nil
		}
		out = append(out, recipe{path: path, keys: keys})
		return nil
	})
	return out, unreadable, err
}

// rootKeys is the set of keys one recipe declares, per container. An HCL
// recipe is read through the same converter the factory uses, so this surveys
// what zpkb would actually see rather than what the file looks like.
//
// `distributable` and `versions` may each be a list of objects; every element
// is surveyed, because one stray key in the second entry is still a key the
// schema has never heard of.
func rootKeys(path string) (map[string]map[string]bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if strings.HasSuffix(path, ".hcl") {
		doc, err = artifact.HCLToMap(body, path)
		if err != nil {
			return nil, err
		}
	} else if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	out := map[string]map[string]bool{"(root)": {}}
	add := func(container string, ms []map[string]any) {
		for _, m := range ms {
			if out[container] == nil {
				out[container] = map[string]bool{}
			}
			for k := range m {
				out[container][k] = true
			}
		}
	}
	for k, v := range doc {
		out["(root)"][k] = true
		switch k {
		// ⛔ ONLY THE OBJECT FORM. `build:` and `test:` also take a SCRIPT
		// SHORTHAND — a bare list of steps — and a step is a scriptStep, not
		// a build. Surveying the list form reported `run` as an unknown build
		// key in 33 recipes and `if` in 6, which are neither unknown nor
		// build keys. A measurement that conflates two shapes invents work.
		case "build", "test":
			if m, ok := v.(map[string]any); ok {
				add(k, []map[string]any{m})
			}
		// These two really are "an object, or a list of objects".
		case "distributable", "versions":
			add(k, objectsIn(v))
		}
	}
	return out, nil
}

// objectsIn returns v as a list of maps: v itself when it is one, its map
// elements when it is a list, and nothing when it is a scalar (the shorthand
// forms, which declare no keys).
func objectsIn(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		var out []map[string]any
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// propertiesAt is the set of property names the schema enumerates at pointer,
// where pointer walks object members by key and array members by index. A nil
// pointer is the document root.
func propertiesAt(raw []byte, pointer []string) (map[string]bool, error) {
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	for _, step := range pointer {
		switch t := node.(type) {
		case map[string]any:
			next, ok := t[step]
			if !ok {
				return nil, fmt.Errorf("schema: no member %q at %v", step, pointer)
			}
			node = next
		case []any:
			i, err := strconv.Atoi(step)
			if err != nil || i < 0 || i >= len(t) {
				return nil, fmt.Errorf("schema: %q is not an index of the array at %v", step, pointer)
			}
			node = t[i]
		default:
			return nil, fmt.Errorf("schema: %v does not address an object or array", pointer)
		}
	}
	obj, ok := node.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema: %v is not an object", pointer)
	}
	props, ok := obj["properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema: %v enumerates no properties", pointer)
	}
	out := make(map[string]bool, len(props))
	for k := range props {
		out[k] = true
	}
	return out, nil
}
