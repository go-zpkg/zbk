// Package pantry parses and validates pkgx pantry package.yml recipes. The
// parsed Recipe is the shared representation that both the YAML front-end and
// the HCL2 front-end decode into, so a recipe written either way yields an
// identical build.
package pantry

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-zpkg/zbk/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// Recipe is a decoded package.yml. Fields use `any` where pkgx allows several
// shapes (a script may be a string or a list; env values a scalar or a list;
// deps a constraint or a platform-keyed map) — the build-script generator
// resolves those shapes against the build target. Unknown keys are retained in
// Extra so nothing is silently dropped.
type Recipe struct {
	Distributable any            `yaml:"distributable"`
	Versions      any            `yaml:"versions"`
	Dependencies  map[string]any `yaml:"dependencies"`
	Build         any            `yaml:"build"`
	Test          any            `yaml:"test"`
	Provides      any            `yaml:"provides"`
	Runtime       *Runtime       `yaml:"runtime"`
	Companions    map[string]any `yaml:"companions"`
	Platforms     any            `yaml:"platforms"`
	Warnings      any            `yaml:"warnings"`
	// Members makes a recipe a SET: a named, versionable tree of packages
	// rather than one discrete package.
	//
	// The three systems that solved this agree on the shape and disagree on
	// almost nothing that matters here:
	//
	//	Nix    a tree IS a derivation — `buildEnv` takes a list of packages
	//	       and its output is a tree of symlinks. No new kind of object.
	//	Guix   a manifest names packages; a PROFILE is the tree it makes.
	//	Spack  `spack.yaml` is the abstract set, `spack.lock` the concrete
	//	       one: "the same root specs... may concretize differently".
	//
	// Nix's answer is the one taken: a set is an ordinary recipe. It is
	// therefore signed, attested, published and installed by everything that
	// already does those things for a package — rather than a second kind of
	// artefact to keep in step, which is the defect this repository has paid
	// for more than once.
	//
	// What this does NOT give is Guix's warning: a manifest alone is not
	// reproducible, because the same names resolve differently against a
	// different package set. `members` is the ABSTRACT half; `bk lock` is
	// the concrete one, and writes the resolved versions down beside the
	// pantry and overlay revisions that produced them.
	//
	// The shape is `dependencies`' shape on purpose: a reader who knows one
	// knows the other, and the resolver already handles it.
	Members map[string]any `yaml:"members"`

	DisplayName string `yaml:"display-name"`
	Summary     string `yaml:"summary"`
	Description string `yaml:"description"`

	// Provenance records the files of the PROJECT ITSELF that this recipe's
	// build was derived from.
	//
	// ⛔ IT IS THE REASON THESE RECIPES MAY EXIST. pkgxdev/pantry carries no
	// licence — 0 of 2453 files, and `"license": null` from the API — so it
	// cannot seed ours, and the recipes are WRITTEN rather than converted
	// (go-zpkg/packages#431). Written from what? From each project's own
	// configure, CMakeLists.txt, Makefile, INSTALL or README, under that
	// project's own licence. This field is where that claim stops being a
	// claim.
	//
	// Typed rather than left in the generic document because a field nothing
	// decodes is a field nothing can require, and `additionalProperties` is
	// true at the root: before this, a recipe could carry `provenance` and
	// zbk would accept it and drop it, which reads to anyone opening the
	// recipe as a record that exists.
	// ⛔⛔ `json:"-"` IS LOAD-BEARING, AND A GOLDEN TEST CAUGHT ITS ABSENCE.
	// spec.hashRecipes json.Marshals the whole Recipe, so a new field adds a
	// key to the canonical form and moves the LOCK SPEC HASH that every lock
	// file in existence holds — `zbk lock --check` would then report every
	// project as changed, which reads as "the pantry moved" rather than "the
	// tool did". TestTheLockSpecHashIsTheValueLockFilesHold said so in one
	// line.
	//
	// Excluded on principle and not merely to keep the test quiet:
	// provenance records WHY WE MAY SHIP THIS RECIPE, not anything the build
	// consumes. It cannot change a byte of the output, so it must not change
	// the identity of the output. Were it ever to appear in the hash, a
	// reworded `note` would re-address every bottle of that project.
	Provenance *Provenance `yaml:"provenance" json:"-"`
}

// Provenance is a recipe's own origin: not the package's source, which is
// `distributable`, but the project files whose build instructions this recipe
// re-expresses.
type Provenance struct {
	// Read names paths inside the project's source. At least one, enforced by
	// the schema: a provenance block with nothing read says less than none.
	Read []string `yaml:"read"`

	// Consulted names other distributions' packaging of the same project —
	// Nix, Guix, Spack, Homebrew, pkgx, Debian, Fedora — that were read while
	// writing this recipe.
	//
	// ⛔⛔ READING THEM IS BIBLIOGRAPHY, AND WRITING DOWN THAT WE DID IS THE
	// HONEST FORM OF IT. Rewriting the recipes rather than converting them
	// (go-zpkg/packages#431) is about EXPRESSION: we do not take anyone's
	// script. It is not an undertaking to ignore how six other distributions
	// solved the same build, and it would be a poor one — their packaging is
	// where the hard-won facts live: which configure flag a project needs on
	// darwin, which dependency it does not declare, which test hangs under
	// qemu. Those are facts about the software, and a fact has no author.
	//
	// So this field is not a confession, it is a citation list, and it is the
	// thing that makes the distinction auditable: `read` is what the build
	// DERIVES from, `consulted` is what was learned from. A recipe that cites
	// six distributions and derives from the project's own configure is
	// visibly doing the right thing; one that cites nothing and happens to
	// match Debian's rules line for line is not, and nobody could tell the
	// difference without this.
	Consulted []string `yaml:"consulted"`

	// Note is one line on what those files said to do.
	Note string `yaml:"note"`
}

// Runtime is the environment a package exports to its consumers.
type Runtime struct {
	Env map[string]any `yaml:"env"`
}

// ErrSchema reports that a recipe does not satisfy the authoritative schema,
// as distinct from being unreadable or absent.
//
// ⛔⛔ THE DISTINCTION IS LOAD-BEARING SINCE THE SCHEMA WAS CLOSED. Closing
// `additionalProperties` (#423) made us refuse 42 of the 1932 upstream
// recipes, which is intended — they rely on keys nothing here implements. But
// `zbk overrides` validated the OVERRIDDEN recipe and reported every error as
// "override(s) whose premise is gone", so a recipe our schema declines became
// indistinguishable from a patch that no longer applies, and the step went red
// on `additional properties 'aliases' not allowed` for python.org,
// protobuf.dev and rust-lang.org.
//
// Those are two different findings about two different files. Validating
// somebody else's recipe against our schema and calling the result an override
// failure blames our patch for their key.
var ErrSchema = errors.New("pantry: schema validation failed")

// compiledSchema is the package.yml JSON Schema, compiled once at load.
var compiledSchema = must(compile(schema.PackageJSON))

// compile builds a jsonschema.Schema from raw JSON-Schema bytes.
func compile(data []byte) (*jsonschema.Schema, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	// AddResource does not validate an in-memory document (even a malformed
	// $id surfaces later, at Compile), so its error is unreachable here.
	_ = c.AddResource("package.schema.json", doc)
	return c.Compile("package.schema.json")
}

func must(s *jsonschema.Schema, err error) *jsonschema.Schema {
	if err != nil {
		panic("pantry: " + err.Error())
	}
	return s
}

// Validate checks raw package.yml bytes against the authoritative schema.
func Validate(data []byte) error {
	_, err := validated(data)
	return err
}

// validated is Validate, and returns the normalised document it checked.
//
// The document is the only answer to "does this recipe STATE this key", which
// the typed Recipe cannot give: its optional fields are `any`, so an absent
// key and a stated `null` both decode to nil. Rather than read the file a
// second time to find out, the one reading that already happens is returned —
// see ParseWithDoc.
func validated(data []byte) (map[string]any, error) {
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("pantry: invalid YAML: %w", err)
	}
	doc = toJSONValue(doc)
	if err := compiledSchema.Validate(doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	// The schema's root is `"type": "object"`, so anything that reached here is
	// a mapping. Asserted without a branch on purpose: an arm no input can
	// enter is an arm no test can check.
	m, _ := doc.(map[string]any)
	return m, nil
}

// Parse decodes and validates package.yml bytes into a Recipe. It decodes into
// the typed struct first (so a type mismatch is reported precisely), then
// checks the whole document against the authoritative schema.
func Parse(data []byte) (*Recipe, error) {
	r, _, err := ParseWithDoc(data)
	return r, err
}

// ParseWithDoc is Parse, and also returns the DOCUMENT it validated: the keys
// the file states, before any typing.
//
// It exists so that nothing has to read a recipe twice to learn both. The
// first shape of `bk lint --require-standalone` read the file once for the
// recipe and once for the document, which bought two error arms that no input
// could reach — the second read cannot fail to find a file the first just
// parsed — and the 100% coverage gate was right to refuse them. One reading
// also removes a real hazard: two reads of a file being edited can disagree,
// and "the recipe says X and the document says Y" would then be a state this
// package could produce.
func ParseWithDoc(data []byte) (*Recipe, map[string]any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("pantry: decode: %w", err)
	}
	var r Recipe
	if err := root.Decode(&r); err != nil {
		return nil, nil, fmt.Errorf("pantry: decode: %w", err)
	}
	// A list-form `versions:` enumerates candidate versions verbatim. yaml.v3
	// coerces unquoted numeric scalars when decoding into `any` (3.0 becomes
	// float64(3), losing the ".0"), which would corrupt the distributable URL
	// that interpolates {{version.raw}}. Re-read the sequence's raw scalar text
	// straight from the YAML node so each candidate keeps its exact source form.
	r.Versions = rawListVersions(&root, r.Versions)
	doc, err := validated(data)
	if err != nil {
		return nil, nil, err
	}
	return &r, doc, nil
}

// rawListVersions returns the verbatim scalar text of a list-form `versions:`
// sequence as a []any of strings, so a candidate like "3.0" is preserved
// exactly rather than coerced. For any other form (the github/url map, or an
// absent versions key) it returns decoded unchanged.
func rawListVersions(root *yaml.Node, decoded any) any {
	// A successful root.Decode into the Recipe struct guarantees a mapping
	// document; only the empty-document case has no content.
	if len(root.Content) == 0 {
		return decoded
	}
	m := root.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != "versions" {
			continue
		}
		node := m.Content[i+1]
		if node.Kind != yaml.SequenceNode {
			return decoded
		}
		// Only a SCALAR element carries verbatim text worth rescuing. A list can
		// also hold {url, match, strip} MAPPINGS -- kernel.org/linux-headers has
		// one per kernel series -- and a mapping node's .Value is the empty
		// string, so taking it turned every such source block into "" and the
		// recipe could no longer resolve a single version.
		dec, _ := decoded.([]any)
		out := make([]any, 0, len(node.Content))
		for i, c := range node.Content {
			if c.Kind == yaml.ScalarNode {
				out = append(out, c.Value)
				continue
			}
			if i < len(dec) {
				out = append(out, dec[i])
			}
		}
		return out
	}
	return decoded
}

// toJSONValue normalises a yaml.v3-decoded value into the plain types the JSON
// Schema validator expects: map[string]any, []any, string, float64, bool, nil.
func toJSONValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = toJSONValue(x)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = toJSONValue(x)
		}
		return m
	case []any:
		for i, x := range t {
			t[i] = toJSONValue(x)
		}
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	default:
		return v
	}
}
