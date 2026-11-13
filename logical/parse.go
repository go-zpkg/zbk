package logical

import (
	"fmt"
	"sort"

	"github.com/go-zpkg/artifact"
)

// Override is one project's logical change, as a file states it.
//
//	project = "info-zip.org/zip"
//	why     = "gcc 14 makes an implicit declaration an error, and info-zip's
//	           memset probe runs $CC without CFLAGS"
//
//	merge {
//	  build {
//	    dependencies { "gnu.org/patch" = "*" }
//	  }
//	}
//
//	edits = [
//	  {
//	    why  = "unix/Makefile overwrites CFLAGS, so CC is the only channel"
//	    path = "build.script"
//	    from = "-std=gnu17\""
//	    to   = "-std=gnu17 -Wno-implicit-function-declaration\""
//	  },
//	  { why = "…", path = "build.dependencies[\"crates.io/semverator\"]", remove = true },
//	]
//
// `merge` is a single block because the shared HCL reader refuses a repeated
// one, and `edits` is a LIST because the order of two operations on the same
// path is a fact the file has to state rather than leave to a map's iteration.
// The merge runs first: it says what shape the recipe should have, and the
// edits adjust that shape.
type Override struct {
	Project string
	Why     string
	Ops     []Op
}

// Parse reads an override file.
//
// Through artifact.HCLToMap, the same reader the recipes themselves go through.
// A second HCL front-end here would be two readings of one format, and the day
// they disagreed an override would mean one thing to the checker and another
// to the builder.
func Parse(src []byte, filename string) (*Override, error) {
	doc, err := artifact.HCLToMap(src, filename)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	doc, _ = sameTypesAsYAML(doc).(map[string]any)
	o := &Override{}
	if s, ok := doc["project"].(string); ok {
		o.Project = s
	}
	if o.Project == "" {
		return nil, fmt.Errorf("%s: needs a `project`", filename)
	}
	if s, ok := doc["why"].(string); ok {
		o.Why = s
	}
	if o.Why == "" {
		// An override whose reason lives only in a commit message is one nobody
		// can ever decide to delete: the question "is this still needed?" has
		// no answer in the file that answers it.
		return nil, fmt.Errorf("%s: needs a `why`", filename)
	}

	if m, ok := doc["merge"]; ok {
		mm, ok := m.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: `merge` must be a block", filename)
		}
		for _, op := range mergeOps(mm, nil, o.Why) {
			o.Ops = append(o.Ops, op)
		}
	}

	raw, ok := doc["edits"]
	if !ok {
		if len(o.Ops) == 0 {
			return nil, fmt.Errorf("%s: neither `merge` nor `edits` — it changes nothing", filename)
		}
		return o, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: `edits` must be a list", filename)
	}
	for i, e := range list {
		op, err := parseEdit(e, o.Why)
		if err != nil {
			return nil, fmt.Errorf("%s: edits[%d]: %w", filename, i, err)
		}
		o.Ops = append(o.Ops, op)
	}
	return o, nil
}

// mergeOps flattens a merge block into one Set per LEAF map, so that adding
// `build.dependencies."gnu.org/patch"` does not replace the whole `build`
// block. Deep-merging is what makes an overlay an overlay rather than a fork.
//
// Keys are walked in sorted order so a file produces the same operations every
// time; two runs that disagree about the order would make a parity check
// between the old format and this one impossible to read.
func mergeOps(m map[string]any, prefix Path, why string) []Op {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Op
	for _, k := range keys {
		p := append(append(Path{}, prefix...), k)
		if sub, ok := m[k].(map[string]any); ok && len(sub) > 0 {
			out = append(out, mergeOps(sub, p, why)...)
			continue
		}
		out = append(out, Op{Why: why, Path: p, Set: m[k]})
	}
	return out
}

func parseEdit(e any, defaultWhy string) (Op, error) {
	m, ok := e.(map[string]any)
	if !ok {
		return Op{}, fmt.Errorf("must be an object, got %T", e)
	}
	var op Op
	op.Why = defaultWhy
	if s, ok := m["why"].(string); ok && s != "" {
		op.Why = s
	}
	ps, _ := m["path"].(string)
	if ps == "" {
		return Op{}, fmt.Errorf("needs a `path`")
	}
	p, err := ParsePath(ps)
	if err != nil {
		return Op{}, err
	}
	op.Path = p

	_, hasSet := m["set"]
	from, hasFrom := m["from"].(string)
	to, hasTo := m["to"].(string)
	rm, _ := m["remove"].(bool)
	app, hasApp := m["append"]
	pre, hasPre := m["prepend"]

	if e, ok := m["expect"]; ok {
		op.Expect, op.HasExpect = e, true
	}
	n := 0
	if hasSet {
		n++
		op.Set = m["set"]
	}
	if rm {
		n++
		op.Remove = true
	}
	if hasFrom || hasTo {
		n++
		op.Substitute = true
		op.From, op.To = from, to
	}
	if hasApp {
		n++
		l, ok := app.([]any)
		if !ok {
			return Op{}, fmt.Errorf("`append` must be a list")
		}
		op.Append = l
	}
	if hasPre {
		n++
		l, ok := pre.([]any)
		if !ok {
			return Op{}, fmt.Errorf("`prepend` must be a list")
		}
		op.Prepend = l
	}
	switch n {
	case 1:
		return op, nil
	case 0:
		return Op{}, fmt.Errorf("names no verb (set / remove / from+to / append / prepend)")
	default:
		// Two verbs in one edit would need an order, and the file already has
		// one: the list.
		return Op{}, fmt.Errorf("names more than one verb; write them as separate edits")
	}
}

// sameTypesAsYAML makes HCL's numbers the Go types the YAML reader produces.
//
// The recipe a value is merged INTO was read by gopkg.in/yaml.v3, which gives
// a plain `int`; HCL gives an `int64`. Both print 14 and neither is wrong, and
// a document holding one where the other is expected compares unequal while
// looking identical — fftw.org's gnu.org/gcc pin failed a parity check as
// `14 != 14`.
//
// Two readers of the same recipe have to agree about what they read, or every
// comparison downstream is measuring the readers.
func sameTypesAsYAML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = sameTypesAsYAML(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sameTypesAsYAML(e)
		}
		return out
	case int64:
		return int(t)
	default:
		return v
	}
}
