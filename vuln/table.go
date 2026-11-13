// Package vuln answers one question for a pkgx project: under what name will a
// vulnerability database recognise it?
//
// There are two answers and they rank. Most projects name a repository or an
// ecosystem themselves, and versions.Identities plus FromProjectName read it
// (the DERIVED answer). The rest name nothing but an upstream host, and for
// those a human writes the name down once, in a table (the DECLARED answer).
// Declared wins, because it exists only where the derivation was judged wrong
// or absent.
//
// ⛔ TWO CENSUSES, TWO CORPORA, DO NOT MIX THEM. An offline census over the
// pantry AND the overlay — 1908 recipes — counting build-dependency hints as
// an ecosystem, found 1005 in an ecosystem, 1506 naming a repository, 302 with
// only an upstream host and 14 with nothing. `bk vulnid` measures something
// narrower and more useful: only what a QUERY can be built from. On the cached
// pantry alone, 1563 recipes, it reports 1241 derived and 322 with no identity.
// Neither number is wrong and neither substitutes for the other.
//
// # How the others do it
//
// Yocto puts the name in the recipe and defaults it: CVE_PRODUCT is ${BPN}
// unless a recipe overrides it, and the documentation gives both reasons an
// override is needed — a product whose CVE name differs from its recipe name
// (`CVE_PRODUCT = "oracle_berkeley_db berkeley_db"`, note the TWO names), and a
// name that is not specific enough:
//
//	Sometimes the product name is not specific enough, for example "tar"
//	has been matching CVEs for the GNU tar package and also the node-tar
//	node.js extension. To avoid this problem, use the vendor name as a
//	prefix. The syntax for this is: CVE_PRODUCT = "vendor:package"
//
// That is the defect measured here on 2026-10-11 from the other end: a bare
// `openssl:3.5.7` CPE query returned 27 CVEs, four of them from 2009, because
// every openssl criterion in the answer reads `openssl:*` with no upper bound.
// So a CPE name in this table is REFUSED unless it carries its vendor.
//
// Wolfi keeps the other half — which vulnerabilities a package has, and what
// was decided about each — in a separate `<package>.advisories.yaml` per
// package, as an ordered list of timestamped events (`detection`, `fixed` with
// a `fixed-version`, `false-positive-determination`, …). This table is NOT
// that: it holds identity only. Mixing the two would mean editing a file that
// names 1908 projects every time one vulnerability is triaged.
package vuln

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-zpkg/zpkb/versions"
	"gopkg.in/yaml.v3"
)

// Identity is versions.Identity under the name callers of this package reach
// for. An ALIAS, not a new type: a declared identity and a derived one must be
// the same value, or the two halves could not be compared.
type Identity = versions.Identity

// Source says where an identity came from, and therefore how much it is worth.
type Source int

const (
	// SourceNone: nothing names this project in a way a database accepts.
	SourceNone Source = iota
	// SourceDerived: read off the recipe's `versions:` block.
	SourceDerived
	// SourceDeclared: written down in the table by a person.
	SourceDeclared
)

func (s Source) String() string {
	switch s {
	case SourceDeclared:
		return "declared"
	case SourceDerived:
		return "derived"
	default:
		return "none"
	}
}

// TableVersion is the only schema version ParseTable accepts.
//
// An unknown version is an ERROR rather than a best effort, because every
// plausible future change here changes what a name MEANS — a second CPE
// spelling, a vendor field of its own, a per-platform entry. Reading a v2 file
// with v1 rules would not fail, it would answer confidently about the wrong
// package, which is the one outcome a vulnerability query must not have.
const TableVersion = 1

// A database key is checked against an ALLOWLIST, never merely for not being
// known-bad: a typo (`githb:`) in a denylist world is not a typo, it is a
// project that silently has no identity — indistinguishable from one nobody has
// looked at yet.
//
// osvEcosystems is OSV's own list of defined ecosystems, copied verbatim from
// the auto-generated table in ossf/osv-schema docs/schema.md as read on
// 2026-10-11, spelling and case included.
//
// It is copied WHOLE rather than filtered to the ones this fleet uses today.
// A list of the ones I expected is a list whose gaps are invisible: `Homebrew`
// and `vcpkg` are in here, and a C library packaged by both is exactly the kind
// of project pkgx holds. The case matters because a query sends this string —
// "crates" or "conan" matches nothing at all.
//
// Note what is NOT in it: pkgx. OSV has ecosystems for Homebrew, Alpine, Wolfi,
// Chainguard and vcpkg, so the long-term answer for this fleet is to become one
// rather than to keep translating into someone else's.
var osvEcosystems = []string{
	"AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux",
	"BellSoft Hardened Containers", "Bioconductor", "Bitnami", "Chainguard",
	"CleanStart", "ConanCenter", "CRAN", "crates.io", "Debian",
	"Docker Hardened Images", "Echo", "FreeBSD", "GHC", "GitHub Actions", "Go",
	"Hackage", "Hex", "Homebrew", "Julia", "Kubernetes", "Linux", "Mageia",
	"Maven", "MinimOS", "npm", "NuGet", "opam", "openEuler", "openSUSE",
	"OSS-Fuzz", "Packagist", "Photon OS", "Pub", "PyPI", "Red Hat",
	"Red Hat Lightwell", "Rocky Linux", "Root", "RubyGems", "SUSE", "SwiftURL",
	"TuxCare", "Ubuntu", "vcpkg", "VSCode", "Wolfi", "WordPress",
}

// extraDBs are the keys that are NOT OSV ecosystems.
//
// "GitHub" and "GitLab" name advisories keyed by REPOSITORY rather than by
// package — the spelling versions.Identities already produces, so a declared
// entry and a derived one are the same kind of thing. "cpe" is the NVD route,
// kept for the projects that name nothing but an upstream host — 322 of the
// cached pantry's 1563, as `bk vulnid` counts them.
var extraDBs = []string{"cpe", "GitHub", "GitLab"}

var knownDBs = func() map[string]bool {
	m := make(map[string]bool, len(osvEcosystems)+len(extraDBs))
	for _, e := range osvEcosystems {
		m[e] = true
	}
	for _, e := range extraDBs {
		m[e] = true
	}
	return m
}()

// Table is the declared half: project -> the names a database knows it by.
type Table struct {
	SchemaVersion int `yaml:"schema-version"`
	// Projects maps a pkgx project onto database -> one or more names. Several
	// names per database is not a mistake: Yocto's berkeley_db carries two
	// because NVD records the same package under both.
	Projects map[string]map[string][]string `yaml:"projects"`
}

// ParseTable reads an identity table, refusing anything it cannot be sure of.
func ParseTable(data []byte) (*Table, error) {
	var t Table
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("vuln: table: %w", err)
	}
	if t.SchemaVersion != TableVersion {
		return nil, fmt.Errorf("vuln: table: schema-version %d, want %d", t.SchemaVersion, TableVersion)
	}
	for _, project := range sortedKeys(t.Projects) {
		dbs := t.Projects[project]
		if len(dbs) == 0 {
			return nil, fmt.Errorf("vuln: table: %s names no database — remove the entry or give it one", project)
		}
		for _, db := range sortedKeys(dbs) {
			if !knownDBs[db] {
				return nil, fmt.Errorf("vuln: table: %s: unknown database %q", project, db)
			}
			names := dbs[db]
			if len(names) == 0 {
				return nil, fmt.Errorf("vuln: table: %s: %s names nothing", project, db)
			}
			for _, name := range names {
				if err := checkName(db, name); err != nil {
					return nil, fmt.Errorf("vuln: table: %s: %s: %w", project, db, err)
				}
			}
		}
	}
	return &t, nil
}

// checkName refuses a name that would query the wrong thing.
func checkName(db, name string) error {
	if strings.TrimSpace(name) != name || name == "" {
		return fmt.Errorf("name %q is empty or padded", name)
	}
	if db == "cpe" && !strings.Contains(name, ":") {
		// Yocto's rule, and the openssl measurement's conclusion: without a
		// vendor, "tar" is GNU tar AND node-tar, and "openssl" is every
		// openssl record ever filed.
		return fmt.Errorf("cpe name %q has no vendor — write it as vendor:product", name)
	}
	if db == "cpe" && strings.Count(name, ":") != 1 {
		return fmt.Errorf("cpe name %q should be exactly vendor:product", name)
	}
	return nil
}

// For returns the identities to query a project under, and where they came
// from. recipeVersions is the recipe's `versions:` value, used only when the
// table says nothing.
//
// A nil Table is not an error: it is the state of a fleet that has declared
// nothing yet, and the derivation still answers for most projects.
func (t *Table) For(project string, recipeVersions any) ([]versions.Identity, Source) {
	if t != nil {
		if dbs, ok := t.Projects[project]; ok {
			var out []versions.Identity
			for _, db := range sortedKeys(dbs) {
				for _, name := range dbs[db] {
					out = append(out, versions.Identity{DB: db, Name: name})
				}
			}
			sortIdentities(out)
			return out, SourceDeclared
		}
	}
	// UNION, not a choice. A `crates.io/*` project names its registry package
	// in its own name AND a GitHub repository in its `versions:` block, and
	// those are two different databases with two different answers: OSV keys
	// Rust advisories by crates.io with curated version ranges, a
	// repository-keyed advisory has whatever range its filer wrote. Taking
	// either one alone would discard a question that can be asked.
	ids := FromProjectName(project)
	ids = append(ids, versions.Identities(recipeVersions)...)
	if len(ids) == 0 {
		return nil, SourceNone
	}
	ids = dedupe(ids)
	sortIdentities(ids)
	return ids, SourceDerived
}

// dedupe removes repeats while keeping one of each. The two derived sources
// can name the same key — a project called `npmjs.com/x` whose versions block
// also says `npm: x` — and a duplicated identity would be counted twice in
// every census built on this.
func dedupe(ids []Identity) []Identity {
	seen := make(map[Identity]bool, len(ids))
	out := ids[:0:0]
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func sortIdentities(ids []versions.Identity) {
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].DB != ids[j].DB {
			return ids[i].DB < ids[j].DB
		}
		return ids[i].Name < ids[j].Name
	})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
