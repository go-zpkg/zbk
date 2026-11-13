package vuln

import (
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/versions"
)

const minimal = "schema-version: 1\nprojects:\n  openssl.org:\n    cpe: [openssl:openssl]\n"

func TestDeclaredBeatsDerived(t *testing.T) {
	tab, err := ParseTable([]byte(minimal))
	if err != nil {
		t.Fatalf("ParseTable: %v", err)
	}
	// A recipe that DOES derive an identity, so the test proves the ranking
	// rather than merely that the table is read when nothing else answers.
	spec := map[string]any{"github": "openssl/openssl"}
	ids, src := tab.For("openssl.org", spec)
	if src != SourceDeclared {
		t.Errorf("source = %v, want declared", src)
	}
	want := []versions.Identity{{DB: "cpe", Name: "openssl:openssl"}}
	if len(ids) != 1 || ids[0] != want[0] {
		t.Errorf("identities = %v, want %v", ids, want)
	}
}

func TestDerivedWhenTheTableIsSilent(t *testing.T) {
	tab, err := ParseTable([]byte(minimal))
	if err != nil {
		t.Fatalf("ParseTable: %v", err)
	}
	ids, src := tab.For("curl.se", map[string]any{"github": "curl/curl"})
	if src != SourceDerived {
		t.Fatalf("source = %v, want derived", src)
	}
	if len(ids) != 1 || ids[0] != (versions.Identity{DB: "GitHub", Name: "curl/curl"}) {
		t.Errorf("identities = %v", ids)
	}
}

func TestNoneWhenNothingNamesIt(t *testing.T) {
	// The 302-project case: a recipe whose only hint is a distributable URL.
	ids, src := (*Table)(nil).For("ftp.gnu.org/gperf", map[string]any{"url": "https://ftp.gnu.org/gnu/gperf/"})
	if src != SourceNone {
		t.Errorf("source = %v, want none", src)
	}
	if len(ids) != 0 {
		t.Errorf("identities = %v, want none", ids)
	}
}

// A nil table must still derive. A fleet that has declared nothing yet is the
// normal state, and treating it as "no identities at all" would report 1908
// projects as unqueryable.
func TestNilTableStillDerives(t *testing.T) {
	ids, src := (*Table)(nil).For("curl.se", map[string]any{"github": "curl/curl"})
	if src != SourceDerived || len(ids) != 1 {
		t.Errorf("nil table: %v / %v", ids, src)
	}
}

func TestSeveralNamesInOneDatabase(t *testing.T) {
	// Yocto's berkeley_db carries two CVE_PRODUCT names because NVD files the
	// same package under both; dropping one loses the advisories filed there.
	const y = "schema-version: 1\nprojects:\n  oracle.com/berkeley-db:\n    cpe: [oracle:oracle_berkeley_db, oracle:berkeley_db]\n"
	tab, err := ParseTable([]byte(y))
	if err != nil {
		t.Fatalf("ParseTable: %v", err)
	}
	ids, _ := tab.For("oracle.com/berkeley-db", nil)
	if len(ids) != 2 {
		t.Fatalf("identities = %v, want 2", ids)
	}
	// Sorted, so two runs agree.
	if ids[0].Name != "oracle:berkeley_db" || ids[1].Name != "oracle:oracle_berkeley_db" {
		t.Errorf("not sorted by name: %v", ids)
	}
}

func TestTwoDatabasesAreOrderedByDatabase(t *testing.T) {
	const y = "schema-version: 1\nprojects:\n  p:\n    cpe: [v:p]\n    GitHub: [o/r]\n"
	tab, err := ParseTable([]byte(y))
	if err != nil {
		t.Fatalf("ParseTable: %v", err)
	}
	ids, _ := tab.For("p", nil)
	if len(ids) != 2 || ids[0].DB != "GitHub" || ids[1].DB != "cpe" {
		t.Errorf("identities = %v, want GitHub before cpe", ids)
	}
}

func TestParseTableRefusals(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{
			// The measured defect, as a refusal: a bare CPE product name
			// returned 27 CVEs for openssl, four of them from 2009.
			"cpe without a vendor",
			"schema-version: 1\nprojects:\n  openssl.org:\n    cpe: [openssl]\n",
			"no vendor",
		},
		{
			"cpe with too many colons",
			"schema-version: 1\nprojects:\n  p:\n    cpe: [a:b:c]\n",
			"exactly vendor:product",
		},
		{
			"unknown schema version",
			"schema-version: 2\nprojects: {}\n",
			"schema-version 2",
		},
		{
			"absent schema version",
			"projects: {}\n",
			"schema-version 0",
		},
		{
			"unknown database",
			"schema-version: 1\nprojects:\n  p:\n    githb: [o/r]\n",
			"unknown database",
		},
		{
			"project naming no database",
			"schema-version: 1\nprojects:\n  p: {}\n",
			"names no database",
		},
		{
			"database naming nothing",
			"schema-version: 1\nprojects:\n  p:\n    cpe: []\n",
			"names nothing",
		},
		{
			"padded name",
			"schema-version: 1\nprojects:\n  p:\n    GitHub: [\" o/r\"]\n",
			"empty or padded",
		},
		{
			"not YAML at all",
			"\tnot: yaml\n",
			"vuln: table:",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseTable([]byte(c.yaml))
			if err == nil {
				t.Fatalf("accepted %q", c.yaml)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// A valid table of several projects parses, and reports every one of them.
// Without this, every accepting path above is exercised by a one-entry table,
// and a loop that stopped after the first entry would pass.
func TestWholeTableIsChecked(t *testing.T) {
	const y = "schema-version: 1\nprojects:\n  a:\n    GitHub: [o/a]\n  b:\n    cpe: [v:b]\n  c:\n    cpe: [c]\n"
	_, err := ParseTable([]byte(y))
	if err == nil {
		t.Fatal("accepted a table whose THIRD entry has a bare cpe name")
	}
	if !strings.Contains(err.Error(), "c:") {
		t.Errorf("error %q does not name the offending project", err)
	}
}

func TestSourceString(t *testing.T) {
	for _, c := range []struct {
		s    Source
		want string
	}{{SourceDeclared, "declared"}, {SourceDerived, "derived"}, {SourceNone, "none"}} {
		if got := c.s.String(); got != c.want {
			t.Errorf("%d.String() = %q, want %q", c.s, got, c.want)
		}
	}
}

// The allowlist is OSV's list, not a recollection of it. These four were each
// absent from the list I first wrote from memory, or spelled differently.
func TestOSVSpellingsAreOSVs(t *testing.T) {
	for _, db := range []string{"crates.io", "ConanCenter", "SwiftURL", "Homebrew", "vcpkg", "Packagist"} {
		if !knownDBs[db] {
			t.Errorf("%q is a defined OSV ecosystem and is not accepted", db)
		}
	}
	for _, db := range []string{"crates", "conan", "homebrew", "PYPI"} {
		if knownDBs[db] {
			t.Errorf("%q is not how OSV spells it and is accepted", db)
		}
	}
}
