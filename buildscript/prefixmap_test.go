package buildscript

import (
	"strings"
	"testing"
)

func TestPrefixMapFor(t *testing.T) {
	root := "/Users/runner/Library/Caches/brewkit"
	got, err := PrefixMapFor(root, root+"/darwin+aarch64/p/v1/build", root+"/darwin+aarch64/p/v1")
	if err != nil || got != root+"=/build" {
		t.Fatalf("got %q, %v", got, err)
	}
	// The value follows the root it is given: a hardcoded string would pass the
	// case above and fail this one.
	got, err = PrefixMapFor("/home/runner/.local/share/brewkit", "/home/runner/.local/share/brewkit/x")
	if err != nil || got != "/home/runner/.local/share/brewkit=/build" {
		t.Fatalf("linux root: got %q, %v", got, err)
	}
	// Refusals: a map that could not match is an error, never a silent no-op.
	for name, c := range map[string]struct {
		root string
		dirs []string
	}{
		"empty root":     {"", nil},
		"relative root":  {"brewkit", nil},
		"filesystem /":   {"/", nil},
		"equals in root": {"/a=b", nil},
		"dir outside":    {root, []string{"/elsewhere/build"}},
		"sibling prefix": {root, []string{root + "-other/build"}},
	} {
		if _, err := PrefixMapFor(c.root, c.dirs...); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestWrapExportsPrefixMap(t *testing.T) {
	o := WrapOptions{UserScript: "true", Home: "/h", SrcRoot: "/r/b", PrefixMap: "/r=/build"}
	if s := Wrap(o); !strings.Contains(s, "export ZBK_FILE_PREFIX_MAP=\"/r=/build\"\n") {
		t.Errorf("map not exported:\n%s", s)
	}
	o.PrefixMap = ""
	if s := Wrap(o); strings.Contains(s, "ZBK_FILE_PREFIX_MAP") {
		t.Errorf("exported without a map:\n%s", s)
	}
}

// ZBK_OSO_PREFIX is exported for darwin targets only, from the same derived root
// as the prefix map, with a trailing slash so the recorded path becomes relative.
func TestWrapExportsTheOSOPrefixOnDarwinOnly(t *testing.T) {
	o := WrapOptions{UserScript: "true", Home: "/h", SrcRoot: "/r/b", PrefixMap: "/r=/build"}
	o.Target.Platform = "darwin"
	if s := Wrap(o); !strings.Contains(s, "export ZBK_OSO_PREFIX=\"/r/\"\n") {
		t.Errorf("darwin: no OSO prefix:\n%s", s)
	}
	o.Target.Platform = "linux"
	if s := Wrap(o); strings.Contains(s, "ZBK_OSO_PREFIX") {
		t.Errorf("linux exports an OSO prefix:\n%s", s)
	}
}

func TestPrefixMapRefusesACommaInTheRoot(t *testing.T) {
	if _, err := PrefixMapFor("/a,b"); err == nil {
		t.Error("a root with a comma cannot be passed through -Wl, and must be refused")
	}
}
