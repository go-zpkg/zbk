package build

import (
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

// `provides:` comes in TWO shapes, and a reader that knows one of them
// reports nothing for the other instead of failing. providedBins, which
// looks for a self-dependency's binary on the host, handles only the flat
// list — correctly, because there the platform is already decided.
//
// A catalogue is built FOR a platform, and podman on linux provides a
// different set from podman on darwin.
func TestProvidedCommandsReadsBothShapes(t *testing.T) {
	linux := target.Target{Platform: "linux", Arch: "x86-64"}
	darwin := target.Target{Platform: "darwin", Arch: "aarch64"}

	flat := []any{"bin/jq", "lib/libjq.so", "bin/jq-dbg"}
	if got := strings.Join(ProvidedCommands(flat, linux), " "); got != "jq jq-dbg" {
		t.Errorf("flat list = %q, want \"jq jq-dbg\" (and no lib/)", got)
	}
	// The same answer on every platform: a flat list is not platform-keyed.
	if got := strings.Join(ProvidedCommands(flat, darwin), " "); got != "jq jq-dbg" {
		t.Errorf("flat list on darwin = %q", got)
	}

	// THE SHAPE THAT WAS INVISIBLE.
	keyed := map[string]any{
		"linux":  []any{"bin/podman", "bin/podman-remote"},
		"darwin": []any{"bin/podman", "bin/podman-remote", "bin/podman-mac-helper"},
	}
	if got := strings.Join(ProvidedCommands(keyed, linux), " "); got != "podman podman-remote" {
		t.Errorf("keyed on linux = %q", got)
	}
	if got := strings.Join(ProvidedCommands(keyed, darwin), " "); got != "podman podman-mac-helper podman-remote" {
		t.Errorf("keyed on darwin = %q", got)
	}

	// A platform with no entry provides nothing, which is the truth and
	// not an error: grpc.io lists darwin only.
	only := map[string]any{"darwin": []any{"bin/grpc_cli"}}
	if got := ProvidedCommands(only, linux); len(got) != 0 {
		t.Errorf("a darwin-only recipe provides %v on linux", got)
	}

	// Arch-qualified keys narrow further.
	arched := map[string]any{
		"darwin/aarch64": []any{"bin/only-on-apple-silicon"},
		"darwin/x86-64":  []any{"bin/only-on-intel"},
	}
	if got := strings.Join(ProvidedCommands(arched, darwin), " "); got != "only-on-apple-silicon" {
		t.Errorf("arch-keyed = %q", got)
	}
}

// Sorted and deduplicated, because the catalogue is published and compared:
// the same recipe must give byte-identical output on two runs, and a map
// iterates in a different order every time.
func TestProvidedCommandsIsSortedAndDeduplicated(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	in := map[string]any{
		"linux":          []any{"bin/zzz", "bin/aaa", "bin/mmm"},
		"linux/x86-64":   []any{"bin/aaa", "bin/bbb"},
		"darwin":         []any{"bin/not-here"},
		"not-a-platform": []any{"bin/ignored"},
	}
	want := "aaa bbb mmm zzz"
	for i := 0; i < 20; i++ {
		if got := strings.Join(ProvidedCommands(in, tgt), " "); got != want {
			t.Fatalf("run %d = %q, want %q", i, got, want)
		}
	}
}

func TestProvidedCommandsOnJunk(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	for name, in := range map[string]any{
		"nil":           nil,
		"a string":      "bin/jq",
		"numbers":       []any{42, "bin/ok"},
		"an empty bin/": []any{"bin/"},
		"a nested map":  map[string]any{"linux": map[string]any{"bin/x": true}},
	} {
		got := ProvidedCommands(in, tgt)
		if name == "numbers" {
			if strings.Join(got, " ") != "ok" {
				t.Errorf("%s = %v, want the one readable entry", name, got)
			}
			continue
		}
		if len(got) != 0 {
			t.Errorf("%s = %v, want nothing", name, got)
		}
	}
}
