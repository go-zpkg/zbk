package target

import (
	"strings"
	"testing"
)

// TestWasip1Target: ZBK_TARGET=wasip1/wasm resolves to the cross triple
// wasm32-wasip1 and the bottle slug wasip1/wasm.
func TestWasip1Target(t *testing.T) {
	t.Setenv("ZBK_TARGET", "wasip1/wasm")
	tgt, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}
	if tgt.Slug() != "wasip1/wasm" || tgt.Triple != "wasm32-wasip1" {
		t.Errorf("got slug %q triple %q", tgt.Slug(), tgt.Triple)
	}
	if !tgt.Cross() {
		t.Error("wasip1/wasm must be a cross build on every host bk runs on")
	}
	// the "+" spelling too
	t.Setenv("ZBK_TARGET", "wasip1+wasm")
	if tgt, err = Resolve(); err != nil || tgt.Slug() != "wasip1/wasm" {
		t.Errorf("wasip1+wasm: %+v, %v", tgt, err)
	}
}

// TestWasmIsAnArchOfWasip1Only: arch validation is per platform. wasm must not
// become valid for linux, nor x86-64 for wasip1.
func TestWasmIsAnArchOfWasip1Only(t *testing.T) {
	for _, bad := range []string{"linux/wasm", "darwin/wasm", "windows/wasm", "wasip1/x86-64", "wasip1/aarch64", "wasip1/s390x"} {
		t.Setenv("ZBK_TARGET", bad)
		if _, _, _, err := Override(); err == nil {
			t.Errorf("%s accepted", bad)
		} else if !strings.Contains(err.Error(), "unsupported target arch") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	for _, good := range []string{"linux/x86-64", "linux/s390x", "windows/aarch64", "darwin/aarch64", "wasip1/wasm"} {
		t.Setenv("ZBK_TARGET", good)
		if _, _, ok, err := Override(); err != nil || !ok {
			t.Errorf("%s refused: %v", good, err)
		}
	}
}

// TestVocabularyListsAreSortedAndComplete: build derives its recipe-key regexp
// from these lists, so they must name every platform and arch exactly once.
// ⛔ THE BSDs BELONG HERE BECAUSE THE REGEXP IS THE POINT. A platform absent
// from this vocabulary turns a recipe's `freebsd:` block into a DEPENDENCY on
// a project called "freebsd" — bottle says exactly that at pkgx.go:1563, and
// bottle has listed these three since before any bottle existed for them. bk
// not listing them was the two halves disagreeing about what a recipe key
// means.
func TestVocabularyListsAreSortedAndComplete(t *testing.T) {
	wantP := []string{"darwin", "freebsd", "linux", "netbsd", "openbsd", "wasip1", "windows"}
	wantA := []string{"aarch64", "s390x", "wasm", "x86-64"}
	for _, c := range []struct {
		name      string
		got, want []string
	}{{"Platforms", Platforms(), wantP}, {"Arches", Arches(), wantA}} {
		if strings.Join(c.got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s() = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestWasip1Vocabulary(t *testing.T) {
	if !IsPlatform("wasip1") || !IsArch("wasm") {
		t.Error("recipe vocabulary must know wasip1 and wasm")
	}
	if IsPair("linux", "wasm") || !IsPair("wasip1", "wasm") {
		t.Error("IsPair wrong for wasm")
	}
	if got := nativeTripleFor("wasip1", "wasm"); got != "wasm32-wasip1" {
		t.Errorf("nativeTripleFor(wasip1) = %q", got)
	}
}
