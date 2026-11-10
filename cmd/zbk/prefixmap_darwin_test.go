//go:build darwin

package main

import (
	"bytes"
	"debug/macho"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ld64 writes the debug map (OSO stabs: N_OSO = 0x66) itself, so
// -ffile-prefix-map never reaches it. This links for real, with the shim, and
// reads the stabs back with debug/macho.
func TestCCShimRealLinkNormalisesTheDebugMap(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("no cc")
	}
	root := t.TempDir()
	build := filepath.Join(root, "darwin+aarch64", "p", "v1", "build")
	if err := os.MkdirAll(build, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(build, "main.c")
	if err := os.WriteFile(src, []byte("int main(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	osos := func(withFlag bool) []string {
		t.Setenv("ZBK_CC", "")
		t.Setenv(prefixMapEnv, "")
		t.Setenv(osoPrefixEnv, "")
		if withFlag {
			t.Setenv(osoPrefixEnv, root+"/")
		}
		obj := filepath.Join(build, "main.o")
		exe := filepath.Join(build, "main")
		var errb bytes.Buffer
		if code := ccShim("cc", []string{"-g", "-c", src, "-o", obj}, &errb); code != 0 {
			t.Fatalf("compile: %s", errb.String())
		}
		if code := ccShim("cc", []string{"-g", obj, "-o", exe}, &errb); code != 0 {
			t.Fatalf("link: %s", errb.String())
		}
		f, err := macho.Open(exe)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var out []string
		for _, s := range f.Symtab.Syms {
			if s.Type == 0x66 { // N_OSO
				out = append(out, s.Name)
			}
		}
		return out
	}
	before := osos(false)
	if len(before) == 0 {
		t.Fatal("control failed: the debug map is empty before the flag, so nothing below could mean anything")
	}
	if !strings.Contains(strings.Join(before, " "), root) {
		t.Fatalf("control failed: OSO entries %v do not carry the root %q before the flag", before, root)
	}
	after := osos(true)
	if len(after) != len(before) {
		t.Fatalf("debug map changed size: %d -> %d (it must be kept)", len(before), len(after))
	}
	if strings.Contains(strings.Join(after, " "), root) {
		t.Fatalf("OSO entries still carry the root: %v", after)
	}
	if !strings.HasSuffix(after[0], "main.o") {
		t.Errorf("OSO entry lost its object name: %v", after)
	}
}
