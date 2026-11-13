package buildscript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

func wasiTgt() target.Target {
	return target.Target{Platform: "wasip1", Arch: "wasm", Triple: "wasm32-wasip1"}
}

// TestWrapWasip1C: a wasip1 target takes OUR toolchain — llvm.org, the wasi-libc
// sysroot and the compiler-rt builtins, whatever the host — and the stencil that
// every compiler shim re-execs carries --target, --sysroot and -resource-dir.
func TestWrapWasip1C(t *testing.T) {
	for _, host := range []target.Target{linuxTgt(), {Platform: "darwin", Arch: "aarch64"}} {
		// HasCompiler (a recipe naming its own compiler) must not suppress clang.
		s := Wrap(WrapOptions{
			UserScript: "make", Deps: []string{"gnu.org/gcc"}, HasCompiler: true,
			Target: wasiTgt(), Host: host, Home: "/h", SrcRoot: "/s", LibcZpkgx: true,
		})
		for _, want := range []string{
			`"+llvm.org"`, `"+github.com/WebAssembly/wasi-libc"`, `"+compiler-rt.llvm.org/wasi"`,
			`export ZPKB_CC="clang --target=wasm32-wasip1 --sysroot="$ZPKB_WASI_SYSROOT" -resource-dir="$ZPKB_WASI_RT" -mcpu=lime1 --rtlib=compiler-rt`,
			`export ZPKB_CXX="clang++ --target=wasm32-wasip1`,
			`export CC="${CC:-$ZPKB_CC}" CXX="${CXX:-$ZPKB_CXX}"`,
			`export AR=llvm-ar RANLIB=llvm-ranlib NM=llvm-nm STRIP=llvm-strip`,
			`$ZPKG_DIR/github.com/WebAssembly/wasi-libc/v[0-9]*`,
			`$ZPKG_DIR/compiler-rt.llvm.org/wasi/v[0-9]*`,
			`the wasip1 toolchain is not installed`,
			// C++: libc++ is its own bottle, named only when installed
			`$ZPKG_DIR/libcxx.llvm.org/wasi/v[0-9]*`,
			`${ZPKB_WASI_CXX:+ -fno-exceptions -stdlib=libc++ -nostdinc++ -isystem $ZPKB_WASI_CXX/include/wasm32-wasip1/c++/v1 -L$ZPKB_WASI_CXX/lib/wasm32-wasip1}`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("host %s: missing %q:\n%s", host.Platform, want, s)
			}
		}
		// the HOST's sovereign libc must not leak into a wasm compile
		for _, bad := range []string{"ZPKB_GLIBC_PREFIX", "-fPIC", "--dynamic-linker", "LDFLAGS", "-pie", "glibc", "linux-headers"} {
			if strings.Contains(s, bad) {
				t.Errorf("host %s: wasip1 target got %q:\n%s", host.Platform, bad, s)
			}
		}
	}
}

// TestWriteLibexecForWasip1: the compiler shims exist for a wasip1 target even
// without --libc=pkgx, and carry the triple-prefixed spelling autoconf looks for.
func TestWriteLibexecForWasip1(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLibexecFor(dir, false, "wasm32-wasip1", "wasip1", "wasm"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"cc", "gcc", "clang", "clang++", "wasm32-wasip1-clang", "wasm32-wasip1-gcc"} {
		if fi, err := os.Lstat(filepath.Join(dir, n)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s: %v (want a symlink to bk)", n, err)
		}
	}
}
