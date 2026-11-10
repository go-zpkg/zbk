package buildscript

import (
	"strings"
	"testing"
)

// ⛔ BINDGEN DOES NOT GO THROUGH THE COMPILER DRIVER.
//
// Everything sovereign about this environment reaches a build through `cc`
// — the shim that re-execs $ZBK_CC — or through $CC. bindgen drives libclang
// in-process, so it sees none of it. Measured on rpm.org/rpm-sequoia
// (go-zpkg/packages run 40498046156): openssl 3.6.4 was found and
// configured correctly, and then
//
//	/pkgx/openssl.org/v3.6.4/include/openssl/asn1.h:27:10:
//	  fatal error: 'stdio.h' file not found
//
// because libclang had no sysroot. bindgen's own lib.rs:260 names this case
// and this variable.
func TestSovereignBuildGivesBindgenTheSysroot(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "cargo build --release\n",
		Deps:       []string{"openssl.org"},
		Target:     linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", PkgxDir: "/opt/pkgx",
		PkgxBin: "/opt/pkgx/bin/pkgx", LibcPkgx: true,
	})
	if !strings.Contains(s, "export BINDGEN_EXTRA_CLANG_ARGS=") {
		t.Fatalf("a sovereign build does not tell bindgen where the headers are:\n%s", s)
	}
	// The sysroot and BOTH -isystem directories: glibc's own headers, and the
	// kernel headers glibc's include. Finding one and not the other fails
	// later and less legibly than finding neither.
	for _, want := range []string{
		`--sysroot="$ZBK_GLIBC_PREFIX"`,
		`-isystem "${ZBK_GLIBC_PREFIX}include"`,
		`-isystem "${ZBK_KHDR_PREFIX}include"`,
	} {
		if !strings.Contains(bindgenLine(t, s), want) {
			t.Errorf("BINDGEN_EXTRA_CLANG_ARGS lacks %s:\n%s", want, bindgenLine(t, s))
		}
	}
	// ⛔ APPENDED, NOT SUBSTITUTED. A recipe naming an extra -I has a reason,
	// and the sysroot is not ours to drop on its behalf.
	if !strings.Contains(bindgenLine(t, s), `${BINDGEN_EXTRA_CLANG_ARGS:-}`) {
		t.Errorf("a recipe's own BINDGEN_EXTRA_CLANG_ARGS is discarded:\n%s", bindgenLine(t, s))
	}
	// ⛔ AND NOT THE LINK FLAGS. bindgen produces no binary; --rtlib and
	// -fuse-ld are options for a step it never runs.
	for _, unwanted := range []string{"--rtlib=", "-fuse-ld=", "-L"} {
		if strings.Contains(bindgenLine(t, s), unwanted) {
			t.Errorf("BINDGEN_EXTRA_CLANG_ARGS carries the link-time %s:\n%s", unwanted, bindgenLine(t, s))
		}
	}
}

// ⛔ THE CONTROL: outside sovereign mode there is no ZBK_GLIBC_PREFIX, so
// exporting the variable would point libclang at an empty sysroot — worse
// than leaving it alone, because an empty --sysroot hides the host's headers
// that a non-sovereign build is entitled to use.
func TestANonSovereignBuildDoesNotSetBindgenArgs(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "cargo build --release\n",
		Deps:       []string{"openssl.org"},
		Target:     linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", PkgxDir: "/opt/pkgx",
		PkgxBin: "/opt/pkgx/bin/pkgx",
	})
	if strings.Contains(s, "BINDGEN_EXTRA_CLANG_ARGS") {
		t.Fatalf("a non-sovereign build sets a sysroot it does not have:\n%s", s)
	}
}

func bindgenLine(t *testing.T, script string) string {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "export BINDGEN_EXTRA_CLANG_ARGS=") {
			return line
		}
	}
	t.Fatalf("no BINDGEN_EXTRA_CLANG_ARGS line in:\n%s", script)
	return ""
}
