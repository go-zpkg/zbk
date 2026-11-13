package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFixShebangs drives the pure-Go rewriter over a battery of sample files and
// asserts it matches upstream fix-shebangs.ts: an absolute interpreter (with
// args) is rewritten to `#!/usr/bin/env <basename>` (args dropped, body + mode
// preserved), while env/sh shebangs, binaries, no-shebang files, directories
// and missing paths are all left untouched.
func TestFixShebangs(t *testing.T) {
	work := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	script := write("script.py", "#!/opt/pkgx/python.org/v3.11/bin/python3 -u\nprint('hi')\n", 0o755)
	envScript := write("env.py", "#!/usr/bin/env python3\nprint('hi')\n", 0o755)
	shScript := write("plain.sh", "#!/bin/sh\necho hi\n", 0o755)
	binary := write("data.bin", "\x7fELF\x02\x01\x01\x00rest", 0o755)
	noShebang := write("notes.txt", "just some text\nno shebang\n", 0o644)
	shortFile := write("short", "#", 0o644) // < 2 bytes of shebang magic
	oneLine := write("oneliner", "#!/some/abs/bin/perl", 0o755)
	missing := filepath.Join(work, "does-not-exist")
	dir := filepath.Join(work, "adir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	if code := fixShebangs([]string{
		script, envScript, shScript, binary, noShebang, shortFile, oneLine, missing, dir,
	}, &stderr); code != 0 {
		t.Fatalf("fixShebangs code=%d stderr=%q", code, stderr.String())
	}

	assert := func(path, want string) {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s =\n%q\nwant\n%q", filepath.Base(path), got, want)
		}
	}
	assert(script, "#!/usr/bin/env python3\nprint('hi')\n")
	assert(envScript, "#!/usr/bin/env python3\nprint('hi')\n")
	assert(shScript, "#!/bin/sh\necho hi\n")
	assert(binary, "\x7fELF\x02\x01\x01\x00rest")
	assert(noShebang, "just some text\nno shebang\n")
	assert(shortFile, "#")
	assert(oneLine, "#!/usr/bin/env perl\n")
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("missing path should still not exist: %v", err)
	}
	// the rewritten script keeps its executable bit
	if fi, _ := os.Stat(script); fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("rewritten script lost +x: %v", fi.Mode())
	}
}

// TestFixShebangsMalformed proves a shebang whose interpreter is not an absolute
// path is a hard error (non-zero exit + message), matching upstream's thrown
// exception.
func TestFixShebangsMalformed(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("#!python3\nx\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := fixShebangs([]string{bad}, &stderr); code == 0 {
		t.Errorf("expected non-zero for malformed shebang")
	}
	if !strings.Contains(stderr.String(), "cannot parse shebang") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestFixShebangsReadError covers the read-failure branch: a file that stats as
// a regular file but cannot be read is skipped, not treated as an error.
func TestFixShebangsReadError(t *testing.T) {
	defer func() { fsReadFile = os.ReadFile }()
	fsReadFile = func(string) ([]byte, error) { return nil, errBoomFix }
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("#!/abs/perl\nx\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := fixShebangs([]string{p}, &stderr); code != 0 {
		t.Errorf("read error should be skipped: code=%d stderr=%q", code, stderr.String())
	}
}

// TestFixShebangsWriteError covers the write-failure branch: a rewrite that
// cannot be persisted is a hard error.
func TestFixShebangsWriteError(t *testing.T) {
	defer func() { fsWriteFile = os.WriteFile }()
	fsWriteFile = func(string, []byte, os.FileMode) error { return errBoomFix }
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("#!/abs/perl\nx\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := fixShebangs([]string{p}, &stderr); code == 0 {
		t.Errorf("write error should be a hard error")
	}
	if !errors.Is(errBoomFix, errBoomFix) || !strings.Contains(stderr.String(), "boom") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestMainMultiCallDispatch proves that when bk is invoked under the shim name
// (argv[0] basename == fix-shebangs.ts), main() routes to fixShebangs rather
// than the normal CLI.
func TestMainMultiCallDispatch(t *testing.T) {
	oldExit, oldArgs := osExit, os.Args
	defer func() { osExit, os.Args = oldExit, oldArgs }()

	got := -1
	osExit = func(c int) { got = c }

	// a regular file with an absolute interpreter → rewritten, exit 0
	p := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(p, []byte("#!/abs/bin/perl\ncode\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"/build/libexec/fix-shebangs.ts", p}
	main()
	if got != 0 {
		t.Fatalf("dispatch exit = %d, want 0", got)
	}
	body, _ := os.ReadFile(p)
	if string(body) != "#!/usr/bin/env perl\ncode\n" {
		t.Errorf("shim did not rewrite via dispatch: %q", body)
	}
}

var errBoomFix = errors.New("boom")
