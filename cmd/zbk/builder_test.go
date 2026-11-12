package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/bottlepkg"
	"github.com/go-zpkg/zbk/build"
)

// fakeStage replaces the four bottle seams with an in-memory registry that
// materialises a plausible glibc/bash/tool layout under zpkgDir.
func fakeStage(t *testing.T) *stageCalls {
	t.Helper()
	calls := &stageCalls{}
	oldR, oldI, oldL, oldS := resolveClosureFor, installFor, findLoaderFor, stubBinsStaged
	t.Cleanup(func() {
		resolveClosureFor, installFor, findLoaderFor, stubBinsStaged = oldR, oldI, oldL, oldS
	})

	closure := []bottle.Resolved{
		{Project: bottle.GlibcProject, Version: bottle.ParseVer("2.44.0")},
		{Project: "gnu.org/bash", Version: bottle.ParseVer("5.3")},
	}
	resolveClosureFor = func(roots map[string]string, osn, arch string) ([]bottle.Resolved, error) {
		calls.resolvedFor = osn + "/" + arch
		calls.roots = roots
		return closure, nil
	}
	installFor = func(r bottle.Resolved, zpkgDir, osn, arch string) (bool, error) {
		calls.installed = append(calls.installed, r.Project)
		calls.installedFor = osn + "/" + arch
		// Lay the files down so the later steps have something real to find.
		libDir := filepath.Join(zpkgDir, r.Project, "v"+r.Version.Raw, "lib", "glibc-2.44")
		binDir := filepath.Join(zpkgDir, r.Project, "v"+r.Version.Raw, "bin")
		for _, d := range []string{libDir, binDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return false, err
			}
		}
		if r.Project == "gnu.org/bash" {
			if err := os.WriteFile(filepath.Join(binDir, "bash"), []byte("x"), 0o755); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	findLoaderFor = func(zpkgDir, arch string) string {
		calls.loaderArch = arch
		return filepath.Join(zpkgDir, bottle.GlibcProject, "v2.44.0", "lib", "glibc-2.44", bottle.LoaderNameFor(arch))
	}
	stubBinsStaged = func(clo []bottle.Resolved, s bottle.Stage) (int, error) {
		calls.stage = s
		return len(clo), nil
	}
	return calls
}

type stageCalls struct {
	resolvedFor  string
	installedFor string
	loaderArch   string
	roots        map[string]string
	installed    []string
	stage        bottle.Stage
}

func stageOpts(root string) stageOptions {
	return stageOptions{
		Root: root, OS: "linux", Arch: "aarch64",
		Roots: map[string]string{"gnu.org/glibc": "*"},
		Log:   func(string) {},
	}
}

// TestStageBuilderTargetsTheRequestedPlatform: every step must be told the
// TARGET's slug. Staging a linux/aarch64 rootfs from a darwin host through the
// host's slug is the failure this whole path exists to avoid.
func TestStageBuilderTargetsTheRequestedPlatform(t *testing.T) {
	calls := fakeStage(t)
	root := t.TempDir()

	if err := stageBuilder(stageOpts(root)); err != nil {
		t.Fatal(err)
	}

	if calls.resolvedFor != "linux/aarch64" || calls.installedFor != "linux/aarch64" {
		t.Errorf("resolved for %q, installed for %q; want linux/aarch64 both", calls.resolvedFor, calls.installedFor)
	}
	if calls.loaderArch != "aarch64" {
		t.Errorf("looked for the %q loader", calls.loaderArch)
	}
	if calls.stage.OS != "linux" || calls.stage.Arch != "aarch64" {
		t.Errorf("stubs staged for %s/%s", calls.stage.OS, calls.stage.Arch)
	}
}

// TestStageBuilderPosesGuestPaths: the symlinks a scratch rootfs lives by must
// point where the GUEST will look, never into the staging directory.
func TestStageBuilderPosesGuestPaths(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()

	if err := stageBuilder(stageOpts(root)); err != nil {
		t.Fatal(err)
	}

	loader, err := os.Readlink(filepath.Join(root, "lib", "ld-linux-aarch64.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loader, guestZpkgDir+"/") {
		t.Errorf("/lib loader -> %q, want a %s path", loader, guestZpkgDir)
	}
	if strings.Contains(loader, root) {
		t.Errorf("/lib loader leaks the staging root: %q", loader)
	}
	sh, err := os.Readlink(filepath.Join(root, "bin", "sh"))
	if err != nil {
		t.Fatal(err)
	}
	if sh != guestZpkgDir+"/gnu.org/bash/v5.3/bin/bash" {
		t.Errorf("/bin/sh -> %q", sh)
	}
}

// TestStageBuilderStubsIntoUsr, not /usr/local: bk builds under a sanitised
// PATH that lists /usr/bin and /bin only, so a stub anywhere else is a stub the
// build cannot call.
func TestStageBuilderStubsIntoUsr(t *testing.T) {
	calls := fakeStage(t)
	root := t.TempDir()

	if err := stageBuilder(stageOpts(root)); err != nil {
		t.Fatal(err)
	}

	if want := filepath.Join(root, "usr"); calls.stage.Prefix != want {
		t.Errorf("stub prefix = %q, want %q", calls.stage.Prefix, want)
	}
	if calls.stage.GuestDir != guestZpkgDir {
		t.Errorf("stubs bake %q, want %q", calls.stage.GuestDir, guestZpkgDir)
	}
	if want := filepath.Join(root, "pkgx"); calls.stage.Dir != want {
		t.Errorf("stubs read from %q, want %q", calls.stage.Dir, want)
	}
}

// TestStageBuilderMakesWritableDirs: a build writes. /tmp missing is not a
// subtle failure, but it is a late one — the first recipe that calls mktemp.
func TestStageBuilderMakesWritableDirs(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()

	if err := stageBuilder(stageOpts(root)); err != nil {
		t.Fatal(err)
	}

	for _, d := range []string{"tmp", "var/tmp"} {
		st, err := os.Stat(filepath.Join(root, d))
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if st.Mode().Perm()&0o777 != 0o777 || st.Mode()&os.ModeSticky == 0 {
			t.Errorf("%s has mode %v, want 1777", d, st.Mode())
		}
	}
	if _, err := os.Stat(filepath.Join(root, "root")); err != nil {
		t.Errorf("no /root: %v", err)
	}
}

// TestStageBuilderInstallsBinaries checks the two drivers land where the
// entrypoint expects them, executable.
func TestStageBuilderInstallsBinaries(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	src := filepath.Join(t.TempDir(), "bk")
	if err := os.WriteFile(src, []byte("ELF-ish"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := stageOpts(root)
	o.BkBin = src

	if err := stageBuilder(o); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(root, "usr", "local", "bin", "zbk")
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o111 == 0 {
		t.Errorf("%s is not executable: %v", dst, st.Mode())
	}
	b, _ := os.ReadFile(dst)
	if string(b) != "ELF-ish" {
		t.Errorf("copied %q", b)
	}
}

// TestStageBuilderErrors covers each step's failure surfacing with its own
// message, rather than a bare "no such file" three layers down.
func TestStageBuilderErrors(t *testing.T) {
	t.Run("resolve", func(t *testing.T) {
		fakeStage(t)
		resolveClosureFor = func(map[string]string, string, string) ([]bottle.Resolved, error) {
			return nil, errors.New("boom")
		}
		if err := stageBuilder(stageOpts(t.TempDir())); err == nil || !strings.Contains(err.Error(), "resolve closure") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("install", func(t *testing.T) {
		fakeStage(t)
		installFor = func(bottle.Resolved, string, string, string) (bool, error) {
			return false, errors.New("boom")
		}
		if err := stageBuilder(stageOpts(t.TempDir())); err == nil || !strings.Contains(err.Error(), "install ") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no loader", func(t *testing.T) {
		fakeStage(t)
		findLoaderFor = func(string, string) string { return "" }
		err := stageBuilder(stageOpts(t.TempDir()))
		if err == nil || !strings.Contains(err.Error(), "loader") {
			t.Fatalf("got %v", err)
		}
		// The message must say what to DO about it.
		if !strings.Contains(err.Error(), "gnu.org/glibc") {
			t.Errorf("message does not name the missing package: %v", err)
		}
	})
	t.Run("stubs", func(t *testing.T) {
		fakeStage(t)
		stubBinsStaged = func([]bottle.Resolved, bottle.Stage) (int, error) {
			return 0, errors.New("boom")
		}
		if err := stageBuilder(stageOpts(t.TempDir())); err == nil || !strings.Contains(err.Error(), "stub binaries") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing binary", func(t *testing.T) {
		fakeStage(t)
		o := stageOpts(t.TempDir())
		o.BkBin = filepath.Join(t.TempDir(), "absent")
		if err := stageBuilder(o); err == nil || !strings.Contains(err.Error(), "install zbk") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unwritable rootfs", func(t *testing.T) {
		fakeStage(t)
		root := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(root, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := stageBuilder(stageOpts(root)); err == nil {
			t.Fatal("staging into a regular file must fail")
		}
	})
}

// TestMicroVMConfigIsBootable is what makes a staged directory runnable with no
// registry at all: weft's Pull treats this file as its "already materialised"
// sentinel.
func TestMicroVMConfigIsBootable(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	o := stageOpts(root)
	o.MicroVM = true
	o.Dist = "oci://ghcr.io/go-zpkg/packages"
	o.Overlay = "https://example.invalid/projects"

	if err := stageBuilder(o); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(root, ".weft-microvm", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg microVMConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Process.Args) != 1 || cfg.Process.Args[0] != "/usr/local/bin/zbk" {
		t.Errorf("args = %v", cfg.Process.Args)
	}
	env := strings.Join(cfg.Process.Env, "\n")
	// The guest's init execs these args VERBATIM — no pkgx wrapper composes
	// the environment the way a container ENTRYPOINT did. Without an explicit
	// LD_LIBRARY_PATH the first thing that happens in the guest is /bin/sh
	// failing to find libc.so.6.
	if !strings.Contains(env, "LD_LIBRARY_PATH="+guestZpkgDir+"/") {
		t.Errorf("no guest LD_LIBRARY_PATH:\n%s", env)
	}
	if strings.Contains(env, root) {
		t.Errorf("env leaks the staging root:\n%s", env)
	}
	for _, want := range []string{"ZPKG_DIR=" + guestZpkgDir, "ZPKG_DIST=oci://", "ZPKG_PANTRY_OVERLAY=https://", "HOME=/root", "TMPDIR=/tmp"} {
		if !strings.Contains(env, want) {
			t.Errorf("env missing %q:\n%s", want, env)
		}
	}
	if cfg.Process.Cwd != "/" {
		t.Errorf("cwd = %q", cfg.Process.Cwd)
	}
}

// TestMicroVMConfigOmitsUnsetSources: an empty --dist must not bake an empty
// ZPKG_DIST, which pkgx would read as "no registry".
func TestMicroVMConfigOmitsUnsetSources(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	o := stageOpts(root)
	o.MicroVM = true

	if err := stageBuilder(o); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(filepath.Join(root, ".weft-microvm", "config.json"))
	if strings.Contains(string(b), "ZPKG_DIST=\"") || strings.Contains(string(b), "ZPKG_DIST=\n") {
		t.Errorf("baked an empty ZPKG_DIST:\n%s", b)
	}
	if strings.Contains(string(b), "ZPKG_PANTRY_OVERLAY") {
		t.Errorf("baked an unset overlay:\n%s", b)
	}
}

// TestMicroVMConfigUnwritable surfaces the write failure with its own message.
func TestMicroVMConfigUnwritable(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	// A FILE where .weft-microvm must be a directory.
	if err := os.WriteFile(filepath.Join(root, ".weft-microvm"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	o := stageOpts(root)
	o.MicroVM = true

	if err := stageBuilder(o); err == nil || !strings.Contains(err.Error(), ".weft-microvm/config.json") {
		t.Fatalf("got %v", err)
	}
}

func TestToolchainRootsDefault(t *testing.T) {
	roots, err := toolchainRoots("")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"llvm.org", "gnu.org/glibc", "gnu.org/bash", "kernel.org/linux-headers"} {
		if _, ok := roots[want]; !ok {
			t.Errorf("the built-in toolchain has no %s", want)
		}
	}
}

func TestToolchainRootsFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "toolchain.txt")
	body := "# a comment\n\n" +
		"llvm.org\n" +
		"gnu.org/glibc@^2.40   # trailing comment\n" +
		"perl.org~5.42\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	roots, err := toolchainRoots(p)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{"llvm.org": "*", "gnu.org/glibc": "^2.40", "perl.org": "~5.42"}
	if len(roots) != len(want) {
		t.Fatalf("roots = %v", roots)
	}
	for k, v := range want {
		if roots[k] != v {
			t.Errorf("%s = %q, want %q", k, roots[k], v)
		}
	}
}

func TestToolchainRootsErrors(t *testing.T) {
	if _, err := toolchainRoots(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing toolchain file must fail")
	}
	p := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(p, []byte("# only comments\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := toolchainRoots(p); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty list must fail, got %v", err)
	}
}

func TestSplitToolchainSpec(t *testing.T) {
	for _, tc := range []struct{ in, proj, constraint string }{
		{"llvm.org", "llvm.org", "*"},
		{"gnu.org/glibc@^2.40", "gnu.org/glibc", "^2.40"},
		{"perl.org~5.42", "perl.org", "~5.42"},
		{"llvm.org<19", "llvm.org", "<19"},
		{"x.org=1.2.3", "x.org", "=1.2.3"},
		{"x.org@", "x.org", "*"}, // an @ with nothing after it pins nothing
	} {
		p, c := splitToolchainSpec(tc.in)
		if p != tc.proj || c != tc.constraint {
			t.Errorf("%q -> (%q,%q), want (%q,%q)", tc.in, p, c, tc.proj, tc.constraint)
		}
	}
}

// ⛔⛔ THE ONE PLACE THE GUEST ROOT'S VALUE IS PINNED. Everything else builds
// its expectation from guestZpkgDir, which is right — those tests are about
// what uses the root, not about what it is called. But if NOTHING asserts the
// value, the constant can drift back with a green suite, and the whole reason
// it moved is that upstream's name had been deciding it.
//
// Our prefix is zpkg: the user store is ~/.zpkg (bottle.Dir), the environment
// variable is ZPKG_DIR, and the guest root inside the build container is the
// last thing that said otherwise. It carries no x: this is the STORE, like
// ZPKG_DIR, not the zpkgx runtime.
func TestTheGuestRootIsZpkg(t *testing.T) {
	if guestZpkgDir != "/zpkg" {
		t.Errorf("guestZpkgDir = %q, want /zpkg", guestZpkgDir)
	}
	if strings.Contains(guestZpkgDir, "pkgx") {
		t.Errorf("guestZpkgDir = %q still carries upstream's name", guestZpkgDir)
	}
}

func TestGuestPath(t *testing.T) {
	// ⛔ THE EXPECTATION IS BUILT FROM guestZpkgDir, NOT FROM ITS VALUE. This
	// test hardcoded "/pkgx" and went red when the guest root moved to
	// "/zpkg" — which told me nothing about guestPath, only that someone had
	// changed a constant. What it is actually about is that the staging root
	// is REPLACED by the guest root; TestTheGuestRootIsZpkg below is where
	// the value itself is pinned, once, on purpose.
	dir := "/stage/store"
	if got := guestPath(dir+"/gnu.org/bash/v5.3/bin/bash", dir); got != guestZpkgDir+"/gnu.org/bash/v5.3/bin/bash" {
		t.Errorf("got %q", got)
	}
	if got := guestPath("", dir); got != "" {
		t.Errorf("an absent optional became %q", got)
	}
	// A path outside the staging dir is not ours to rewrite.
	if got := guestPath("/elsewhere/bin/bash", dir); got != "/elsewhere/bin/bash" {
		t.Errorf("rewrote a foreign path to %q", got)
	}
}

func TestRunBuilderUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runBuilder(nil, &out, &errb); code != 2 {
		t.Errorf("no --out: exit %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "--out") {
		t.Errorf("usage does not mention --out: %q", errb.String())
	}
	errb.Reset()
	if code := runBuilder([]string{"--out", t.TempDir(), "--platform", "darwin/aarch64"}, &out, &errb); code != 2 {
		t.Errorf("darwin: exit %d, want 2", code)
	}
	errb.Reset()
	if code := runBuilder([]string{"--nonsuch"}, &out, &errb); code != 2 {
		t.Errorf("bad flag: exit %d, want 2", code)
	}
}

func TestRunBuilderStages(t *testing.T) {
	calls := fakeStage(t)
	root := filepath.Join(t.TempDir(), "rootfs")
	tc := filepath.Join(t.TempDir(), "toolchain.txt")
	if err := os.WriteFile(tc, []byte("gnu.org/glibc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer

	code := runBuilder([]string{
		"--out", root, "--platform", "linux/x86-64", "--toolchain", tc,
		"--dist", "oci://example.invalid/pkgs", "--overlay", "https://example.invalid/p",
	}, &out, &errb)

	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if calls.resolvedFor != "linux/x86-64" {
		t.Errorf("resolved for %q", calls.resolvedFor)
	}
	if _, ok := calls.roots["gnu.org/glibc"]; !ok || len(calls.roots) != 1 {
		t.Errorf("roots = %v, want only the file's entry", calls.roots)
	}
	if bottle.DistBase != "oci://example.invalid/pkgs" {
		t.Errorf("--dist not applied: %q", bottle.DistBase)
	}
	if !strings.Contains(out.String(), "stubs in /usr/bin") {
		t.Errorf("no progress reported: %q", out.String())
	}
}

func TestRunBuilderReportsStagingFailure(t *testing.T) {
	fakeStage(t)
	resolveClosureFor = func(map[string]string, string, string) ([]bottle.Resolved, error) {
		return nil, errors.New("registry down")
	}
	var out, errb bytes.Buffer

	if code := runBuilder([]string{"--out", t.TempDir()}, &out, &errb); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "registry down") {
		t.Errorf("the cause was swallowed: %q", errb.String())
	}
}

func TestRunBuilderRejectsMissingToolchainFile(t *testing.T) {
	fakeStage(t)
	var out, errb bytes.Buffer
	code := runBuilder([]string{"--out", t.TempDir(), "--toolchain", filepath.Join(t.TempDir(), "absent")}, &out, &errb)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
}

func TestCopyExecutableErrors(t *testing.T) {
	t.Run("missing source", func(t *testing.T) {
		if err := copyExecutable(filepath.Join(t.TempDir(), "absent"), filepath.Join(t.TempDir(), "x")); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("destination dir is a file", func(t *testing.T) {
		root := t.TempDir()
		blocker := filepath.Join(root, "blocked")
		if err := os.WriteFile(blocker, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(root, "src")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := copyExecutable(src, filepath.Join(blocker, "sub", "bk")); err == nil {
			t.Fatal("want a mkdir error")
		}
	})
	t.Run("destination unwritable", func(t *testing.T) {
		// root is not refused by a mode bit, so this case can only be posed to a
		// user that permissions apply to. CI runs as an ordinary user; a VM or a
		// container may not, and there the failure would look like a defect in
		// copyExecutable rather than in the question being asked.
		if os.Geteuid() == 0 {
			t.Skip("running as root: the permission this case relies on does not apply")
		}
		root := t.TempDir()
		src := filepath.Join(root, "src")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "ro")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o755) })
		if err := copyExecutable(src, filepath.Join(dir, "bk")); err == nil {
			t.Fatal("want an open error")
		}
	})
	t.Run("copy fails", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		old := ioCopy
		ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("boom") }
		t.Cleanup(func() { ioCopy = old })
		dst := filepath.Join(root, "bk")
		if err := copyExecutable(src, dst); err == nil {
			t.Fatal("want a copy error")
		}
		// A half-written binary must not survive as if it were whole.
		if _, err := os.Stat(dst + ".tmp"); err == nil {
			t.Error("the partial file was left behind")
		}
	})
	t.Run("close fails", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		old := closeWritten
		closeWritten = func(*os.File) error { return errors.New("boom") }
		t.Cleanup(func() { closeWritten = old })
		dst := filepath.Join(root, "bk")
		if err := copyExecutable(src, dst); err == nil {
			t.Fatal("want a close error")
		}
		if _, err := os.Stat(dst + ".tmp"); err == nil {
			t.Error("the partial file was left behind")
		}
	})
}

func TestMicroVMConfigMarshalFailure(t *testing.T) {
	fakeStage(t)
	old := jsonMarshalIndent
	jsonMarshalIndent = func(any, string, string) ([]byte, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { jsonMarshalIndent = old })
	o := stageOpts(t.TempDir())
	o.MicroVM = true

	if err := stageBuilder(o); err == nil || !strings.Contains(err.Error(), ".weft-microvm/config.json") {
		t.Fatalf("got %v", err)
	}
}

// TestStageBuilderReportsUnwritableDirs: /tmp and friends are created after
// the closure is on disk, so their failure needs its own reachable case.
func TestStageBuilderReportsUnwritableDirs(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	// A FILE named tmp: MkdirAll fails at the very first writable dir.
	if err := os.WriteFile(filepath.Join(root, "tmp"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := stageBuilder(stageOpts(root)); err == nil {
		t.Fatal("want an error when /tmp cannot be created")
	}
}

// TestStageBuilderReportsChmodFailure covers the sticky-bit step on its own.
// Through a seam: a symlink-to-nowhere makes MkdirAll fail FIRST, so the test
// that looked like it covered this actually covered the line above it.
func TestStageBuilderReportsChmodFailure(t *testing.T) {
	fakeStage(t)
	old := osChmod
	osChmod = func(string, os.FileMode) error { return errors.New("boom") }
	t.Cleanup(func() { osChmod = old })

	if err := stageBuilder(stageOpts(t.TempDir())); err == nil {
		t.Fatal("want an error when /tmp cannot be chmod'd")
	}
}

// TestStageBuilderPoseFailure: the loader symlinks land in /lib and /lib64.
func TestStageBuilderPoseFailure(t *testing.T) {
	fakeStage(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "lib"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := stageBuilder(stageOpts(root)); err == nil || !strings.Contains(err.Error(), "pose loader") {
		t.Fatalf("got %v", err)
	}
}

// TestStageBuilderSkipsAlreadyInstalled keeps the "already present" path
// honest: a re-stage into a warm directory must not claim to install again.
func TestStageBuilderSkipsAlreadyInstalled(t *testing.T) {
	fakeStage(t)
	old := installFor
	installFor = func(r bottle.Resolved, zpkgDir, osn, arch string) (bool, error) {
		if _, err := old(r, zpkgDir, osn, arch); err != nil {
			return false, err
		}
		return false, nil // already there
	}
	root := t.TempDir()
	var logged []string

	o := stageOpts(root)
	o.Log = func(s string) { logged = append(logged, s) }
	if err := stageBuilder(o); err != nil {
		t.Fatal(err)
	}

	for _, l := range logged {
		if strings.HasPrefix(l, "  + ") {
			t.Errorf("reported an install that did not happen: %q", l)
		}
	}
}

// TestBuilderIsDispatched: a subcommand nobody routes to is a subcommand that
// does not exist.
func TestBuilderIsDispatched(t *testing.T) {
	code, _, errb := run2(t, "builder")

	if code != 2 {
		t.Fatalf("bk builder: exit %d, want the usage exit 2", code)
	}
	if !strings.Contains(errb, "--out") {
		t.Errorf("dispatched somewhere else: %q", errb)
	}
}

func TestSetCodec(t *testing.T) {
	orig := bottlepkg.Codec
	t.Cleanup(func() { bottlepkg.Codec = orig })

	for _, tc := range []struct{ in, want string }{
		{"gzip", bottle.ExtTarGz},
		{"gz", bottle.ExtTarGz},
		{"zstd", bottle.ExtTarZst},
		{"zst", bottle.ExtTarZst},
	} {
		if err := setCodec(tc.in); err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if bottlepkg.Codec != tc.want {
			t.Errorf("--compress %s → %q, want %q", tc.in, bottlepkg.Codec, tc.want)
		}
	}
	if err := setCodec("brotli"); err == nil {
		t.Error("an unknown codec must be refused, not silently ignored")
	}
}

// TestFactoryRejectsUnknownCompress: the flag is validated before anything is
// built, so a typo costs a message rather than a run.
func TestFactoryRejectsUnknownCompress(t *testing.T) {
	orig := bottlepkg.Codec
	t.Cleanup(func() { bottlepkg.Codec = orig })
	var out, errb bytes.Buffer

	if code := runFactory([]string{"--compress", "brotli", "--platform", "linux/aarch64", "--recipes", "lz4.org", "--pantry", t.TempDir()}, &out, &errb); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "brotli") {
		t.Errorf("the message does not name the bad value: %q", errb.String())
	}
}

// TestToolchainPinsMeanWhatTheySay evaluates each pinned toolchain constraint
// instead of comparing it to a string.
//
// `gnu.org/gawk@5.3` looked like a pin and was not one. A bare version is a
// caret in this resolver, so it means ">=5.3, same major" and ADMITS 5.4.1 —
// the single version the entry exists to exclude. Against the registry it
// resolved to 5.4.1 every time. Nothing noticed for as long as no 5.3.x was
// published for darwin: a pin that cannot be satisfied and a pin that selects
// the wrong thing look identical until the version you meant exists.
//
// A test that asserted the entry equalled "gnu.org/gawk@5.3" would have passed
// throughout. This one asks the resolver.
func TestToolchainPinsMeanWhatTheySay(t *testing.T) {
	constraintFor := func(project string) string {
		t.Helper()
		for _, spec := range build.BaseToolchain() {
			if p, c := splitToolchainSpec(spec); p == project {
				return c
			}
		}
		t.Fatalf("%s is not in the base toolchain: %v", project, build.BaseToolchain())
		return ""
	}
	for _, tc := range []struct {
		project, version string
		want             bool
		why              string
	}{
		{"gnu.org/gawk", "5.3.2", true, "the version the pin exists to select"},
		{"gnu.org/gawk", "5.4.1", false, "collapses libpng's pnglibconf: 175 features off"},
		{"gnu.org/gawk", "5.4.0", false, "same 5.4 line, same regression"},
		{"gnu.org/gawk", "6.0.0", false, "a later major is not what this pin means either"},
		{"perl.org", "5.44.0", true, "the line the XS-bearing tools are built against"},
		{"perl.org", "5.42.3", false, "an XS module refuses to load under another API version"},
	} {
		c := constraintFor(tc.project)
		if got := bottle.ParseVer(tc.version).Satisfies(c); got != tc.want {
			t.Errorf("%s %q satisfied by %s = %v, want %v (%s)",
				tc.project, c, tc.version, got, tc.want, tc.why)
		}
	}
}

// --dry-run is the pre-flight for a lane that costs hours. It must RESOLVE and
// must not INSTALL: an install that happened anyway would write 2 GiB into a
// directory the caller never named.
func TestBuilderDryRunResolvesAndStagesNothing(t *testing.T) {
	calls := fakeStage(t)
	var out, errb bytes.Buffer
	if rc := runBuilder([]string{"--dry-run", "--platform", "linux/s390x"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, errb.String())
	}
	if calls.resolvedFor != "linux/s390x" {
		t.Errorf("resolved for %q, want linux/s390x", calls.resolvedFor)
	}
	if len(calls.installed) != 0 {
		t.Errorf("a dry run installed %v", calls.installed)
	}
	for _, w := range []string{"gnu.org/bash", "2 packages resolve for linux/s390x"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("missing %q in:\n%s", w, out.String())
		}
	}
}

// --out is what a staging run writes into, so a dry run must not demand one —
// the whole point is to ask the question before choosing where to put the
// answer.
func TestBuilderDryRunNeedsNoOutputDirectory(t *testing.T) {
	fakeStage(t)
	var out, errb bytes.Buffer
	if rc := runBuilder([]string{"--dry-run"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d, stderr: %s", rc, errb.String())
	}
	// And a run WITHOUT --dry-run still does.
	var out2, errb2 bytes.Buffer
	if rc := runBuilder(nil, &out2, &errb2); rc != 2 {
		t.Errorf("rc = %d without --out, want 2", rc)
	}
}

// A refusal must name EVERY blocked root. Reporting the first one costs one
// build per gap on an architecture being brought up, which is the whole reason
// this exists.
func TestBuilderDryRunNamesEveryBlockedRoot(t *testing.T) {
	old := resolveClosureFor
	t.Cleanup(func() { resolveClosureFor = old })
	// curl.se and gnu.org/tar have no bottle; everything else does. The joint
	// resolve reports whichever it meets first.
	absent := map[string]bool{"curl.se": true, "gnu.org/tar": true}
	resolveClosureFor = func(roots map[string]string, osn, arch string) ([]bottle.Resolved, error) {
		for p := range roots {
			if absent[p] {
				return nil, fmt.Errorf("no version of %s is published for %s/%s", p, osn, arch)
			}
		}
		return []bottle.Resolved{{Project: "gnu.org/bash", Version: bottle.ParseVer("5.3")}}, nil
	}

	dir := t.TempDir()
	tc := filepath.Join(dir, "toolchain.txt")
	if err := os.WriteFile(tc, []byte("curl.se\ngnu.org/bash\ngnu.org/tar\ngnu.org/sed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if rc := runBuilder([]string{"--dry-run", "--platform", "linux/s390x", "--toolchain", tc}, &out, &errb); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	for _, w := range []string{"BLOCKED curl.se", "BLOCKED gnu.org/tar", "2 of 4 roots cannot resolve"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("missing %q in:\n%s", w, out.String())
		}
	}
	if strings.Contains(out.String(), "BLOCKED gnu.org/bash") || strings.Contains(out.String(), "BLOCKED gnu.org/sed") {
		t.Errorf("a root that resolves was reported blocked:\n%s", out.String())
	}
}

// Every root resolving alone while the set does not is a CONFLICT, and saying
// "0 roots cannot resolve" after refusing would read as a contradiction.
func TestBuilderDryRunDistinguishesAConflictFromAMissingBottle(t *testing.T) {
	old := resolveClosureFor
	t.Cleanup(func() { resolveClosureFor = old })
	resolveClosureFor = func(roots map[string]string, osn, arch string) ([]bottle.Resolved, error) {
		if len(roots) > 1 {
			return nil, fmt.Errorf("demands do not intersect")
		}
		return []bottle.Resolved{{Project: "gnu.org/bash", Version: bottle.ParseVer("5.3")}}, nil
	}
	dir := t.TempDir()
	tc := filepath.Join(dir, "toolchain.txt")
	if err := os.WriteFile(tc, []byte("gnu.org/bash\ngnu.org/sed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if rc := runBuilder([]string{"--dry-run", "--toolchain", tc}, &out, &errb); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(out.String(), "CONFLICT between them") {
		t.Errorf("a conflict was reported as a missing bottle:\n%s", out.String())
	}
}

// Two failures wear one symptom — "no loader" — and they are nothing alike.
//
// On linux/s390x this refused with "is gnu.org/glibc in the toolchain?" while
// gnu.org/glibc was plainly in it and all 42 packages had installed: the
// loader TABLE had no entry for the architecture. The message sent its reader
// to the toolchain file, which was correct, and cost a detour.
func TestBuilderDistinguishesAnUnknownArchFromAMissingGlibc(t *testing.T) {
	for _, tc := range []struct {
		name, arch string
		want       string
		notWant    string
	}{
		{
			// An architecture bottle has no loader name for. ppc64le is a real
			// one: bk is tested on it and builds no bottle for it.
			name: "unknown arch", arch: "ppc64le",
			want:    "no loader name is known for ppc64le",
			notWant: "is gnu.org/glibc in the toolchain",
		},
		{
			// A known arch whose loader is simply not in the tree: the
			// toolchain question is the right one, and the message now names
			// the FILE it looked for.
			name: "known arch, absent file", arch: "aarch64",
			want:    "no aarch64 loader (ld-linux-aarch64.so.1) in the staged glibc",
			notWant: "no loader name is known",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeStage(t)
			_ = calls
			old := findLoaderFor
			findLoaderFor = func(string, string) string { return "" }
			t.Cleanup(func() { findLoaderFor = old })

			var out, errb bytes.Buffer
			rc := runBuilder([]string{"--out", t.TempDir(), "--platform", "linux/" + tc.arch}, &out, &errb)
			if rc != 1 {
				t.Fatalf("rc = %d, want 1", rc)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("missing %q in: %s", tc.want, errb.String())
			}
			if strings.Contains(errb.String(), tc.notWant) {
				t.Errorf("the wrong half of the diagnosis: %q in %s", tc.notWant, errb.String())
			}
		})
	}
}

// "Not found" is a fact about the LOOKUP as much as about the tree, and the
// two readings send a person to different places. The error now carries the
// listing, so a bottle that puts its loader one directory over is told apart
// from one that has none — without a round trip to a runner.
func TestBuilderLoaderErrorListsWhatIsThere(t *testing.T) {
	fakeStage(t)
	old := findLoaderFor
	findLoaderFor = func(string, string) string { return "" }
	t.Cleanup(func() { findLoaderFor = old })

	root := t.TempDir()
	// fakeStage's installFor lays glibc down under lib/glibc-2.44, so the
	// listing has something real to report. Put a loader-shaped file there
	// under the WRONG name: that is the case the listing exists for.
	var out, errb bytes.Buffer
	rc := runBuilder([]string{"--out", root, "--platform", "linux/aarch64"}, &out, &errb)
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	got := errb.String()
	for _, w := range []string{"glibc-2.44", "entr(y/ies)", "ld*:"} {
		if !strings.Contains(got, w) {
			t.Errorf("the error does not carry the listing (%q missing):\n%s", w, got)
		}
	}
}

// Nothing staged at all is its own answer, and it must not read as an empty
// listing — "no gnu.org/glibc directory" is what a caller can act on.
func TestGlibcLayoutWithNothingStaged(t *testing.T) {
	got := glibcLayout(t.TempDir())
	if !strings.Contains(got, "no gnu.org/glibc directory") {
		t.Errorf("got %q", got)
	}
}

// A lib dir that cannot be read is skipped rather than reported as empty: the
// listing is a diagnostic and must not invent a fact.
func TestGlibcLayoutSkipsAnUnreadableDir(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, bottle.GlibcProject, "v2.44.0", "lib")
	if err := os.MkdirAll(filepath.Join(lib, "glibc-2.44"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(lib, "glibc-2.44"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(lib, "glibc-2.44"), 0o755) })
	// As root the mode is advisory: the FreeBSD, NetBSD and OpenBSD lanes run
	// as root, ReadDir succeeds, and "0 entr(y/ies)" is then the TRUTH about
	// that directory rather than an invented fact. Asserting otherwise there
	// would be asserting that root cannot read, which it can.
	// TestSetupScratchRootfsAtReadOnlyDir in go-zpkg/bottle skips for the
	// same reason, in the same words.
	if _, err := os.ReadDir(filepath.Join(lib, "glibc-2.44")); err == nil {
		t.Skip("this filesystem lets root read a mode-000 directory")
	}
	got := glibcLayout(dir)
	if !strings.Contains(got, "glibc-2.44") {
		t.Errorf("the outer listing went missing: %q", got)
	}
	if strings.Contains(got, "0 entr(y/ies)") {
		t.Errorf("an unreadable dir was reported as empty: %q", got)
	}
}

// More entries than the cap: the listing is an error message, not a report.
func TestGlibcLayoutCapsTheListing(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, bottle.GlibcProject, "v2.44.0", "lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(lib, fmt.Sprintf("f%02d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := glibcLayout(dir)
	if !strings.Contains(got, "…") {
		t.Errorf("an unbounded listing went into an error: %q", got)
	}
}

// The case the listing exists for: a loader IS there under another name, so
// "not found" was about the lookup and not about the tree. Naming the ld*
// files turns one round trip to a runner into a glance.
func TestGlibcLayoutNamesTheLoaderFilesItFound(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, bottle.GlibcProject, "v2.44.0", "lib", "glibc-2.44")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ld64.so.1", "libc.so.6", "ld-linux-x86-64.so.2"} {
		if err := os.WriteFile(filepath.Join(sub, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := glibcLayout(dir)
	for _, w := range []string{"ld64.so.1", "ld-linux-x86-64.so.2", "3 entr(y/ies)", "libc.so.6"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in: %s", w, got)
		}
	}
	if strings.Contains(got, "ld*: libc.so.6") {
		t.Errorf("a non-loader file was listed as one: %s", got)
	}
}

// A tree inherited from an earlier run is reused in silence, and the log said
// "42 packages" while installing none of them. Three s390x pilots in a row
// were read as progress on that line.
func TestBuilderSaysWhenItReusesAStagedTree(t *testing.T) {
	calls := fakeStage(t)
	_ = calls
	root := t.TempDir()
	// Pose the closure's prefixes, as a half-finished run leaves them.
	// fakeStage resolves glibc 2.44.0 and bash 5.3.
	for _, p := range []string{
		filepath.Join("pkgx", bottle.GlibcProject, "v2.44.0"),
		filepath.Join("pkgx", "gnu.org/bash", "v5.3"),
	} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var logged []string
	err := stageBuilder(stageOptions{
		Root: root, OS: "linux", Arch: "aarch64",
		Roots: map[string]string{"gnu.org/bash": ""},
		Log:   func(s string) { logged = append(logged, s) },
	})
	// The staging goes on to fail for want of a loader in the posed tree,
	// which is fine: the line under test comes before that.
	_ = err
	joined := strings.Join(logged, "\n")
	for _, w := range []string{"2 of them are ALREADY in", "will not be re-installed"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in:\n%s", w, joined)
		}
	}
}

// A fresh tree says nothing: a line that appears every time is a line nobody
// reads, and "nothing was reused" is the normal case.
func TestBuilderSaysNothingWhenTheTreeIsFresh(t *testing.T) {
	fakeStage(t)
	var logged []string
	_ = stageBuilder(stageOptions{
		Root: t.TempDir(), OS: "linux", Arch: "aarch64",
		Roots: map[string]string{"gnu.org/bash": ""},
		Log:   func(s string) { logged = append(logged, s) },
	})
	if strings.Contains(strings.Join(logged, "\n"), "ALREADY in") {
		t.Errorf("a fresh tree reported a reuse:\n%s", strings.Join(logged, "\n"))
	}
}

// The count alone was not enough, measured the hard way: the s390x tree
// reported "2 entr(y/ies), ld*:" and a real glibc has two hundred. That says
// the bottle is nearly empty and says nothing about WHICH two — the next
// question every time. The names are capped, and the cap is visible.
func TestGlibcLayoutNamesSomeInnerEntriesAndSaysWhenItTruncated(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, bottle.GlibcProject, "v2.44", "lib", "glibc-2.44")
	if err := os.MkdirAll(filepath.Join(sub, "gconv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sub, "audit"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := glibcLayout(dir)
	for _, w := range []string{"2 entr(y/ies)", "audit", "gconv"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in: %s", w, got)
		}
	}
	if strings.Contains(got, "…") {
		t.Errorf("two entries are not a truncation: %s", got)
	}

	for i := 0; i < 12; i++ {
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("x%02d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := glibcLayout(dir); !strings.Contains(got, "…") {
		t.Errorf("fourteen entries were listed without saying so: %s", got)
	}
}
