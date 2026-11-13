package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodYML = "dependencies:\n  openssl.org: ^3\nbuild:\n  script: |\n    make PREFIX=${DEST} install\n"

// A recipe Convert must refuse. The schema is the simplest such case and the
// most stable: `provides` is a list of paths, so a number there is not a
// recipe at all, and no future improvement to the converter will make it one.
//
// It used to be MACOSX_DEPLOYMENT_TARGET: 11.0, which the converter has since
// learned to handle — a test whose subject stops being a failure is a test
// that silently stops testing.
const unconvertibleYML = "provides: 123\n"

func writeYML(t *testing.T, dir, proj, body string) string {
	t.Helper()
	d := filepath.Join(dir, "projects", proj)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "package.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// By default it PRINTS, so a conversion can be read before it is believed.
func TestToHCLPrints(t *testing.T) {
	dir := t.TempDir()
	p := writeYML(t, dir, "a.org", goodYML)
	var out, errb bytes.Buffer
	if code := runToHCL([]string{p}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "$${DEST}") {
		t.Errorf("the template sigil must be defused:\n%s", got)
	}
	if !strings.Contains(got, "1 converted, 0 refused") {
		t.Errorf("want a tally:\n%s", got)
	}
	// Nothing written without --write.
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), "package.hcl")); err == nil {
		t.Error("printing must not write")
	}
}

// --write puts the hcl down BEFORE removing the yaml. A directory with neither
// file is a project that has vanished.
func TestToHCLWriteReplacesTheRecipe(t *testing.T) {
	dir := t.TempDir()
	p := writeYML(t, dir, "a.org", goodYML)
	var out, errb bytes.Buffer
	if code := runToHCL([]string{"--write", p}, &out, &errb); code != 0 {
		t.Fatalf("code = %d: %s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), "package.hcl")); err != nil {
		t.Errorf("the hcl must be written: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("the yaml must be gone: %v", err)
	}
}

// A refusal leaves the yaml alone. That is the whole safety of the migration:
// a recipe HCL cannot express keeps the file that can express it.
func TestToHCLRefusalKeepsTheYAML(t *testing.T) {
	dir := t.TempDir()
	p := writeYML(t, dir, "hard.org", unconvertibleYML)
	var out, errb bytes.Buffer
	if code := runToHCL([]string{"--write", p}, &out, &errb); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "hard.org") {
		t.Errorf("the refusal must name the recipe: %q", errb.String())
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("a refused recipe must keep its yaml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), "package.hcl")); err == nil {
		t.Error("and must not leave a half-converted hcl behind")
	}
}

// --dir walks a checkout, and reports both tallies rather than stopping at the
// first refusal: the useful output of a migration is which ones did not go.
func TestToHCLDirConvertsWhatItCan(t *testing.T) {
	dir := t.TempDir()
	writeYML(t, dir, "a.org", goodYML)
	writeYML(t, dir, "b.org", goodYML)
	writeYML(t, dir, "hard.org", unconvertibleYML)
	var out, errb bytes.Buffer
	code := runToHCL([]string{"--dir", dir, "--write"}, &out, &errb)
	if code != 1 {
		t.Fatalf("code = %d, want 1 — one was refused", code)
	}
	if !strings.Contains(out.String(), "2 converted, 1 refused") {
		t.Errorf("want both tallies:\n%s", out.String())
	}
}

// An unreadable file is reported, not skipped silently.
func TestToHCLUnreadableFile(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runToHCL([]string{filepath.Join(t.TempDir(), "gone.yml")}, &out, &errb); code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "gone.yml") {
		t.Errorf("the missing file must be named: %q", errb.String())
	}
}

func TestToHCLNeedsSomethingToDo(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runToHCL(nil, &out, &errb); code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "--dir") {
		t.Errorf("the refusal must say how: %q", errb.String())
	}
	if code := runToHCL([]string{"--nope"}, &out, &errb); code != 2 {
		t.Errorf("flag error code = %d, want 2", code)
	}
}

func TestToHCLDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"tohcl"}, &out, &errb); code != 2 {
		t.Errorf("code = %d, want the usage refusal", code)
	}
	if !strings.Contains(errb.String(), "--dir") {
		t.Errorf("want the tohcl usage, got %q", errb.String())
	}
}

// The write and the remove are ordered so a recipe directory is never left
// with neither file. An ordering is only worth having if both halves fail
// safely, so both are made to fail.
func TestToHCLWriteFailureKeepsTheYAML(t *testing.T) {
	dir := t.TempDir()
	p := writeYML(t, dir, "a.org", goodYML)
	old := toHCLWriteFile
	t.Cleanup(func() { toHCLWriteFile = old })
	toHCLWriteFile = func(string, []byte, os.FileMode) error { return os.ErrPermission }

	var out, errb bytes.Buffer
	if code := runToHCL([]string{"--write", p}, &out, &errb); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("the yaml must survive a failed write: %v", err)
	}
}

func TestToHCLRemoveFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	p := writeYML(t, dir, "a.org", goodYML)
	old := toHCLRemove
	t.Cleanup(func() { toHCLRemove = old })
	toHCLRemove = func(string) error { return os.ErrPermission }

	var out, errb bytes.Buffer
	if code := runToHCL([]string{"--write", p}, &out, &errb); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	// The hcl IS there — a recipe with both files is readable, and
	// recipefile.Load prefers the hcl — but the failure is still said, because
	// a leftover yaml is a half-finished migration somebody has to finish.
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), "package.hcl")); err != nil {
		t.Errorf("the hcl must be on disk: %v", err)
	}
	if !strings.Contains(errb.String(), "package.yml") {
		t.Errorf("the failure must be reported: %q", errb.String())
	}
}
