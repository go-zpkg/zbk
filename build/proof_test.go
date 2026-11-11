package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-zpkg/zbk/target"
)

// TestProofPropsInBuildDir is a focused end-to-end proof: a recipe whose script
// runs `test -f props/iconv.patch` succeeds only because the RecipeDir (which IS
// props/, pkgx-style) was copied into the build tree the wrapped script cd's into.
func TestProofPropsInBuildDir(t *testing.T) {
	tenv(t)
	tgt, _ := target.Resolve()
	project := "gnu.org/tar"

	// iconv.patch sits at the recipe-dir root (like projects/gnu.org/tar/iconv.patch)
	recipeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(recipeDir, "iconv.patch"), []byte("PATCH"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := okRunner(project, tgt)
	r.RecipeDir = recipeDir
	// A real pkgx stub: the generated script now ABORTS when the dependency
	// environment fails (a silent failure used to let a build run on with no
	// deps and die later with something unrelated), so this end-to-end proof
	// has to provide a pkgx that succeeds.
	stub := filepath.Join(t.TempDir(), "pkgx")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.ZpkgxBin = stub
	// really run the generated (wrapped) script under bash, then create the
	// staging dir so the pipeline's rename step still works.
	//
	// bash is looked UP rather than named: this proof is about whether the
	// props reach the build dir, not about where bash lives, and /bin/bash is a
	// Linux and macOS convention — on FreeBSD it is /usr/local/bin/bash when it
	// is installed at all. A test that asserts something about its environment
	// should check it rather than fail as if the code were wrong.
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this host: nothing to run the generated script with")
	}
	// The recipe FIRST: the stub below needs it to ask the same identity
	// question the build asks, and the install prefix depends on the recipe.
	rec := okRecipe()
	rec.Distributable = nil // no fetch; the build dir is created empty by the pipeline
	rec.Dependencies = nil
	rec.Build = map[string]any{"script": []any{"test -f props/iconv.patch"}}

	r.Run = func(scriptPath string, env []string) error {
		cmd := exec.Command(bash, scriptPath)
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		// ⛔ THE PREFIX THE BUILD CHOSE, read off the Runner. It carries
		// the build's identity, so a stub that composed its own path would
		// create a directory the build does not look in — and the failure
		// would read as "the script did not install anything".
		return os.MkdirAll(r.BuildInstall, 0o755)
	}

	if _, err := r.Build(rec, project, "*", tgt, tgt, ""); err != nil {
		t.Fatalf("proof failed - props not visible to script: %v", err)
	}
	t.Log("PROOF OK: `test -f props/iconv.patch` passed inside the build dir")
}
