package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/go-zpkg/zbk/fetch"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// pythonVenvStub is bk's copy of pkgx brewkit's share/brewkit/python-venv-stub.py.
// `bkpyvenv seal` installs it as $PREFIX/bin/<cmd>: at runtime the stub rewrites
// the venv's interpreter shebangs to an absolute in-venv python, (re)creates the
// python symlink + pyvenv.cfg, and re-execs the real entry point inside the venv
// — the mechanism that lets a relocatable python bottle keep working wherever it
// is installed. It is shipped verbatim so behaviour matches upstream exactly.
//
//go:embed python-venv-stub.py
var pythonVenvStub []byte

// Seams. Building a python venv is intrinsically an exec of the packaged runtime
// (`python -m venv`, `poetry …`) — exactly as brewkit does; it is the real build
// action, not shelling-out-for-logic. Routing every process spawn and every
// fallible go-git step through a package var keeps each error branch reachable
// from a test without a real python/poetry/toolchain present.
var (
	pyGetwd  = os.Getwd
	pyRun    = defaultPyRun    // spawn, inheriting stderr; nil on success
	pyOutput = defaultPyOutput // spawn, capture stdout

	// go-git method values, indirected so tests can force each error branch of
	// pyGitInitTag while the happy path exercises real go-git in a temp repo.
	ggPlainInit = gogit.PlainInit
	ggWorktree  = (*gogit.Repository).Worktree
	ggCommit    = (*gogit.Worktree).Commit
	ggHead      = (*gogit.Repository).Head
	ggCreateTag = (*gogit.Repository).CreateTag

	pyGitInitTag = defaultGitInitTag
	pyNow        = time.Now
	pyGlob       = filepath.Glob // seam: filepath.Glob only errors on a bad pattern

	// pyGOOS selects the venv-creation flags; indirected so both the Linux
	// (--copies) and non-Linux branches are reachable on any test host.
	pyGOOS = runtime.GOOS
)

func defaultPyRun(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func defaultPyOutput(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}

// srcRoot is the directory bkpyvenv operates in, matching upstream's
// `cd "$SRCROOT"`: the build tree. It honours $SRCROOT (set by the build
// wrapper) and falls back to the current directory.
func srcRoot() (string, error) {
	if s := os.Getenv("SRCROOT"); s != "" {
		return s, nil
	}
	return pyGetwd()
}

// bkpyvenv is bk's pure-Go port of pkgx brewkit's libexec/bkpyvenv, dispatched
// when the multi-call binary is invoked under the name "bkpyvenv". It builds a
// Python application into a self-contained, relocatable venv under $PREFIX in
// two phases the recipe drives:
//
//	bkpyvenv stage [--engine=poetry] <prefix> <version>
//	    prepare the venv: create a git tag so setuptools-scm can see <version>
//	    (pip engine), then `python -m venv` (Linux: --copies, so the bottle does
//	    not bake an absolute symlink to the build python — pantry#8487) or, for
//	    poetry, enable in-project virtualenvs. The recipe then pip-installs into
//	    $PREFIX/venv between the two phases.
//	bkpyvenv seal [--engine=poetry] <prefix> <cmd>...
//	    for poetry, build an sdist and unpack it into the in-project .venv, then
//	    move it to $PREFIX/venv; finally install the launcher stub as
//	    $PREFIX/bin/<cmd> for each name, with a `zpkgx python@X.Y` shebang.
func bkpyvenv(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: bkpyvenv <stage|seal> [--engine=poetry] <prefix> ...")
		return 2
	}
	cmd := args[0]
	args = args[1:]

	engine := "pip"
	if len(args) > 0 && args[0] == "--engine=poetry" {
		engine = "poetry"
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "bkpyvenv: missing <prefix>")
		return 2
	}
	prefix := args[0]
	args = args[1:]

	root, err := srcRoot()
	if err != nil {
		fmt.Fprintln(stderr, "bkpyvenv:", err)
		return 1
	}

	switch cmd {
	case "stage":
		if len(args) == 0 {
			fmt.Fprintln(stderr, "bkpyvenv stage: missing <version>")
			return 2
		}
		if err := pyStage(root, prefix, args[0], engine); err != nil {
			fmt.Fprintln(stderr, "bkpyvenv stage:", err)
			return 1
		}
	case "seal":
		if err := pySeal(root, prefix, engine, args); err != nil {
			fmt.Fprintln(stderr, "bkpyvenv seal:", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "bkpyvenv: unknown subcommand %q\n", cmd)
		return 2
	}
	return 0
}

// pyStage implements `bkpyvenv stage`.
func pyStage(root, prefix, version, engine string) error {
	// A git tag lets setuptools-scm / hatch-vcs derive the version from the
	// source tree; upstream only bootstraps one when the tree is not already a
	// repo, so an existing .git (a real git checkout) is left untouched.
	if _, err := os.Stat(filepath.Join(root, ".git")); os.IsNotExist(err) {
		if err := pyGitInitTag(root, version); err != nil {
			return err
		}
	}

	if engine == "poetry" {
		if err := pyRun(root, "poetry", "config", "virtualenvs.create", "true"); err != nil {
			return err
		}
		return pyRun(root, "poetry", "config", "virtualenvs.in-project", "true")
	}

	venv := filepath.Join(prefix, "venv")
	venvArgs := []string{"-m", "venv"}
	if pyGOOS == "linux" {
		// --copies: embed the interpreter rather than an absolute symlink to the
		// build-time python prefix, so the bottle relocates (pantry#8487).
		venvArgs = append(venvArgs, "--copies")
	}
	venvArgs = append(venvArgs, venv)
	return pyRun(root, "python", venvArgs...)
}

var pyVersionRe = regexp.MustCompile(`Python (\d+\.\d+)`)

// pySeal implements `bkpyvenv seal`.
func pySeal(root, prefix, engine string, cmds []string) error {
	out, err := pyOutput(root, "python", "--version")
	if err != nil {
		return err
	}
	m := pyVersionRe.FindStringSubmatch(out)
	if m == nil {
		return fmt.Errorf("cannot parse python version from %q", strings.TrimSpace(out))
	}
	pyVer := m[1]

	if engine == "poetry" {
		if err := pySealPoetry(root, prefix, pyVer); err != nil {
			return err
		}
	}

	// ⛔⛔ zpkgx, NOT pkgx — AND THIS SHIPPED. Every python-venv bottle this
	// factory has ever built installs $PREFIX/bin/<cmd> whose shebang invokes
	// `pkgx`: upstream's runtime, which we no longer interoperate with
	// (go-zpkg/packages#431), do not publish, and have no reason to expect on
	// anybody's PATH. The launcher was therefore unrunnable unless the user
	// happened to have installed the software we broke compatibility with.
	//
	// It survived the rename because nothing looked: before this line changed,
	// `git grep zpkgx -- '*.go'` over this whole repository returned ZERO
	// matches. The rename moved the commands and left every string that names
	// one behind, and a shebang is the kind of string no test reads out loud.
	//
	// `zpkgx <pkg>[@version] [arg...]` is the same form `pkgx` offered — its own
	// help gives `zpkgx node@22 --version` — so this is a name change and not a
	// behaviour change.
	shebang := "#!/usr/bin/env -S zpkgx python@" + pyVer + "\n"
	binDir := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	// Replace the stub's first line (`#!/usr/bin/env python`) with the pinned
	// `zpkgx python@X.Y` shebang, then install it as bin/<cmd> for every name.
	body := shebang
	if i := bytes.IndexByte(pythonVenvStub, '\n'); i >= 0 {
		body += string(pythonVenvStub[i+1:])
	}
	for _, name := range cmds {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// pySealPoetry mirrors upstream's poetry seal: build an sdist, unpack it into
// the in-project venv's site-packages (strip-components=1), then move the venv
// into place at $PREFIX/venv.
func pySealPoetry(root, prefix, pyVer string) error {
	if err := pyRun(root, "poetry", "build", "-f", "sdist"); err != nil {
		return err
	}
	sdists, err := pyGlob(filepath.Join(root, "dist", "*.tar.gz"))
	if err != nil {
		return err
	}
	if len(sdists) == 0 {
		return fmt.Errorf("no sdist produced under %s", filepath.Join(root, "dist"))
	}
	site := filepath.Join(root, ".venv", "lib", "python"+pyVer, "site-packages")
	if err := fetch.ExtractTarGzFile(sdists[0], site, 1); err != nil {
		return err
	}
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		return err
	}
	return os.Rename(filepath.Join(root, ".venv"), filepath.Join(prefix, "venv"))
}

// defaultGitInitTag bootstraps a throwaway git repo at root and tags it version,
// matching upstream's init/commit/tag so version-from-VCS tooling sees the tag.
func defaultGitInitTag(root, version string) error {
	repo, err := ggPlainInit(root, false)
	if err != nil {
		return err
	}
	w, err := ggWorktree(repo)
	if err != nil {
		return err
	}
	sig := &object.Signature{Name: "pkgx[bot]", Email: "bot@pkgx.dev", When: pyNow()}
	if _, err := ggCommit(w, "nil", &gogit.CommitOptions{AllowEmptyCommits: true, Author: sig}); err != nil {
		return err
	}
	head, err := ggHead(repo)
	if err != nil {
		return err
	}
	_, err = ggCreateTag(repo, version, head.Hash(), &gogit.CreateTagOptions{
		Message: "Version " + version,
		Tagger:  sig,
	})
	return err
}
