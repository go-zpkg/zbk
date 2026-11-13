package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ⛔⛔ THE TWO LAUNCHER SCRIPTS THIS FILE EMBEDDED ARE GONE, NOT PORTED.
// `pyStubberStub` (1837 bytes, from brewkit's libexec/python-venv-stubber.sh)
// and `pyPyStub` (525 bytes of POSIX sh, from libexec/python-venv.py) were the
// last two VERBATIM copies of pkgxdev/brewkit in this repository, and brewkit
// declares no licence at all — so a published zpkb binary was redistributing
// somebody else's expression without a grant (go-zpkg/zpkb#431). Both are
// replaced by installVenvLaunch, which installs cmd/venvlaunch instead; see
// venvlaunchinstall.go for why a script cannot do this job in the images we
// target. The sh one rewrote the venv's shebangs with `sed` on every
// invocation, which is also three dependencies (sh, sed, a writable bottle)
// this design no longer has.

// pyRunEnv spawns like pyRun but with extra environment entries (the old
// python-venv family points pip's TMPDIR at $SRCROOT/dev.pkgx.python.build).
var pyRunEnv = defaultPyRunEnv

func defaultPyRunEnv(dir string, extraEnv []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// pyOneShotOpts parameterises the shared one-shot venv builder for the two
// old-family entry points (python-venv.sh vs python-venv.py).
type pyOneShotOpts struct {
	venvFlags       []string // extra `python -m venv` flags (.py: --symlinks)
	pipArgs         []string // pip args after `install`
	delEmptyInclude bool     // .py prunes an empty venv/include
}

// pyVenvOneShot is the shared core of brewkit's libexec/python-venv.{sh,py}: it
// derives prefix/version/cmd from the target executable path, creates the venv,
// tags the source (setuptools-scm), pip-installs the project into the venv, and
// installs the relocatable launcher stub as $prefix/bin/<cmd>.
func pyVenvOneShot(root, exe string, o pyOneShotOpts) error {
	prefix := filepath.Dir(filepath.Dir(exe))
	version := filepath.Base(prefix)
	cmdName := filepath.Base(exe)
	venv := filepath.Join(prefix, "venv")

	venvArgs := append([]string{"-m", "venv"}, o.venvFlags...)
	venvArgs = append(venvArgs, venv)
	if err := pyRun(root, "python", venvArgs...); err != nil {
		return err
	}

	// tag the tree so setuptools-scm/hatch-vcs see the version (skip a real
	// checkout, matching bkpyvenv's guard).
	if _, err := os.Stat(filepath.Join(root, ".git")); os.IsNotExist(err) {
		if err := pyGitInitTag(root, version); err != nil {
			return err
		}
	}

	buildDir := filepath.Join(root, "dev.pkgx.python.build")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return err
	}
	pip := append([]string{"install"}, o.pipArgs...)
	if err := pyRunEnv(venv, []string{"TMPDIR=" + buildDir}, filepath.Join(venv, "bin", "pip"), pip...); err != nil {
		return err
	}

	if err := installVenvLaunch(prefix, venv, []string{cmdName}); err != nil {
		return err
	}

	if o.delEmptyInclude {
		pyDeleteEmptyDirs(filepath.Join(venv, "include"))
	}
	return nil
}

// pythonVenvSh ports libexec/python-venv.sh — `python-venv.sh <prefix>/bin/<cmd>`.
func pythonVenvSh(args []string, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: python-venv.sh <prefix>/bin/<cmd>")
		return 2
	}
	root, err := srcRoot()
	if err != nil {
		fmt.Fprintln(stderr, "python-venv.sh:", err)
		return 1
	}
	err = pyVenvOneShot(root, args[0], pyOneShotOpts{
		pipArgs: []string{root, "--verbose", "--no-clean", "--require-virtualenv"},
	})
	if err != nil {
		fmt.Fprintln(stderr, "python-venv.sh:", err)
		return 1
	}
	return 0
}

// pythonVenvPy ports libexec/python-venv.py —
// `python-venv.py <exe> [--extra E...] [--requirements-txt] [--no-binary]`.
func pythonVenvPy(args []string, stderr io.Writer) int {
	var exe string
	var extras []string
	reqTxt, noBinary := false, false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--requirements-txt":
			reqTxt = true
		case args[i] == "--no-binary":
			noBinary = true
		case args[i] == "--extra":
			// consume following non-flag tokens as extras
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				extras = append(extras, args[i+1])
				i++
			}
		case strings.HasPrefix(args[i], "--extra="):
			extras = append(extras, strings.TrimPrefix(args[i], "--extra="))
		case exe == "":
			exe = args[i]
		}
	}
	if exe == "" {
		fmt.Fprintln(stderr, "usage: python-venv.py <exe> [--extra E...] [--requirements-txt] [--no-binary]")
		return 2
	}
	root, err := srcRoot()
	if err != nil {
		fmt.Fprintln(stderr, "python-venv.py:", err)
		return 1
	}

	installName := root
	if len(extras) > 0 {
		installName = fmt.Sprintf("%s[%s]", root, strings.Join(extras, ","))
	}
	pipArgs := []string{installName}
	if reqTxt {
		pipArgs = append(pipArgs, "-r", filepath.Join(root, "requirements.txt"))
	}
	if noBinary {
		pipArgs = append(pipArgs, "--no-binary", ":all:")
	}
	pipArgs = append(pipArgs, "--verbose", "--no-clean", "--require-virtualenv")

	err = pyVenvOneShot(root, exe, pyOneShotOpts{
		venvFlags:       []string{"--symlinks"},
		pipArgs:         pipArgs,
		delEmptyInclude: true,
	})
	if err != nil {
		fmt.Fprintln(stderr, "python-venv.py:", err)
		return 1
	}
	return 0
}

// pythonVenvStubber ports libexec/python-venv-stubber.sh — it installs the
// launcher at $VIRTUAL_ENV/../bin/<cmd>, taking the venv from $VIRTUAL_ENV.
func pythonVenvStubber(args []string, stderr io.Writer) int {
	venv := os.Getenv("VIRTUAL_ENV")
	if venv == "" {
		fmt.Fprintln(stderr, "python-venv-stubber.sh: error: VIRTUAL_ENV not set")
		return 1
	}
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: python-venv-stubber.sh <cmd>")
		return 2
	}
	if err := installVenvLaunch(filepath.Dir(venv), venv, []string{args[0]}); err != nil {
		fmt.Fprintln(stderr, "python-venv-stubber.sh:", err)
		return 1
	}
	return 0
}

// pyDeleteEmptyDirs mirrors python-venv.py's cleanup: remove dir if it (and its
// subtree) contains no files. Best-effort — errors are ignored, as upstream's is.
func pyDeleteEmptyDirs(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			pyDeleteEmptyDirs(filepath.Join(dir, e.Name()))
		} else {
			return // a regular file → not empty, keep
		}
	}
	_ = os.Remove(dir)
}
