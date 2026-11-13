package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"fmt"
	"github.com/go-attest/sign"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/config"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/overrides"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
	"github.com/go-zpkg/zpkb/versions"
)

// published records what the stubbed publish seam was asked to push.
type publishedArtifact struct {
	project, version, tag, osn, arch, dist, path, glibc string
	signed                                              bool
	when                                                time.Time
	// advisories is the tree the publish was told to build its OpenVEX
	// document from. Recorded because a mutation that dropped it on the way to
	// publishArtifact — the whole feature — survived the suite without it.
	advisories string
}

// factoryHarness stubs every factory seam (network, pantry, compiler) and
// collects what the run did.
type factoryHarness struct {
	pantry   string
	failures string
	detail   string
	// tests is where the recorded test outcomes go. Given a path like the
	// other two, because the flag's default writes into the CURRENT
	// directory and the suite was leaving a cmd/bk/tests.txt behind.
	tests string
	// artifacts is where built and mirrored artifacts are staged, for the SAME
	// reason tests, failures and detail are given paths — and it was the one
	// of the four that was missed. The fix had been applied three times and
	// `--artifacts` still defaulted to the relative "dist", so a mirror test
	// wrote `cmd/bk/dist/lib.org/linux/x86-64/v1.0.tar.xz` into the
	// repository and `git add -A` staged it.
	artifacts string
	published []publishedArtifact
	checked   []string // "project@tag" the publish-check was asked about
	built     []string // "project@constraint"
	out, errb bytes.Buffer
}

// newFactoryHarness wires safe defaults: nothing is published yet, every build
// and publish succeeds, requested projects have two versions, deps resolve to
// 9.9.
func newFactoryHarness(t *testing.T) *factoryHarness {
	t.Helper()
	h := &factoryHarness{
		pantry:    t.TempDir(),
		failures:  filepath.Join(t.TempDir(), "failures.txt"),
		detail:    filepath.Join(t.TempDir(), "failures-detail.txt"),
		tests:     filepath.Join(t.TempDir(), "tests.txt"),
		artifacts: filepath.Join(t.TempDir(), "dist"),
	}
	ov, li, re, pu, bu, hp, bf, lp := factoryOverrides, factoryList, factoryResolve, factoryPublish, factoryBuild, factoryHasPlatform, buildFactory, lookPath
	pl := factoryPlan
	t.Cleanup(func() {
		factoryOverrides, factoryList, factoryResolve, factoryPublish = ov, li, re, pu
		factoryBuild, factoryHasPlatform, buildFactory, lookPath = bu, hp, bf, lp
		factoryPlan = pl
	})
	for _, k := range []string{"ZPKB_TARGET", "PLATFORM", "PANTRY", "RECIPES", "DIST", "MAX_VERSIONS", "FORCE", "SIGNING_KEY", "SOURCE_DATE_EPOCH"} {
		t.Setenv(k, "")
	}

	factoryHasPlatform = func(_, project, tag, _, _ string) (bool, error) {
		h.checked = append(h.checked, project+"@"+tag)
		return false, nil
	}
	factoryList = func(any) ([]versions.VersionTag, error) {
		return []versions.VersionTag{{Version: "2.0", Tag: "v2.0"}, {Version: "1.0", Tag: "v1.0"}}, nil
	}
	factoryResolve = func(any, string) (string, string, error) { return "9.9", "v9.9", nil }
	// ⛔ THE PLAN IS STUBBED, AND IT CARRIES A SPEC. The factory asks the
	// registry about the BUILD, so a plan with an empty spec would produce a
	// bare version tag and this harness would quietly measure the old
	// behaviour — passing while the thing under test does not happen.
	factoryPlan = func(_ *build.Runner, _ *pantry.Recipe, project, constraint string, tgt target.Target) (build.Plan, error) {
		v := strings.TrimPrefix(constraint, "=")
		return build.Plan{
			Version:  v,
			Tag:      "v" + v,
			Concrete: testSpec(project, v, tgt),
			SpecHash: testSpec(project, v, tgt).Hash(),
		}, nil
	}
	factoryBuild = func(_ *build.Runner, p build.Plan, _ *pantry.Recipe, project string, _, _ target.Target, out string) (build.Result, error) {
		h.built = append(h.built, project+"@="+p.Version)
		return build.Result{
			Version: p.Version, Concrete: p.Concrete, SpecHash: p.SpecHash,
			ArtifactPath: filepath.Join(out, project, "v"+p.Version+".tar.gz"),
		}, nil
	}
	factoryPublish = func(o publishOptions) (string, ocispec.Descriptor, error) {
		tag := buildTag(o.Project, o.Version, o.Glibc, o.Concrete)
		h.published = append(h.published, publishedArtifact{
			project: o.Project, version: o.Version, tag: tag, osn: o.OS, arch: o.Arch,
			dist: o.Dist, path: o.Path, glibc: o.Glibc, signed: o.Key != nil, when: o.Time,
			advisories: o.Advisories,
		})
		// A distinct digest per artifact, so a test can tell one published
		// manifest from another the way the index check does.
		return tag, ocispec.Descriptor{Digest: digest.FromString(o.Project + tag + o.Arch)}, nil
	}
	buildFactory = func(string) *build.Runner { return &build.Runner{} }
	lookPath = func(s string) (string, error) { return "/usr/local/bin/" + s, nil }
	return h
}

// testSpec is a stand-in for what a build IS, made distinct per project,
// version and platform so two stubbed builds do not share one address.
//
// ⛔ IT IS NOT A HASH THE TEST CHOSE. The hash is asked of artifact.Concrete,
// the way the real plan asks for it, so an assertion about a tag is an
// assertion about the value the publish path will actually produce — not
// about a constant written twice.
func testSpec(project, version string, tgt target.Target) artifact.Concrete {
	return artifact.Concrete{
		Platform: tgt.Platform + "/" + tgt.Arch,
		Recipe:   "sha256:" + project + "@" + version,
	}
}

// harnessTarget is the platform every factory-harness run builds for; the
// harness forces it, and the spec hash depends on it.
var harnessTarget = target.Target{Platform: "linux", Arch: "x86-64"}

// specTag is the tag a (project, version) build lands on in a harness run:
// the version with the identity the stubbed plan gives it.
func specTag(project, version string) string {
	return version + testSpec(project, version, harnessTarget).VariantTag()
}

// args builds a command line with the harness's paths plus extras.
// args are the flags every harness run passes.
//
// ⛔ --artifacts IS NOT OPTIONAL HERE. It defaults to the RELATIVE path "dist",
// and `go test` runs with the package directory as its working directory — so
// a run that stages an artifact writes into cmd/bk/dist, inside the repository,
// one `git add -A` from being committed. Measured: a mirror test staged
// `cmd/bk/dist/lib.org/linux/x86-64/v1.0.tar.xz` and it got staged.
//
// The stub factoryPublish writes nothing, which is why this went unnoticed
// until a test exercised the MIRROR path — that one puts the downloaded bytes
// on disk before publishing them. The guard belongs here, not in each test:
// the next test written without it is the one that escapes.
func (h *factoryHarness) args(extra ...string) []string {
	return append([]string{
		"--platform", "linux/x86-64",
		"--pantry", h.pantry,
		"--overrides", "",
		"--artifacts", h.artifacts,
		"--failures", h.failures,
		"--failures-detail", h.detail,
		"--tests", h.tests,
	}, extra...)
}

func (h *factoryHarness) run(t *testing.T, extra ...string) int {
	t.Helper()
	h.out.Reset()
	h.errb.Reset()
	return runFactory(h.args(extra...), &h.out, &h.errb)
}

func (h *factoryHarness) failuresFile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(h.failures)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (h *factoryHarness) detailFile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(h.detail)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRunFactoryBuildsClosureDepsFirst is the headline behaviour: the requested
// project is expanded to its closure, dependencies build FIRST and at a single
// resolved version, the requested project builds every version, and each artifact
// is published under the registry the run was pointed at.
func TestRunFactoryBuildsClosureDepsFirst(t *testing.T) {
	h := newFactoryHarness(t)
	// missing.org has no recipe here: it is not ours to build (it resolves from
	// upstream dist at build time), so the closure notes it and moves on.
	writeClosureRecipe(t, h.pantry, "app.org", "dependencies:\n  lib.org: '*'\n  missing.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")

	if code := h.run(t, "--recipes", "app.org", "--to", "oci://example.test/pkgs"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if got := strings.Join(h.built, " "); got != "lib.org@=9.9 app.org@=2.0 app.org@=1.0" {
		t.Fatalf("built = %q", got)
	}
	if len(h.published) != 3 {
		t.Fatalf("published = %+v", h.published)
	}
	for _, p := range h.published {
		if p.dist != "oci://example.test/pkgs" || p.osn != "linux" || p.arch != "x86-64" {
			t.Fatalf("published to the wrong place: %+v", p)
		}
		if p.signed {
			t.Fatalf("unsigned run produced a signed artifact: %+v", p)
		}
		if p.when != time.Unix(defaultEpoch, 0).UTC() {
			t.Fatalf("attestation time = %v, want the pinned epoch", p.when)
		}
	}
	// Staged under the --artifacts directory, named by project and version. The
	// literal "dist" used to be asserted here, which was asserting the FLAG's
	// relative default — the very thing that let a mirror test write into the
	// repository.
	if h.published[0].path != filepath.Join(h.artifacts, "lib.org", "v9.9.tar.gz") {
		t.Fatalf("artifact path = %q, want it under %q", h.published[0].path, h.artifacts)
	}
	out := h.out.String()
	for _, want := range []string{
		"signing: disabled (no key)",
		"closure: 2 project(s) for linux/x86-64 (from 1 requested)",
		"versions app.org: 2 to consider (linux/x86-64)",
		"✅ OK lib.org " + specTag("lib.org", "9.9") + " linux/x86-64",
		"=== summary (linux/x86-64): 3 built, 0 skipped, 0 failed ===",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(h.errb.String(), "closure: skip missing.org") {
		t.Fatalf("stderr = %s", h.errb.String())
	}
	if h.failuresFile(t) != "" || h.detailFile(t) != "" {
		t.Fatalf("failure files not empty: %q / %q", h.failuresFile(t), h.detailFile(t))
	}
}

// TestFactorySeamsAreReal exercises the seams the other tests stub out, so the
// production wiring itself is covered rather than only its stand-ins.
func TestFactorySeamsAreReal(t *testing.T) {
	t.Run("plan and build run the real Runner", func(t *testing.T) {
		tempEnv(t)
		rec, err := pantry.Parse([]byte(miniRecipe))
		if err != nil {
			t.Fatal(err)
		}
		runner := stubFactory()("pkgx")
		plan, err := factoryPlan(runner, rec, "test.org/x", "*", target.Host())
		if err != nil {
			t.Fatal(err)
		}
		// ⛔ THE PLAN SETTLES THE IDENTITY BEFORE ANYTHING IS BUILT. That is
		// the whole reason it is a step of its own: the registry is asked
		// about this hash while the build has not started.
		if plan.SpecHash == "" {
			t.Fatal("the plan produced no identity, so there is nothing to ask the registry about")
		}
		res, err := factoryBuild(runner, plan, rec, "test.org/x", target.Host(), target.Host(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if res.Version != "1.0.0" {
			t.Fatalf("res = %+v", res)
		}
		if res.SpecHash != plan.SpecHash {
			t.Errorf("the build used a different identity from the one the plan checked: %q vs %q",
				res.SpecHash, plan.SpecHash)
		}
	})

	t.Run("publish-check talks to a registry", func(t *testing.T) {
		m := newMiniOCI()
		defer m.close()
		// nothing has been pushed to this registry: an absent tag is a
		// not-published signal, not an error.
		published, err := factoryHasPlatform(m.base(), "lib.org", "1.0", "linux", "x86-64")
		if err != nil || published {
			t.Fatalf("published = %v, err = %v", published, err)
		}
		if _, err := factoryHasPlatform("://bad", "lib.org", "1.0", "linux", "x86-64"); err == nil {
			t.Fatal("want an error for an unusable registry base")
		}
	})
}

// TestRunFactorySkipIfPublished: an already-published (project, tag, platform)
// is skipped — and --force rebuilds it anyway.
func TestRunFactorySkipIfPublished(t *testing.T) {
	for _, tc := range []struct {
		name              string
		extra             []string
		wantBuilt         int
		wantSkipped       int
		wantSummaryPhrase string
	}{
		{"skip", nil, 0, 1, "0 built, 1 skipped, 0 failed"},
		{"force", []string{"--force"}, 1, 0, "1 built, 0 skipped, 0 failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFactoryHarness(t)
			writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
			factoryHasPlatform = func(_, project, tag, _, _ string) (bool, error) {
				h.checked = append(h.checked, project+"@"+tag)
				return true, nil
			}
			if code := h.run(t, append([]string{"--recipes", "lib.org", "--max-versions", "1"}, tc.extra...)...); code != 0 {
				t.Fatalf("code = %d", code)
			}
			if len(h.built) != tc.wantBuilt {
				t.Fatalf("built = %v", h.built)
			}
			if !strings.Contains(h.out.String(), tc.wantSummaryPhrase) {
				t.Fatalf("stdout = %s", h.out.String())
			}
			// ⛔ THE SKIP NAMES THE BUILD, NOT THE VERSION. "lib.org 2.0 is
			// already published" was the wrong sentence: it skipped a package
			// whose RECIPE had changed, because the version had not.
			wantSkip := "⏭  SKIP lib.org " + specTag("lib.org", "2.0") + " (linux/x86-64) — already published"
			if tc.wantSkipped > 0 && !strings.Contains(h.out.String(), wantSkip) {
				t.Fatalf("stdout = %s", h.out.String())
			}
			if tc.name == "force" && len(h.checked) != 0 {
				t.Fatalf("--force still queried the registry: %v", h.checked)
			}
		})
	}
}

// TestRunFactoryPublishCheckErrorBuildsAnyway: an unreachable registry must not
// silently skip the world — the check failure is reported and the build runs.
func TestRunFactoryPublishCheckErrorBuildsAnyway(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	factoryHasPlatform = func(string, string, string, string, string) (bool, error) {
		return false, errors.New("dial tcp: no route to host")
	}
	if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if len(h.built) != 1 {
		t.Fatalf("built = %v", h.built)
	}
	if !strings.Contains(h.errb.String(), "publish-check lib.org "+specTag("lib.org", "2.0")+": dial tcp") {
		t.Fatalf("stderr = %s", h.errb.String())
	}
}

// TestRunFactoryMaxVersions caps a requested project to the newest N versions.
func TestRunFactoryMaxVersions(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if got := strings.Join(h.built, " "); got != "lib.org@=2.0" {
		t.Fatalf("built = %q, want only the newest", got)
	}
}

// TestRunFactoryGlibcFlavor: --glibc implies the pkgx libc and flavors both the
// published tag and the already-published check.
func TestRunFactoryGlibcFlavor(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "gnu.org/glibc", "versions:\n  github: a/glibc/tags\nbuild: make\n")
	var runner *build.Runner
	buildFactory = func(string) *build.Runner { runner = &build.Runner{}; return runner }

	if code := h.run(t, "--recipes", "lib.org gnu.org/glibc", "--glibc", "2.27.0", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if runner.LibcMode != "zpkx" || runner.Glibc != "2.27.0" {
		t.Fatalf("runner libc = %q glibc = %q", runner.LibcMode, runner.Glibc)
	}
	// ⛔ THE GLIBC FLAVOUR COMES FIRST AND THE IDENTITY LAST. Both are in the
	// tag and they are not the same thing: the flavour is readable and says
	// which libc, the hash is the address and says which build. The glibc
	// package itself is never flavoured — it IS the glibc — but it is still
	// addressed, so it carries a hash like everything else.
	libTag := "2.0-glibc2.27.0" + testSpec("lib.org", "2.0", harnessTarget).VariantTag()
	glibcTag := specTag("gnu.org/glibc", "2.0")
	if got, want := strings.Join(h.checked, " "), "lib.org@"+libTag+" gnu.org/glibc@"+glibcTag; got != want {
		t.Fatalf("checked = %q, want %q (glibc itself must not be flavored)", got, want)
	}
	if h.published[0].tag != libTag || h.published[1].tag != glibcTag {
		t.Fatalf("tags = %q %q, want %q %q", h.published[0].tag, h.published[1].tag, libTag, glibcTag)
	}
	if !strings.Contains(h.out.String(), "✅ OK lib.org "+libTag+" linux/x86-64") {
		t.Fatalf("stdout = %s", h.out.String())
	}
}

// TestRunFactoryFailureStages: every way one recipe can fail is recorded in
// failures.txt (+ detail) and never fails the run.
func TestRunFactoryFailureStages(t *testing.T) {
	t.Run("build, with the error tail captured", func(t *testing.T) {
		h := newFactoryHarness(t)
		writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
		script := filepath.Join(t.TempDir(), "build.sh")
		if err := os.WriteFile(script, []byte("echo compiling lib\necho 'error: boom' >&2\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		factoryBuild = func(r *build.Runner, _ build.Plan, _ *pantry.Recipe, _ string, _, _ target.Target, _ string) (build.Result, error) {
			if err := r.Run(script, nil); err != nil { // the real script runner, teed into the tail buffer
				t.Fatal(err)
			}
			return build.Result{}, errors.New("stage install: rename: file exists")
		}
		if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org 2.0 build\n" {
			t.Fatalf("failures.txt = %q", got)
		}
		detail := h.detailFile(t)
		for _, want := range []string{
			"########## lib.org 2.0 (linux/x86-64) — build failed: stage install: rename: file exists",
			"compiling lib", "error: boom",
		} {
			if !strings.Contains(detail, want) {
				t.Fatalf("failures-detail.txt missing %q:\n%s", want, detail)
			}
		}
		// the build's own output still reaches the log, inside a fold
		if !strings.Contains(h.out.String(), "::group::build lib.org 2.0 (linux/x86-64)\ncompiling lib") {
			t.Fatalf("stdout = %s", h.out.String())
		}
		if !strings.Contains(h.out.String(), "1 failed") {
			t.Fatalf("stdout = %s", h.out.String())
		}
	})

	for _, tc := range []struct {
		name, want string
		setup      func(t *testing.T, h *factoryHarness)
	}{
		// ⛔ A PLAN THAT FAILS IS ITS OWN STAGE. The closure could not be
		// resolved, so the identity does not exist, so nothing can be asked
		// of the registry and nothing can be built — and recording it as
		// "build" would send its reader to read a build log that was never
		// written.
		{"plan", "lib.org 2.0 plan\n", func(t *testing.T, h *factoryHarness) {
			factoryPlan = func(_ *build.Runner, _ *pantry.Recipe, _, _ string, _ target.Target) (build.Plan, error) {
				return build.Plan{}, errors.New("resolve deps: 503")
			}
		}},
		{"package", "lib.org 2.0 package\n", func(t *testing.T, h *factoryHarness) {
			factoryBuild = func(_ *build.Runner, _ build.Plan, _ *pantry.Recipe, _ string, _, _ target.Target, _ string) (build.Result, error) {
				return build.Result{Version: "2.0"}, nil // built, but nothing packaged
			}
		}},
		{"publish", "lib.org 2.0 publish\n", func(t *testing.T, h *factoryHarness) {
			factoryPublish = func(publishOptions) (string, ocispec.Descriptor, error) {
				return "", ocispec.Descriptor{}, errors.New("403 denied")
			}
		}},
		{"versions listing", "lib.org latest versions\n", func(t *testing.T, h *factoryHarness) {
			factoryList = func(any) ([]versions.VersionTag, error) { return nil, errors.New("spec has neither github nor url") }
		}},
		{"versions empty", "lib.org latest versions\n", func(t *testing.T, h *factoryHarness) {
			factoryList = func(any) ([]versions.VersionTag, error) { return nil, nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFactoryHarness(t)
			writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
			tc.setup(t, h)
			if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
				t.Fatalf("code = %d", code)
			}
			if got := h.failuresFile(t); got != tc.want {
				t.Fatalf("failures.txt = %q, want %q", got, tc.want)
			}
			if !strings.Contains(h.out.String(), "0 built, 0 skipped, 1 failed") {
				t.Fatalf("stdout = %s", h.out.String())
			}
			if !strings.Contains(h.out.String(), "failures:\n"+tc.want) {
				t.Fatalf("summary did not list the failure:\n%s", h.out.String())
			}
		})
	}

	t.Run("dependency version resolution", func(t *testing.T) {
		h := newFactoryHarness(t)
		writeClosureRecipe(t, h.pantry, "app.org", "dependencies:\n  lib.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
		writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
		factoryResolve = func(any, string) (string, string, error) {
			return "", "", errors.New("no candidate version matched")
		}
		if code := h.run(t, "--recipes", "app.org", "--max-versions", "1"); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org latest versions\n" {
			t.Fatalf("failures.txt = %q", got)
		}
		if got := strings.Join(h.built, " "); got != "app.org@=2.0" {
			t.Fatalf("a failed dep must not stop the rest: built = %q", got)
		}
	})

	t.Run("unparseable recipe", func(t *testing.T) {
		h := newFactoryHarness(t)
		writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
		// closureOf parsed the recipe already; corrupt it before the build loop.
		closure := closureOf
		t.Cleanup(func() { closureOf = closure })
		closureOf = func(_ *logical.Set, overlayDir, dir string, tgt target.Target, want []string, warn func(string)) ([]string, map[string][]string, map[string][]*pantry.Recipe) {
			writeClosureRecipe(t, h.pantry, "lib.org", "versions: [\n")
			return want, nil, nil
		}
		if code := h.run(t, "--recipes", "lib.org"); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org latest recipe\n" {
			t.Fatalf("failures.txt = %q", got)
		}
	})
}

// TestRunFactorySkipsProjectWithoutRecipe guards the loop against a project the
// pantry cannot supply (e.g. removed between the closure walk and the build).
func TestRunFactorySkipsProjectWithoutRecipe(t *testing.T) {
	h := newFactoryHarness(t)
	closure := closureOf
	t.Cleanup(func() { closureOf = closure })
	closureOf = func(*logical.Set, string, string, target.Target, []string, func(string)) ([]string, map[string][]string, map[string][]*pantry.Recipe) {
		return []string{"ghost.org"}, nil, nil
	}
	if code := h.run(t, "--recipes", "ghost.org"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(h.out.String(), "SKIP ghost.org (no recipe)") {
		t.Fatalf("stdout = %s", h.out.String())
	}
	if len(h.built) != 0 {
		t.Fatalf("built = %v", h.built)
	}
}

// TestRunFactoryOverridesApplied: the pantry is patched before the closure is
// computed, and an override failure is fatal only when the directory itself is
// unusable.
func TestRunFactoryOverridesApplied(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	var gotDir, gotRoot string
	factoryOverrides = func(o overrides.Options) (overrides.Result, error) {
		gotDir, gotRoot = o.Dir, o.Root
		o.Log("override applied: x.patch")
		o.Warn("override SKIP (does not apply): y.patch")
		return overrides.Result{Applied: []string{"x.patch"}}, nil
	}
	if code := h.run(t, "--recipes", "lib.org", "--overrides", "over", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if gotDir != "over" || gotRoot != h.pantry {
		t.Fatalf("overrides applied to %q / %q", gotDir, gotRoot)
	}
	if !strings.Contains(h.out.String(), "override applied: x.patch") || !strings.Contains(h.errb.String(), "y.patch") {
		t.Fatalf("out = %s err = %s", h.out.String(), h.errb.String())
	}

	factoryOverrides = func(overrides.Options) (overrides.Result, error) {
		return overrides.Result{}, errors.New("overrides: syntax error in pattern")
	}
	if code := h.run(t, "--recipes", "lib.org", "--overrides", "over"); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

// TestRunFactorySigning: a key from a file or straight from $SIGNING_KEY (as CI
// provides it) reaches the publisher; an unreadable key is fatal.
func TestRunFactorySigning(t *testing.T) {
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyText := kp.SecretKeyFile("test")

	t.Run("key file", func(t *testing.T) {
		h := newFactoryHarness(t)
		writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte(keyText), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := h.run(t, "--recipes", "lib.org", "--sign", path, "--max-versions", "1"); code != 0 {
			t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
		}
		if !h.published[0].signed || !strings.Contains(h.out.String(), "signing: enabled") {
			t.Fatalf("artifact not signed: %+v / %s", h.published, h.out.String())
		}
	})

	t.Run("SIGNING_KEY env", func(t *testing.T) {
		h := newFactoryHarness(t)
		writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
		t.Setenv("SIGNING_KEY", keyText)
		if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
			t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
		}
		if !h.published[0].signed {
			t.Fatalf("artifact not signed: %+v", h.published)
		}
	})

	t.Run("unreadable key", func(t *testing.T) {
		h := newFactoryHarness(t)
		if code := h.run(t, "--recipes", "lib.org", "--sign", filepath.Join(t.TempDir(), "absent")); code != 1 {
			t.Fatalf("code = %d, want 1", code)
		}
		if !strings.Contains(h.errb.String(), "no such file") {
			t.Fatalf("stderr = %s", h.errb.String())
		}
	})
}

// TestRunFactoryRecipesSources: the want list comes from --recipes, else from
// the recipes file (comments and blanks dropped).
func TestRunFactoryRecipesSources(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	list := filepath.Join(t.TempDir(), "recipes.txt")
	if err := os.WriteFile(list, []byte("# a comment\n\nlib.org\n  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := h.run(t, "--recipes-file", list, "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if got := strings.Join(h.built, " "); got != "lib.org@=2.0" {
		t.Fatalf("built = %q", got)
	}

	if code := h.run(t, "--recipes-file", filepath.Join(t.TempDir(), "absent.txt")); code != 1 {
		t.Fatalf("missing recipes file: code = %d, want 1", code)
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := h.run(t, "--recipes-file", empty); code != 1 {
		t.Fatalf("empty recipes file: code = %d, want 1", code)
	}
	if !strings.Contains(h.errb.String(), "nothing to build") {
		t.Fatalf("stderr = %s", h.errb.String())
	}
}

// TestRunFactoryUsageErrors covers the argument/target validation.
func TestRunFactoryUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"bad flag", []string{"--nope"}, 2},
		{"no platform", []string{"--recipes", "lib.org"}, 2},
		{"bad platform", []string{"--platform", "linux", "--recipes", "lib.org"}, 2},
		{"unsupported arch", []string{"--platform", "linux/frobnicate", "--recipes", "lib.org"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFactoryHarness(t)
			var out, errb bytes.Buffer
			if code := runFactory(tc.args, &out, &errb); code != tc.want {
				t.Fatalf("code = %d, want %d (stderr %s)", code, tc.want, errb.String())
			}
			_ = h
		})
	}
}

// TestRunFactoryZpkxLookupFallback: an unresolvable pkgx name is passed through
// verbatim rather than swallowed.
func TestRunFactoryZpkxLookupFallback(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	var gotBin string
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	buildFactory = func(bin string) *build.Runner { gotBin = bin; return &build.Runner{} }
	if code := h.run(t, "--recipes", "lib.org", "--zpkx", "/opt/zpkx", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if gotBin != "/opt/zpkx" {
		t.Fatalf("zpkx bin = %q", gotBin)
	}
}

// TestRunFactoryFailureFileWriteErrors: an unwritable report path is reported,
// not fatal — the artifacts are already published. All three reports, because
// a chunk whose tests.txt could not be written must say so rather than leave
// a reader thinking no test ran.
func TestRunFactoryFailureFileWriteErrors(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	h.failures = filepath.Join(t.TempDir(), "absent-dir", "failures.txt")
	h.detail = filepath.Join(t.TempDir(), "absent-dir", "detail.txt")
	h.tests = filepath.Join(t.TempDir(), "absent-dir", "tests.txt")
	if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if n := strings.Count(h.errb.String(), "no such file or directory"); n != 3 {
		t.Fatalf("stderr = %s", h.errb.String())
	}
	if !strings.Contains(h.out.String(), "1 built") {
		t.Fatalf("stdout = %s", h.out.String())
	}
}

// withMirrorSeams stubs the upstream listing + download and restores the
// artifact package's dist pointer.
func withMirrorSeams(t *testing.T, versions map[string][]string, download func(project, ver, osn, arch string) ([]byte, string, error)) {
	t.Helper()
	uv, dl, dist := factoryUpstreamVersions, factoryDownload, artifact.DistBase
	t.Cleanup(func() { factoryUpstreamVersions, factoryDownload, artifact.DistBase = uv, dl, dist })
	factoryUpstreamVersions = func(project, _, _ string) ([]artifact.Ver, error) {
		vs, ok := versions[project]
		if !ok {
			return nil, errors.New("404 not found")
		}
		var out []artifact.Ver // upstream lists ascending
		for _, v := range vs {
			out = append(out, artifact.ParseVer(v))
		}
		return out, nil
	}
	factoryDownload = download
}

// TestRunFactoryMirrors is the sweep path: copy upstream artifacts into our
// registry, re-signed and attested, without building anything.
func TestRunFactoryMirrors(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "gnu.org/glibc", "versions:\n  github: a/glibc/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{"gnu.org/glibc": {"2.27.0", "2.38.0", "2.44.0"}},
		func(_, ver, _, _ string) ([]byte, string, error) { return []byte("artifact-" + ver), ".tar.xz", nil })

	if code := h.run(t, "--recipes", "gnu.org/glibc", "--mirror-from", "https://dist.pkgx.dev/",
		"--artifacts", filepath.Join(t.TempDir(), "dist")); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if len(h.built) != 0 {
		t.Fatalf("mirror mode must not build: %v", h.built)
	}
	if artifact.DistBase != "https://dist.pkgx.dev" {
		t.Fatalf("upstream dist = %q (trailing slash must be trimmed)", artifact.DistBase)
	}
	if os.Getenv("ZPKG_VERIFY") != "0" {
		t.Fatalf("ZPKG_VERIFY = %q; an unsigned upstream cannot be copied fail-closed", os.Getenv("ZPKG_VERIFY"))
	}
	// newest first, every version, and the staged tarball is what got published
	var tags []string
	for _, p := range h.published {
		tags = append(tags, p.tag)
		if filepath.Base(p.path) != "v"+p.version+".tar.xz" {
			t.Fatalf("staged path = %q", p.path)
		}
		b, err := os.ReadFile(p.path)
		if err != nil || string(b) != "artifact-"+p.version {
			t.Fatalf("staged bytes = %q, err = %v", b, err)
		}
	}
	if strings.Join(tags, ",") != "2.44.0,2.38.0,2.27.0" {
		t.Fatalf("tags = %v", tags)
	}

	// --max-versions caps the copy at the newest N, as it does for builds
	h2 := newFactoryHarness(t)
	writeClosureRecipe(t, h2.pantry, "gnu.org/glibc", "versions:\n  github: a/glibc/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{"gnu.org/glibc": {"2.27.0", "2.38.0", "2.44.0"}},
		func(_, ver, _, _ string) ([]byte, string, error) { return []byte(ver), ".tar.gz", nil })
	if code := h2.run(t, "--recipes", "gnu.org/glibc", "--mirror-from", "https://d",
		"--max-versions", "2", "--artifacts", filepath.Join(t.TempDir(), "dist")); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if len(h2.published) != 2 || h2.published[0].version != "2.44.0" || h2.published[1].version != "2.38.0" {
		t.Fatalf("capped copy = %+v", h2.published)
	}
	out := h.out.String()
	for _, want := range []string{
		"mirror: copying artifacts from https://dist.pkgx.dev (no build)",
		"versions gnu.org/glibc: 3 to consider (linux/x86-64, upstream)",
		"✅ MIRRORED gnu.org/glibc 2.44.0 linux/x86-64",
		"=== summary (linux/x86-64): 3 built, 0 skipped, 0 failed ===",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

// TestRunFactoryMirrorNeedsNoRecipe: mirroring is recipe-free — a project the
// closure walk drops for want of a recipe is still copied, and a dependency
// only gets its newest.
func TestRunFactoryMirrorNeedsNoRecipe(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "app.org", "dependencies:\n  lib.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{
		"app.org":      {"1.0.0", "2.0.0"},
		"lib.org":      {"0.1.0", "0.2.0"},
		"norecipe.org": {"9.0.0"},
	}, func(_, ver, _, _ string) ([]byte, string, error) { return []byte(ver), ".tar.gz", nil })

	if code := h.run(t, "--recipes", "app.org norecipe.org", "--mirror-from", "https://dist.example",
		"--artifacts", filepath.Join(t.TempDir(), "dist")); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	var got []string
	for _, p := range h.published {
		got = append(got, p.project+"@"+p.version)
	}
	// deps first, one version for the dep, every version for the requested ones
	if strings.Join(got, " ") != "lib.org@0.2.0 app.org@2.0.0 app.org@1.0.0 norecipe.org@9.0.0" {
		t.Fatalf("published = %v", got)
	}
}

// TestRunFactoryMirrorFailures: nothing upstream, a fetch error, an unwritable
// staging dir and a publish error are each recorded, never fatal.
func TestRunFactoryMirrorFailures(t *testing.T) {
	stage := func(t *testing.T) string { return filepath.Join(t.TempDir(), "dist") }

	t.Run("no upstream artifact", func(t *testing.T) {
		h := newFactoryHarness(t)
		withMirrorSeams(t, map[string][]string{"lib.org": nil}, nil)
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", stage(t)); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org latest versions\n" {
			t.Fatalf("failures = %q", got)
		}
		if !strings.Contains(h.detailFile(t), "no upstream artifact for linux/x86-64") {
			t.Fatalf("detail = %q", h.detailFile(t))
		}
	})

	t.Run("upstream listing fails", func(t *testing.T) {
		h := newFactoryHarness(t)
		withMirrorSeams(t, nil, nil)
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", stage(t)); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org latest versions\n" {
			t.Fatalf("failures = %q", got)
		}
	})

	t.Run("fetch fails", func(t *testing.T) {
		h := newFactoryHarness(t)
		withMirrorSeams(t, map[string][]string{"lib.org": {"1.0.0"}},
			func(string, string, string, string) ([]byte, string, error) {
				return nil, "", errors.New("502 bad gateway")
			})
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", stage(t)); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org 1.0.0 fetch\n" {
			t.Fatalf("failures = %q", got)
		}
	})

	t.Run("staging dir unwritable", func(t *testing.T) {
		h := newFactoryHarness(t)
		withMirrorSeams(t, map[string][]string{"lib.org": {"1.0.0"}},
			func(string, string, string, string) ([]byte, string, error) { return []byte("x"), ".tar.gz", nil })
		blocked := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocked, nil, 0o644); err != nil { // a FILE where the tree must go
			t.Fatal(err)
		}
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", blocked); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org 1.0.0 fetch\n" {
			t.Fatalf("failures = %q", got)
		}
	})

	t.Run("write fails", func(t *testing.T) {
		h := newFactoryHarness(t)
		withMirrorSeams(t, map[string][]string{"lib.org": {"1.0.0"}},
			func(string, string, string, string) ([]byte, string, error) { return []byte("x"), ".tar.gz", nil })
		// a leftover DIRECTORY where the tarball must be written
		artifacts := stage(t)
		if err := os.MkdirAll(filepath.Join(artifacts, "lib.org", "linux", "x86-64", "v1.0.0.tar.gz"), 0o755); err != nil {
			t.Fatal(err)
		}
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", artifacts); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org 1.0.0 fetch\n" {
			t.Fatalf("failures = %q", got)
		}
	})

	t.Run("publish fails", func(t *testing.T) {
		h := newFactoryHarness(t)
		withMirrorSeams(t, map[string][]string{"lib.org": {"1.0.0"}},
			func(string, string, string, string) ([]byte, string, error) { return []byte("x"), ".tar.gz", nil })
		factoryPublish = func(publishOptions) (string, ocispec.Descriptor, error) {
			return "", ocispec.Descriptor{}, errors.New("403 denied")
		}
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", stage(t)); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if got := h.failuresFile(t); got != "lib.org 1.0.0 publish\n" {
			t.Fatalf("failures = %q", got)
		}
	})
}

// TestRunFactoryMirrorSkipAndForce: an already-published version is skipped, an
// unreachable registry still mirrors, and --force re-copies.
func TestRunFactoryMirrorSkipAndForce(t *testing.T) {
	newHarness := func(t *testing.T) *factoryHarness {
		h := newFactoryHarness(t)
		withMirrorSeams(t, map[string][]string{"lib.org": {"1.0.0"}},
			func(string, string, string, string) ([]byte, string, error) { return []byte("x"), ".tar.gz", nil })
		return h
	}
	t.Run("skip", func(t *testing.T) {
		h := newHarness(t)
		factoryHasPlatform = func(string, string, string, string, string) (bool, error) { return true, nil }
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", filepath.Join(t.TempDir(), "d")); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if len(h.published) != 0 || !strings.Contains(h.out.String(), "0 built, 1 skipped, 0 failed") {
			t.Fatalf("published = %v\n%s", h.published, h.out.String())
		}
	})
	t.Run("force", func(t *testing.T) {
		h := newHarness(t)
		factoryHasPlatform = func(string, string, string, string, string) (bool, error) { return true, nil }
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--force", "--artifacts", filepath.Join(t.TempDir(), "d")); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if len(h.published) != 1 {
			t.Fatalf("published = %v", h.published)
		}
	})
	t.Run("registry unreachable", func(t *testing.T) {
		h := newHarness(t)
		factoryHasPlatform = func(string, string, string, string, string) (bool, error) {
			return false, errors.New("dial tcp: refused")
		}
		if code := h.run(t, "--recipes", "lib.org", "--mirror-from", "https://d", "--artifacts", filepath.Join(t.TempDir(), "d")); code != 0 {
			t.Fatalf("code = %d", code)
		}
		if len(h.published) != 1 || !strings.Contains(h.errb.String(), "publish-check lib.org 1.0.0") {
			t.Fatalf("published = %v, stderr = %s", h.published, h.errb.String())
		}
	})
}

// TestSetUpstreamDistKeepsAnExplicitVerify: an operator who demanded
// verification keeps it (the copy then fails closed, as asked).
func TestSetUpstreamDistKeepsAnExplicitVerify(t *testing.T) {
	old := artifact.DistBase
	t.Cleanup(func() { artifact.DistBase = old })
	t.Setenv("ZPKG_VERIFY", "1")
	setUpstreamDist("https://dist.example")
	if os.Getenv("ZPKG_VERIFY") != "1" {
		t.Fatalf("ZPKG_VERIFY = %q", os.Getenv("ZPKG_VERIFY"))
	}
}

// TestFactoryUpstreamSeamsAreReal exercises the production wiring of the
// mirror seams (they are stubbed everywhere else).
func TestFactoryUpstreamSeamsAreReal(t *testing.T) {
	old := artifact.DistBase
	t.Cleanup(func() { artifact.DistBase = old })
	t.Setenv("ZPKG_VERIFY", "0")
	artifact.DistBase = "https://127.0.0.1:1/dist" // nothing listening
	if _, err := factoryUpstreamVersions("lib.org", "linux", "x86-64"); err == nil {
		t.Fatal("want a listing error")
	}
	if _, _, err := factoryDownload("lib.org", "1.0.0", "linux", "x86-64"); err == nil {
		t.Fatal("want a download error")
	}
}

// TestFactoryDispatch covers the main-loop `case "factory"` route.
func TestFactoryDispatch(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	code, out, errs := run2(t, "factory", "--platform", "linux/x86-64", "--pantry", h.pantry,
		"--overrides", "", "--failures", h.failures, "--failures-detail", h.detail, "--tests", h.tests,
		"--recipes", "lib.org", "--max-versions", "1")
	if code != 0 {
		t.Fatalf("dispatch factory code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "1 built, 0 skipped, 0 failed") {
		t.Fatalf("dispatch factory out=%q", out)
	}
}

func TestFactoryTime(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")
	if got := factoryTime(); got != time.Unix(defaultEpoch, 0).UTC() {
		t.Fatalf("unset epoch → %v, want the pinned default", got)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1234567890")
	if got := factoryTime(); got != time.Unix(1234567890, 0).UTC() {
		t.Fatalf("epoch honoured? got %v", got)
	}
}

func TestEnvInt(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want int
	}{{"", 0}, {"abc", 0}, {"-3", 0}, {"7", 7}} {
		t.Setenv("ZPKB_TEST_N", tc.val)
		if got := envInt("ZPKB_TEST_N"); got != tc.want {
			t.Fatalf("envInt(%q) = %d, want %d", tc.val, got, tc.want)
		}
	}
}

func TestFactoryWantFields(t *testing.T) {
	got, err := factoryWant("  a.org   b.org ", "/nonexistent", "")
	if err != nil || strings.Join(got, ",") != "a.org,b.org" {
		t.Fatalf("got %v, err %v", got, err)
	}
}

// TestTailWriter: output passes through untouched while only the last lines are
// remembered, including a trailing partial line.
func TestTailWriter(t *testing.T) {
	var sink bytes.Buffer
	tw := &tailWriter{w: &sink, max: 2}
	for _, s := range []string{"one\ntwo\n", "three\nfour", "teen\n", "five"} {
		n, err := tw.Write([]byte(s))
		if err != nil || n != len(s) {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	if sink.String() != "one\ntwo\nthree\nfourteen\nfive" {
		t.Fatalf("pass-through = %q", sink.String())
	}
	if got := tw.tail(); got != "three\nfourteen\nfive" {
		t.Fatalf("tail = %q", got)
	}
}

// TestTailWriterWriteError propagates the underlying writer's error.
func TestTailWriterWriteError(t *testing.T) {
	tw := &tailWriter{w: errWriter{}, max: 2}
	if _, err := tw.Write([]byte("x\n")); err == nil {
		t.Fatal("want error")
	}
	if tw.tail() != "" {
		t.Fatalf("tail = %q", tw.tail())
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

// TestRunFactoryVersionConstraint: --versions selects a LINE, which "newest N"
// cannot. Our registry carries cmake 4.4.2 while 114 pantry recipes pin
// `cmake.org: ^3`; no value of --max-versions reaches a 3.x from a newest-first
// listing, so publishing the version those recipes actually need needs this.
func TestRunFactoryVersionConstraint(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	if code := h.run(t, "--recipes", "lib.org", "--versions", "^1"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if got := strings.Join(h.built, " "); got != "lib.org@=1.0" {
		t.Fatalf("built = %q, want only the 1.x line", got)
	}
	if !strings.Contains(h.out.String(), `versions lib.org: 1 dropped by --versions "^1"`) {
		t.Fatalf("the drop must be said, not silent:\n%s", h.out.String())
	}
}

// A constraint no version satisfies is a failure, not an empty success.
func TestRunFactoryVersionConstraintMatchesNothing(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	// The factory tolerates per-project failures by design (it records them and
	// keeps going), so what must be true is that NOTHING was built and the
	// failure is on the record -- not that the process died.
	h.run(t, "--recipes", "lib.org", "--versions", "^9")
	if len(h.built) != 0 {
		t.Fatalf("nothing may be built: %v", h.built)
	}
	if !strings.Contains(h.failuresFile(t), "lib.org  versions") && !strings.Contains(h.errb.String()+h.out.String(), `no version matches "^9"`) {
		t.Fatalf("failure not reported:\n%s\n%s", h.out.String(), h.failuresFile(t))
	}
}

// The same handle applies to mirror mode, which is where it is actually needed:
// upstream publishes cmake 3.x artifacts our registry lacks.
func TestRunFactoryMirrorVersionConstraint(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "cmake.org", "versions:\n  github: a/cmake/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{"cmake.org": {"3.31.12", "4.4.1", "4.4.2"}},
		func(_, ver, _, _ string) ([]byte, string, error) { return []byte("artifact-" + ver), ".tar.xz", nil })

	if code := h.run(t, "--recipes", "cmake.org", "--mirror-from", "https://dist.pkgx.dev",
		"--versions", "^3", "--artifacts", filepath.Join(t.TempDir(), "dist")); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	var tags []string
	for _, p := range h.published {
		tags = append(tags, p.tag)
	}
	if strings.Join(tags, ",") != "3.31.12" {
		t.Fatalf("tags = %v, want only the 3.x line", tags)
	}
}

// …and in mirror mode too, an unsatisfiable constraint is a recorded failure,
// not a silent no-op that looks like "everything was already published".
func TestRunFactoryMirrorVersionConstraintMatchesNothing(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "cmake.org", "versions:\n  github: a/cmake/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{"cmake.org": {"4.4.1", "4.4.2"}},
		func(_, ver, _, _ string) ([]byte, string, error) { return []byte("artifact-" + ver), ".tar.xz", nil })

	h.run(t, "--recipes", "cmake.org", "--mirror-from", "https://dist.pkgx.dev",
		"--versions", "^3", "--artifacts", filepath.Join(t.TempDir(), "dist"))
	if len(h.published) != 0 {
		t.Fatalf("nothing may be published: %v", h.published)
	}
	if !strings.Contains(h.failuresFile(t), "cmake.org") {
		t.Fatalf("failure not recorded: %q", h.failuresFile(t))
	}
}

// TestFactoryRepairsIndexesAtTheEnd: every artifact a run publishes is re-checked
// once the batch is over, when the other publishers have finished and a repair
// sticks. Doing it per-push cannot work — the racer that dropped python.org's
// arm64 landed AFTER that push had already verified itself.
func TestFactoryRepairsIndexesAtTheEnd(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "app.org", "versions:\n  github: a/app/tags\nbuild: make\n")
	e := &fakeEnsurer{repaired: map[string]bool{}}
	withEnsurer(t, e, nil)

	if code := h.run(t, "--to", "oci://example.invalid/pkgs", "--recipes", "app.org"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}

	if len(e.calls) == 0 {
		t.Fatal("nothing was re-checked, so a dropped platform would go unnoticed")
	}
	if len(e.calls) != len(h.published) {
		t.Errorf("checked %d of %d published artifacts: %v", len(e.calls), len(h.published), e.calls)
	}
	// Nothing was broken, so nothing is announced.
	if strings.Contains(h.out.String(), "REPAIRED") {
		t.Errorf("a repair was reported on intact indexes:\n%s", h.out.String())
	}
}

// TestFactoryAnnouncesARepair: when an index HAD lost a platform, the run says
// so — a silent repair hides a defect that is still happening.
func TestFactoryAnnouncesARepair(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "app.org", "versions:\n  github: a/app/tags\nbuild: make\n")
	// Every index this run wrote comes back missing its platform.
	e := &fakeEnsurer{repaired: map[string]bool{}, repairAll: true}
	withEnsurer(t, e, nil)

	if code := h.run(t, "--to", "oci://example.invalid/pkgs", "--recipes", "app.org"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}

	out := h.out.String()
	if !strings.Contains(out, "🔧 REPAIRED index") {
		t.Errorf("the repair is not announced:\n%s", out)
	}
	if !strings.Contains(out, "index(es) repaired") {
		t.Errorf("no summary line:\n%s", out)
	}
}

// TestMatchingWarnsABareVersionIsARange: `--versions 2.28.0` reads like "that
// one version" and means ">=2.28.0 within major 2". A heal dispatched that way
// walked every glibc from 2.28 to 2.33 and, on another run, filled the runner's
// disk with kernel tarballs. The tool now says so while the run is young.
func TestMatchingWarnsABareVersionIsARange(t *testing.T) {
	var out, errb strings.Builder
	f := &factory{want: "2.28.0", stdout: &out, stderr: &errb}

	got := f.matching("gnu.org/glibc", []string{"2.28.0", "2.29.0", "2.33.0", "1.9.0"})

	if len(got) != 3 {
		t.Fatalf("matched %v", got)
	}
	if !strings.Contains(errb.String(), "is a RANGE") || !strings.Contains(errb.String(), `"=2.28.0"`) {
		t.Errorf("no usable warning: %q", errb.String())
	}
}

// TestMatchingIsQuietOnAnExactVersion: the warning must not fire for the form
// it recommends, or it becomes noise the operator learns to skip.
func TestMatchingIsQuietOnAnExactVersion(t *testing.T) {
	var out, errb strings.Builder
	f := &factory{want: "=2.28.0", stdout: &out, stderr: &errb}

	got := f.matching("gnu.org/glibc", []string{"2.28.0", "2.29.0"})

	if len(got) != 1 || got[0] != "2.28.0" {
		t.Fatalf("matched %v", got)
	}
	if strings.Contains(errb.String(), "RANGE") {
		t.Errorf("warned on an exact version: %q", errb.String())
	}
}

// TestMatchingIsQuietOnASingleMatch: a bare version that happens to match one
// version taught the operator nothing wrong.
func TestMatchingIsQuietOnASingleMatch(t *testing.T) {
	var out, errb strings.Builder
	f := &factory{want: "2.28.0", stdout: &out, stderr: &errb}

	f.matching("gnu.org/glibc", []string{"2.28.0", "1.0.0"})

	if strings.Contains(errb.String(), "RANGE") {
		t.Errorf("warned when the range matched exactly one: %q", errb.String())
	}
}

// TestIsBareVersion draws the line where the surprise is: an operator form.
func TestIsBareVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"14", true}, {"2.28.0", true}, {" 2.28.0", true},
		{"=2.28.0", false}, {"^3", false}, {">=2.4", false}, {"~5.42", false}, {"", false},
	} {
		if got := isBareVersion(tc.in); got != tc.want {
			t.Errorf("isBareVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestMirrorCapUsesAUnionOfArches is the defect this prevents, and it was
// self-inflicted: `--max-versions 3 --mirror-from …`, dispatched to repair split
// indexes, created more of them. Each arch job took the newest three of ITS OWN
// upstream list, and those lists differ — circleci.com carries 124 versions for
// linux/aarch64 and 125 for linux/x86-64 — so the two jobs mirrored different
// sets and every version only one of them picked landed alone in its index.
func TestMirrorCapUsesAUnionOfArches(t *testing.T) {
	old := factoryUpstreamVersions
	defer func() { factoryUpstreamVersions = old }()
	factoryUpstreamVersions = func(proj, osn, arch string) ([]artifact.Ver, error) {
		// Ascending, as upstream lists are. x86-64 has one version aarch64 lacks.
		switch arch {
		case "x86-64":
			return vers("1.0", "2.0", "3.0", "4.0"), nil
		default:
			return vers("1.0", "2.0", "4.0"), nil
		}
	}

	// The union decides WHERE to cut — both arches consider 4.0, 3.0, 2.0, so
	// neither mirrors a version the other stopped short of. It does not decide
	// WHAT to fetch: 3.0 is not there for aarch64, and asking upstream for it
	// fails the entry outright (`gnu.org/gcc 16.2.0 fetch`, on a darwin/aarch64
	// that carries sixteen versions but not that one).
	//
	// 3.0 then exists for x86-64 alone, which is what upstream says. The audit
	// calls that an ABSENCE, not a lost index entry, and there is nothing to
	// heal.
	var out, errb strings.Builder
	for _, tc := range []struct{ arch, want string }{
		{"x86-64", "4.0 3.0 2.0"},
		{"aarch64", "4.0 2.0"},
	} {
		f := &factory{osn: "linux", arch: tc.arch, platform: "linux/" + tc.arch, stdout: &out, stderr: &errb}
		got, err := f.mirrorVersionsFor("circleci.com", true, 3)
		if err != nil {
			t.Fatalf("%s: %v", tc.arch, err)
		}
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%s mirrored %q, want %q", tc.arch, strings.Join(got, " "), tc.want)
		}
	}
}

// TestMirrorSkipsAVersionThisArchDoesNotHaveAtAll: if the cut leaves this arch
// nothing, say so rather than failing later in the fetch.
func TestMirrorSkipsAVersionThisArchDoesNotHaveAtAll(t *testing.T) {
	old := factoryUpstreamVersions
	defer func() { factoryUpstreamVersions = old }()
	factoryUpstreamVersions = func(proj, osn, arch string) ([]artifact.Ver, error) {
		if arch == "x86-64" {
			return vers("1.0", "9.0"), nil
		}
		return vers("1.0"), nil // the cut of 1 takes 9.0, which this arch lacks
	}
	var out, errb strings.Builder
	f := &factory{osn: "linux", arch: "aarch64", platform: "linux/aarch64", stdout: &out, stderr: &errb}
	if _, err := f.mirrorVersionsFor("x.org", true, 1); err == nil ||
		!strings.Contains(err.Error(), "no upstream artifact") {
		t.Fatalf("got %v, want a clear \"nothing to mirror here\"", err)
	}
}

// TestMirrorWithoutACapIsUnchanged: the union only matters when cutting. An
// uncapped mirror still walks exactly what its own platform carries.
func TestMirrorWithoutACapIsUnchanged(t *testing.T) {
	old := factoryUpstreamVersions
	defer func() { factoryUpstreamVersions = old }()
	calls := 0
	factoryUpstreamVersions = func(proj, osn, arch string) ([]artifact.Ver, error) {
		calls++
		return vers("1.0", "2.0"), nil
	}

	var out, errb strings.Builder
	f := &factory{osn: "linux", arch: "aarch64", platform: "linux/aarch64", stdout: &out, stderr: &errb}
	got, err := f.mirrorVersionsFor("x.org", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "2.0 1.0" {
		t.Errorf("got %q", strings.Join(got, " "))
	}
	if calls != 1 {
		t.Errorf("consulted %d lists without a cap, want 1", calls)
	}
}

// TestMirrorCapSurvivesAnUnreachableSibling: if the other arch's list cannot be
// read, cap on ours and SAY the cut is uncoordinated — silently doing it is how
// the split happened in the first place.
func TestMirrorCapSurvivesAnUnreachableSibling(t *testing.T) {
	old := factoryUpstreamVersions
	defer func() { factoryUpstreamVersions = old }()
	factoryUpstreamVersions = func(proj, osn, arch string) ([]artifact.Ver, error) {
		if arch == "x86-64" {
			return nil, errors.New("dns")
		}
		return vers("1.0", "2.0", "3.0"), nil
	}

	var out, errb strings.Builder
	f := &factory{osn: "linux", arch: "aarch64", platform: "linux/aarch64", stdout: &out, stderr: &errb}
	got, err := f.mirrorVersionsFor("x.org", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "3.0 2.0" {
		t.Errorf("got %q", strings.Join(got, " "))
	}
	if !strings.Contains(errb.String(), "capping on linux/aarch64 only") {
		t.Errorf("the uncoordinated cut was not reported: %q", errb.String())
	}
}

// vers builds an ascending upstream version list.
func vers(raw ...string) []artifact.Ver {
	out := make([]artifact.Ver, 0, len(raw))
	for _, r := range raw {
		out = append(out, artifact.ParseVer(r))
	}
	return out
}

// TestMirrorRequestedLeavesNothingPresent: the constraint and the cap both
// match, and every version they leave belongs to the sibling arch. Say so here
// rather than let the fetch fail one version at a time.
func TestMirrorRequestedLeavesNothingPresent(t *testing.T) {
	old := factoryUpstreamVersions
	defer func() { factoryUpstreamVersions = old }()
	factoryUpstreamVersions = func(proj, osn, arch string) ([]artifact.Ver, error) {
		if arch == "x86-64" {
			return vers("1.0", "3.0"), nil
		}
		return vers("1.0"), nil
	}
	var out, errb strings.Builder
	f := &factory{osn: "linux", arch: "aarch64", platform: "linux/aarch64",
		want: "^3", stdout: &out, stderr: &errb}
	_, err := f.mirrorVersionsFor("x.org", true, 5)
	if err == nil || !strings.Contains(err.Error(), "no upstream artifact") {
		t.Fatalf("got %v, want a clear \"nothing here to mirror\"", err)
	}
}

// TestMirrorClosureDepAbsentOnThisArch: a closure dependency takes the newest
// the arches agree on. When that one belongs to the sibling only, there is
// nothing to mirror here, and saying it beats a fetch failure three steps later.
func TestMirrorClosureDepAbsentOnThisArch(t *testing.T) {
	old := factoryUpstreamVersions
	defer func() { factoryUpstreamVersions = old }()
	factoryUpstreamVersions = func(proj, osn, arch string) ([]artifact.Ver, error) {
		if arch == "x86-64" {
			return vers("1.0", "7.0"), nil
		}
		return vers("1.0"), nil
	}
	var out, errb strings.Builder
	f := &factory{osn: "linux", arch: "aarch64", platform: "linux/aarch64", stdout: &out, stderr: &errb}
	if _, err := f.mirrorVersionsFor("x.org", false, 1); err == nil ||
		!strings.Contains(err.Error(), "no upstream artifact") {
		t.Fatalf("got %v, want a clear \"nothing here to mirror\"", err)
	}
}

// TestFactoryJobsFlag: --jobs must reach the runner, and JOBS must be its
// default. The knob exists for emulated targets — on an aarch64 rootfs under
// qemu-user, `make --jobs 32` exhausts the emulated address space and bash
// reports "xmalloc: cannot allocate 8192 bytes", which reads like a broken
// recipe and is not one. A flag nothing wires through is worse than none.
func TestFactoryJobsFlag(t *testing.T) {
	fs := flag.NewFlagSet("factory", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jobs := fs.Int("jobs", envInt("JOBS"), "")
	if err := fs.Parse([]string{"--jobs", "4"}); err != nil {
		t.Fatal(err)
	}
	r := &build.Runner{}
	r.Concurrency = *jobs
	if r.Concurrency != 4 {
		t.Fatalf("Concurrency = %d, want 4", r.Concurrency)
	}

	t.Setenv("JOBS", "2")
	fs2 := flag.NewFlagSet("factory", flag.ContinueOnError)
	fs2.SetOutput(io.Discard)
	jobs2 := fs2.Int("jobs", envInt("JOBS"), "")
	if err := fs2.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *jobs2 != 2 {
		t.Fatalf("JOBS default = %d, want 2", *jobs2)
	}
}

// TestTailKeepsTheFirstErrors is the kernel case: `make --jobs N` reports the
// failing command and then every other job in flight drains after it, so by the
// time make gives up the error is far past the tail. Three and a half hours of
// build left "AR fs/built-in.a" and a top-level make rule naming no cause.
func TestTailKeepsTheFirstErrors(t *testing.T) {
	tw := &tailWriter{w: io.Discard, max: 3}
	fmt.Fprintln(tw, "  CC      drivers/foo.o")
	fmt.Fprintln(tw, "drivers/foo.c:42:7: error: use of undeclared identifier 'x'")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(tw, "  CC      fs/btrfs/file%d.o\n", i)
	}
	fmt.Fprintln(tw, "  AR      fs/built-in.a")
	got := tw.tail()

	if !strings.Contains(got, "use of undeclared identifier") {
		t.Errorf("the cause is missing:\n%s", got)
	}
	if !strings.Contains(got, "AR      fs/built-in.a") {
		t.Errorf("the tail is missing:\n%s", got)
	}
	if !strings.Contains(got, "first errors") {
		t.Errorf("no heading to say where those lines came from:\n%s", got)
	}
}

// A build that stops AT its error already shows it in the tail; repeating it
// above would make every ordinary failure report read twice.
func TestTailDoesNotRepeatAnErrorItAlreadyShows(t *testing.T) {
	tw := &tailWriter{w: io.Discard, max: 5}
	fmt.Fprintln(tw, "configuring")
	fmt.Fprintln(tw, "conf.c:1:1: error: broken")
	got := tw.tail()
	if strings.Contains(got, "first errors") {
		t.Errorf("heading added for an error the tail already carries:\n%s", got)
	}
	if strings.Count(got, "conf.c:1:1") != 1 {
		t.Errorf("error repeated:\n%s", got)
	}
}

func TestErrorLine(t *testing.T) {
	for _, s := range []string{
		"foo.c:1:2: error: bad",
		"CMake Error: no",
		"ld: undefined reference to `x'",
		"make: *** No rule to make target 'z'",
		"clang: error: cannot find -lfoo",
		"./gen.sh: /bin/bash: bad interpreter: No such file or directory",
		"make[1]: *** [Makefile:2065: .] Error 2",
		// gcc's configure refusing a target: the only line in a 151 KB log that
		// said why the build stopped, and the one the artefact used to miss.
		"*** Configuration aarch64-apple-darwin20.0.0 not supported",
		"\t*** The C compiler cannot create executables",
	} {
		if !errorLine(s) {
			t.Errorf("errorLine(%q) = false", s)
		}
	}
	// A build says these constantly without having failed. Matching them would
	// fill the kept lines with noise before the real error ever appeared.
	for _, s := range []string{
		"  CC      lib/error_handling.o",
		"cc -Werror -c foo.c",
		"0 errors, 3 warnings",
		"checking for error_at_line... yes",
		"make[2]: Leaving directory '/x'",
		// `***` mid-line is a banner or a comment, not a diagnostic.
		"echo '*** building stage 2 ***'",
		"  /* *** internal *** */",
	} {
		if errorLine(s) {
			t.Errorf("errorLine(%q) = true", s)
		}
	}
}

// The kept set is bounded and holds the FIRST errors: under parallelism the
// first failure is the cause and what follows is often its consequence.
func TestTailErrorsAreBoundedAndFirst(t *testing.T) {
	tw := &tailWriter{w: io.Discard, max: 1}
	for i := 0; i < failErrorLines+10; i++ {
		fmt.Fprintf(tw, "a.c:%d:1: error: number %d\n", i, i)
	}
	fmt.Fprintln(tw, "done")
	got := tw.tail()
	if strings.Count(got, "error: number") != failErrorLines {
		t.Errorf("kept %d error lines, want %d", strings.Count(got, "error: number"), failErrorLines)
	}
	if !strings.Contains(got, "number 0") || strings.Contains(got, "number 25") {
		t.Errorf("kept the wrong end of the errors:\n%s", got)
	}
}

// A recipe that declares it does not target the platform being built is not
// attempted. `platforms:` was parsed and consulted by nobody, so a darwin run
// walked into every linux-only recipe and collected the failure. Of the 81
// pantry recipes whose platforms: excludes darwin, the seven that do have a
// darwin artifact are all MIRRORS — this factory has never built one, so nothing
// that could succeed is being dropped.
func TestRunFactorySkipsARecipeThatDoesNotTargetThePlatform(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "linuxonly.org",
		"platforms: linux\nversions:\n  github: a/l/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "portable.org",
		"versions:\n  github: a/p/tags\nbuild: make\n")

	if code := h.run(t, "--platform", "darwin/aarch64",
		"--recipes", "linuxonly.org portable.org", "--to", "oci://example.test/pkgs"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	for _, b := range h.built {
		if strings.HasPrefix(b, "linuxonly.org@") {
			t.Errorf("built %q; the recipe says it does not target darwin", b)
		}
	}
	if !strings.Contains(h.out.String(), "SKIP linuxonly.org (recipe does not target darwin/aarch64)") {
		t.Errorf("no reason given for the skip:\n%s", h.out.String())
	}
	// A skip is not a failure, and it is counted as what it is.
	if !strings.Contains(h.out.String(), "1 skipped") {
		t.Errorf("skip not counted:\n%s", h.out.String())
	}
	// The control: the portable recipe beside it still builds.
	if got := strings.Join(h.built, " "); !strings.Contains(got, "portable.org@") {
		t.Errorf("built = %q, want portable.org among them", got)
	}
}

// One tailWriter is the shell runner's stdout AND stderr, and mvdan.cc/sh runs
// a script's commands in goroutines, so Write is called from several at once.
// Unsynchronised it re-slices its buffer under another goroutine's index and
// takes the whole factory run down:
//
//	panic: runtime error: slice bounds out of range [43:0]
//
// Measured on go-zpkg/packages run 35504607323 (darwin/x86-64), where grpc.io
// had finished compiling and the panic discarded the run's two built artifacts.
func TestTailWriterIsWrittenFromSeveralGoroutines(t *testing.T) {
	const writers, each = 8, 200
	tw := &tailWriter{w: io.Discard, max: 50}
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range each {
				// Mixed shapes: whole lines, several lines at once, and
				// fragments that leave a partial line behind — the last is what
				// makes the buffer non-empty between calls.
				switch j % 3 {
				case 0:
					fmt.Fprintf(tw, "writer %d line %d\n", i, j)
				case 1:
					fmt.Fprintf(tw, "a %d\nb %d\nc %d\n", i, j, i)
				default:
					fmt.Fprintf(tw, "partial %d-%d ", i, j)
				}
			}
		}(i)
	}
	wg.Wait()

	// Nothing to assert about WHICH lines survive — they interleave by design.
	// What must hold is that the writer is still coherent: at most max lines,
	// and a tail that can be read.
	if got := len(tw.lines); got > tw.max {
		t.Errorf("kept %d lines, max is %d", got, tw.max)
	}
	if tw.tail() == "" {
		t.Error("tail is empty after 1600 writes")
	}
}

// TestRunFactoryReportsAToolchainPerlDrift: said once, at the top, instead of
// forty times in the middle.
//
// The base toolchain pins perl for the XS-bearing tools inside it. When one of
// those recipes moves, every autotools recipe that generates a man page dies at
// install time on a module it cannot load — and the message names a C file, not
// a pin, so no single failure points at the cause. gnu.org/libidn2 and
// gnu.org/fribidi both failed that way before this existed.
func TestRunFactoryReportsAToolchainPerlDrift(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "app.org", "versions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "gnu.org/texinfo",
		"dependencies:\n  perl.org: ~5.99\nversions:\n  github: a/t/tags\nbuild: make\n")

	if code := h.run(t, "--recipes", "app.org", "--to", "oci://example.test/pkgs"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	got := h.errb.String()
	for _, want := range []string{"toolchain:", "gnu.org/texinfo", "~5.99", build.ToolchainPerl} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr does not mention %q:\n%s", want, got)
		}
	}
	// Reported, not refused: the run still built.
	if len(h.built) == 0 {
		t.Error("a toolchain warning must not stop the run")
	}
}

// TestRunFactoryBootstrapReachesTheRunnerAndSaysSo.
//
// Two things, and the second matters as much as the first. The flag has to
// reach the Runner, or it changes nothing. And it has to be in the RUN'S OWN
// LOG, because an artifact built this way was driven by whatever tools the host
// had, and six months later the log is the only place that fact still lives.
func TestRunFactoryBootstrapReachesTheRunnerAndSaysSo(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	var runner *build.Runner
	buildFactory = func(string) *build.Runner { runner = &build.Runner{}; return runner }

	if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1", "--bootstrap"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if !runner.Bootstrap {
		t.Error("--bootstrap did not reach the Runner")
	}
	if !strings.Contains(h.out.String(), "BOOTSTRAP:") {
		t.Errorf("a run that changes what an artifact IS must say so:\n%s", h.out.String())
	}
}

// And the default: ordinary runs must neither set it nor print the warning,
// or the warning stops meaning anything.
func TestRunFactoryIsNotBootstrapByDefault(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	var runner *build.Runner
	buildFactory = func(string) *build.Runner { runner = &build.Runner{}; return runner }

	if code := h.run(t, "--recipes", "lib.org", "--max-versions", "1"); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if runner.Bootstrap {
		t.Error("Bootstrap must be off unless asked for")
	}
	if strings.Contains(h.out.String(), "BOOTSTRAP:") {
		t.Errorf("an ordinary run must not claim to be a seed:\n%s", h.out.String())
	}
}

// TestFactoryBuildsTheDependencyVersionItsDependentsCanUse.
//
// The real failure, reduced: python.org asks bytereef.org/mpdecimal for `2`,
// the factory resolved the dependency against "*" and built 4.0.1, and
// python's own build then said
//
//	resolve deps: no version of bytereef.org/mpdecimal satisfies "2"
//	(available: 1)
//
// one dispatch and one wasted build later. The constraint was in the dep spec
// the closure walk had already read.
func TestFactoryBuildsTheDependencyVersionItsDependentsCanUse(t *testing.T) {
	f := &factory{demands: map[string][]string{
		"dep.org":  {"2"},
		"many.org": {">=3<3.12", "~3.11", ">=3<3.15"},
		"none.org": {"~5.42", "~5.44"},
	}}
	old := factoryList
	t.Cleanup(func() { factoryList = old })
	factoryList = func(any) ([]versions.VersionTag, error) {
		return []versions.VersionTag{
			{Version: "5.44.1"}, {Version: "5.42.3"}, // perl-shaped
			{Version: "4.0.1"}, {Version: "2.5.1"}, {Version: "1.0.0"}, // mpdecimal-shaped
			{Version: "3.14.7"}, {Version: "3.11.9"}, {Version: "3.11.2"}, // python-shaped
		}, nil
	}
	rec := &pantry.Recipe{}

	// Newest that satisfies the one constraint — 4.0.1 is newest and does not.
	if v, err := f.versionsFor(rec, "dep.org", false, 0); err != nil || len(v) != 1 || v[0] != "2.5.1" {
		t.Errorf("dep.org = %v %v, want [2.5.1]", v, err)
	}
	// EVERY constraint, not the first: only a 3.11.x satisfies all three, and
	// the newest such is 3.11.9.
	if v, err := f.versionsFor(rec, "many.org", false, 0); err != nil || len(v) != 1 || v[0] != "3.11.9" {
		t.Errorf("many.org = %v %v, want [3.11.9]", v, err)
	}
	// No version can satisfy both lines. The error names them, because the
	// answer is two builds and not a choice the factory can make.
	_, err := f.versionsFor(rec, "none.org", false, 0)
	if err == nil {
		t.Fatal("want a refusal")
	}
	for _, want := range []string{"none.org", "~5.42", "~5.44"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q: %v", want, err)
		}
	}
	// A project nothing constrains keeps the old path: newest, resolved.
	oldRes := factoryResolve
	t.Cleanup(func() { factoryResolve = oldRes })
	factoryResolve = func(any, string) (string, string, error) { return "9.9.9", "", nil }
	if v, err := f.versionsFor(rec, "free.org", false, 0); err != nil || len(v) != 1 || v[0] != "9.9.9" {
		t.Errorf("free.org = %v %v, want [9.9.9]", v, err)
	}
	// And a candidate list that cannot be read is an error, not "no constraint".
	factoryList = func(any) ([]versions.VersionTag, error) { return nil, errors.New("boom") }
	if _, err := f.versionsFor(rec, "dep.org", false, 0); err == nil {
		t.Error("an unreadable version list must surface")
	}
}

// The closure walk RECORDS what each dependent asked for; it used to read the
// constraint off every dep spec and drop it.
func TestClosureOfCollectsDemands(t *testing.T) {
	dir := t.TempDir()
	write := func(proj, body string) {
		t.Helper()
		p := filepath.Join(dir, "projects", filepath.FromSlash(proj))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "package.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.org", "dependencies:\n  dep.org: '2'\n  free.org: '*'\nbuild: make\n")
	write("dep.org", "dependencies:\n  free.org: ^1\nbuild: make\n")
	write("free.org", "build: make\n")

	order, demands, _ := closureOf(nil, "", dir, target.Target{Platform: "linux", Arch: "x86-64"}, []string{"app.org"}, func(string) {})
	if len(order) != 3 || order[len(order)-1] != "app.org" {
		t.Errorf("order = %v, want deps before app.org", order)
	}
	if got := demands["dep.org"]; len(got) != 1 || got[0] != "2" {
		t.Errorf("dep.org demands = %v", got)
	}
	// Two dependents, two constraints, recorded once each and sorted.
	if got := demands["free.org"]; len(got) != 1 || got[0] != "^1" {
		t.Errorf("free.org demands = %v — `*` says nothing and must not be recorded", got)
	}
	// A project nobody constrains has no entry at all, rather than an empty
	// slice that would read as "constrained by nothing".
	if _, in := demands["app.org"]; in {
		t.Errorf("a root nobody depends on must not appear: %v", demands)
	}
}

// TestFactoryPinsARequestedProjectToItsDependents.
//
// A REQUESTED project is not held to what depends on it, because naming a
// project is how an operator says "this version, whatever else wants". A SEED
// is the other case: there every project is named, so nothing is held to
// anything — which is how gnu.org/gcc came out at 16.2.0 after twenty-five
// minutes of compiling, while gnu.org/glibc asks for 14.
func TestFactoryPinsARequestedProjectToItsDependents(t *testing.T) {
	old := factoryList
	t.Cleanup(func() { factoryList = old })
	factoryList = func(any) ([]versions.VersionTag, error) {
		return []versions.VersionTag{
			{Version: "16.2.0"}, {Version: "15.1.0"}, {Version: "14.4.0"}, {Version: "14.1.0"},
		}, nil
	}
	rec := &pantry.Recipe{}
	demands := map[string][]string{"gnu.org/gcc": {"14"}}

	// OFF: the newest, as before. A repair run keeps its answer.
	off := &factory{demands: demands, stdout: io.Discard}
	if v, err := off.versionsFor(rec, "gnu.org/gcc", true, 1); err != nil || v[0] != "16.2.0" {
		t.Errorf("off = %v %v, want [16.2.0]", v, err)
	}

	// ON: the newest its dependents can use.
	var out bytes.Buffer
	on := &factory{demands: demands, pinToDependents: true, stdout: &out}
	v, err := on.versionsFor(rec, "gnu.org/gcc", true, 1)
	if err != nil || len(v) != 1 || v[0] != "14.4.0" {
		t.Fatalf("on = %v %v, want [14.4.0]", v, err)
	}
	// Said out loud, and naming the constraint: an operator reading "2 dropped"
	// has to know which knob moved.
	if !strings.Contains(out.String(), "dropped by its dependents") || !strings.Contains(out.String(), "14") {
		t.Errorf("the drop must be reported with its reason: %q", out.String())
	}

	// An explicit pin still WINS: the operator was specific, and a recipe
	// elsewhere in the pantry does not get to overrule that.
	pinned := &factory{
		demands: demands, pinToDependents: true,
		wantPer: map[string]string{"gnu.org/gcc": "=16.2.0"},
		stdout:  io.Discard,
	}
	if v, err := pinned.versionsFor(rec, "gnu.org/gcc", true, 1); err != nil || v[0] != "16.2.0" {
		t.Errorf("an explicit pin must win: %v %v", v, err)
	}

	// Nothing left is an ERROR naming the constraints, not an empty build set
	// that would look like "already published".
	none := &factory{
		demands:         map[string][]string{"gnu.org/gcc": {"~5.42", "~5.44"}},
		pinToDependents: true, stdout: io.Discard,
	}
	if _, err := none.versionsFor(rec, "gnu.org/gcc", true, 1); err == nil {
		t.Error("want a refusal")
	} else if !strings.Contains(err.Error(), "~5.42") || !strings.Contains(err.Error(), "~5.44") {
		t.Errorf("the refusal must name them: %v", err)
	}

	// A project nothing constrains is untouched, with the flag on.
	free := &factory{demands: demands, pinToDependents: true, stdout: io.Discard}
	if v, err := free.versionsFor(rec, "other.org", true, 1); err != nil || v[0] != "16.2.0" {
		t.Errorf("unconstrained = %v %v", v, err)
	}
}

// TestFactoryDropsAPublishedBuildTree.
//
// The Runner clears a tree at the start of that project's own build, which is
// enough for one build and nothing for a run of seventy-six. The s390x seed
// filled its disk on the fifty-seventh — `no space left on device`, fetching
// the kernel headers, with every earlier tree still there and gcc's among them.
func TestFactoryDropsAPublishedBuildTree(t *testing.T) {
	old := factoryRemoveAll
	t.Cleanup(func() { factoryRemoveAll = old })
	var removed []string
	factoryRemoveAll = func(p string) error {
		removed = append(removed, p)
		return nil
	}

	// ⛔ THE STAGED INSTALL IS NAMED AFTER THE BUILD'S IDENTITY, so the sweep
	// has to be told which build it is clearing: `v1.2.3+brewing` named a
	// version, and two builds of one version staged into the same directory.
	const hash = "abcdefghijklmnop"

	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	f := &factory{tgt: tgt, stderr: io.Discard}
	f.dropBuildTree("acme.org/tool", "1.2.3", hash)
	if len(removed) != 2 {
		t.Fatalf("removed = %v, want the build tree and its staged install", removed)
	}
	p := config.Compute("acme.org/tool", "1.2.3", hash, tgt)
	if removed[0] != p.Build || removed[1] != p.BuildInstall {
		t.Errorf("removed = %v, want [%s %s]", removed, p.Build, p.BuildInstall)
	}
	// The INSTALL prefix is not swept: that is the artifact's own content, and
	// the Runner already owns its lifetime.
	for _, r := range removed {
		if r == p.Install {
			t.Errorf("the install prefix must not be removed here: %v", removed)
		}
	}

	// --keep-build-trees leaves everything, for the operator who wants to look.
	removed = nil
	keep := &factory{tgt: tgt, keepBuildTrees: true, stderr: io.Discard}
	keep.dropBuildTree("acme.org/tool", "1.2.3", hash)
	if len(removed) != 0 {
		t.Errorf("nothing must be removed: %v", removed)
	}

	// A removal that fails is REPORTED. Silence would leave the disk filling
	// and the next failure would name a different project.
	var errb bytes.Buffer
	factoryRemoveAll = func(string) error { return errors.New("device busy") }
	(&factory{tgt: tgt, stderr: &errb}).dropBuildTree("acme.org/tool", "1.2.3", hash)
	if !strings.Contains(errb.String(), "could not remove") || !strings.Contains(errb.String(), "device busy") {
		t.Errorf("stderr = %q", errb.String())
	}
}

// TestPinToDependentsOnlySeesThisRunsDependents.
//
// The limitation, held by a test because I shipped the flag believing
// otherwise. The demands come from the closure walk over the REQUESTED set, so
// a batch that never reaches gnu.org/glibc never learns that glibc asks gcc
// for 14 — and a seed dispatched as `gnu.org/gcc info-zip.org/zip
// kernel.org/linux-headers` with the flag ON still built 16.2.0.
func TestPinToDependentsOnlySeesThisRunsDependents(t *testing.T) {
	old := factoryList
	t.Cleanup(func() { factoryList = old })
	factoryList = func(any) ([]versions.VersionTag, error) {
		return []versions.VersionTag{{Version: "16.2.0"}, {Version: "14.4.0"}}, nil
	}
	rec := &pantry.Recipe{}

	// The dependent is in the run: the constraint is known and applied.
	withGlibc := &factory{
		demands:         map[string][]string{"gnu.org/gcc": {"14"}},
		pinToDependents: true, stdout: io.Discard,
	}
	if v, _ := withGlibc.versionsFor(rec, "gnu.org/gcc", true, 1); v[0] != "14.4.0" {
		t.Errorf("with the dependent in the closure = %v, want [14.4.0]", v)
	}

	// The dependent is NOT in the run: nothing was recorded, so nothing is
	// applied, and the newest is built. That is not a bug in the filter — the
	// walk never saw the demand — but it is a trap, and the flag's help says
	// so now.
	withoutGlibc := &factory{
		demands:         map[string][]string{}, // glibc was not in this batch
		pinToDependents: true, stdout: io.Discard,
	}
	if v, _ := withoutGlibc.versionsFor(rec, "gnu.org/gcc", true, 1); v[0] != "16.2.0" {
		t.Errorf("without the dependent = %v — this documents the limit, not an aspiration", v)
	}
}

// The logical overrides reach the recipe the factory BUILDS, and a broken one
// stops the run rather than quietly building the unoverridden recipe.
func TestRunFactoryAppliesLogicalOverrides(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "app.org", "versions:\n  github: a/app/tags\nbuild: make\ndependencies:\n  openssl.org: ^1.1\n")

	ovDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ovDir, "app.hcl"), []byte(`
project = "app.org"
why     = "our registry carries no openssl 1.x"
edits   = [{ path = "dependencies[\"openssl.org\"]", set = "^3" }]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	code := h.run(t, "--recipes", "app.org", "--overrides", ovDir, "--to", "oci://example.test/pkgs")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if !strings.Contains(h.out.String(), "1 logical override(s)") {
		t.Errorf("the run must say how many it carries:\n%s", h.out.String())
	}
	// It reached the recipe: openssl.org is now in the closure at ^3, so the
	// walk visited it. Had the override not been applied the closure would
	// still name it, so assert the CONSTRAINT rather than the presence.
	if !strings.Contains(h.out.String(), "closure:") {
		t.Errorf("no closure line:\n%s", h.out.String())
	}
}

func TestRunFactoryRefusesABrokenLogicalOverride(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "app.org", "versions:\n  github: a/app/tags\nbuild: make\n")
	ovDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ovDir, "bad.hcl"), []byte("project = "), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := h.run(t, "--recipes", "app.org", "--overrides", ovDir, "--to", "oci://example.test/pkgs"); code == 0 {
		t.Fatalf("an override that does not parse must stop the run; stderr = %s", h.errb.String())
	}
}

// TestEnvBool. `FORCE=0` used to mean FORCE, because every one of these flags
// read `os.Getenv(k) != ""` — the shell's `[ -n "$X" ]` convention, which is
// wrong the moment anyone writes the value out rather than leaving it unset.
//
// Measured on the s390x seed's own registry, 2026-09-29, everything else held:
//
//	FORCE unset   ⏭  SKIP zlib.net 1.3.2 — already published   0 built, 1 skipped
//	FORCE=0       ✅ OK zlib.net 1.3.2                         1 built, 0 skipped
func TestEnvBool(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
		why  string
	}{
		{"", false, "unset is off, as it always was"},
		{"0", false, "THE defect: a non-empty string that means false"},
		{"false", false, ""},
		{"FALSE", false, ""},
		{"False", false, ""},
		{"f", false, ""},
		{"1", true, ""},
		{"true", true, ""},
		{"TRUE", true, ""},
		{"t", true, ""},
		// Anything else non-empty stays TRUE: that is what it meant yesterday,
		// and `FORCE=yes` must not quietly start meaning no.
		{"yes", true, "not a ParseBool word, and it meant true before this"},
		{"on", true, ""},
		{"please", true, ""},
		{" ", true, "a space is not emptiness"},
	} {
		name := tc.val
		if name == "" {
			name = "(unset)"
		}
		t.Run(name, func(t *testing.T) {
			if tc.val == "" {
				os.Unsetenv("ZPKB_TEST_BOOL")
			} else {
				t.Setenv("ZPKB_TEST_BOOL", tc.val)
			}
			if got := envBool("ZPKB_TEST_BOOL"); got != tc.want {
				t.Errorf("envBool(%q) = %v, want %v  %s", tc.val, got, tc.want, tc.why)
			}
		})
	}
}
