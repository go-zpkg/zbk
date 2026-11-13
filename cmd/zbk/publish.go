package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-attest/sbom"
	"github.com/go-attest/sbom/provenance"

	"github.com/go-attest/sign"
	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/build"
	"github.com/go-zpkg/zbk/fixup"
	"github.com/go-zpkg/zbk/moustache"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// OCI artifactType / mediaType of each attestation attached as a referrer.
const (
	artifactCycloneDX = "application/vnd.cyclonedx+json"
	artifactInToto    = "application/vnd.in-toto+json"
	// artifactOpenVEX is the media type an OpenVEX document is attached under.
	// It is what makes the rebuild's JUSTIFICATION travel with the bottle
	// rather than live in a repository nobody downstream reads.
	artifactOpenVEX = "application/vnd.openvex+json"
	buildType       = "https://github.com/go-zpkg/zbk/buildtype@v1"
	builderID       = "https://github.com/go-zpkg/zbk"
)

// seams (swapped in tests).
var (
	osReadFile    = os.ReadFile
	osCreateTemp  = os.CreateTemp
	nowFn         = time.Now
	sbomJSON      = func(d sbom.Document) ([]byte, error) { return d.CycloneDX() }
	provJSON      = func(s provenance.Statement) ([]byte, error) { return s.JSON() }
	simpleSigning = sign.SimpleSigningPayload
	ociPush       = func(distBase, project, ver, osn, arch string, tarball []byte, ext string, refs []bottle.Referrer, annotations map[string]string) (ocispec.Descriptor, error) {
		c, err := bottle.NewOCIClient(distBase)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		// The DESCRIPTOR, not just an error: the end-of-run index check needs to
		// name the manifest it is looking for, and it cannot discover it — that
		// lookup would go through the index whose contents are in question.
		return c.PushWithReferrersAnnotated(project, ver, osn, arch, tarball, ext, refs, annotations)
	}
)

// libcSoname is the C library's soname — the ELF whose .note.ABI-tag records
// glibc's minimum supported kernel.
const libcSoname = "libc.so.6"

// glibcMinKernelFromTarball finds the C library inside a bottle tarball and
// returns glibc's minimum supported kernel (from its .note.ABI-tag) — the value
// stamped as the org.go-zpkg.glibc.min-kernel annotation on a glibc bottle so a
// glibc-by-kernel selector can pick it. ext is ".tar.gz" or ".tar.xz".
//
// Where the ELF lives depends on the glibc vintage: a modern bottle ships
// lib/glibc-X.Y/libc.so.6 as a regular file, while glibc before 2.34 ships the
// image as libc-X.Y.so with libc.so.6 a SYMLINK to it (tar carries no content
// for a symlink). Both are handled — and `libc.so` is deliberately not, since
// that one is a linker script, not an ELF.
// ABIProvidesAnnotation lists the sonames a bottle's shared libraries call
// themselves by, comma-separated and sorted.
//
// The compatibility key of a shared library is its soname, and a pkgx
// constraint cannot express one: libxml2 2.13.9 ships libxml2.2.dylib and
// 2.15.4 ships libxml2.16.dylib, and `^2` admits both. Recording what a bottle
// PROVIDES is the half that can be computed locally; with it, a checker can ask
// of any published version whether it still provides the soname a dependent
// recorded, and refuse a constraint that cannot honour it
// (go-zpkg/packages#207).
//
// It belongs beside GlibcVersionAnnotation in go-zpkg/bottle once a resolver
// reads it; today only bk writes it, so it lives here rather than forcing a
// cross-repo bump for a field nothing consumes yet.
const ABIProvidesAnnotation = "org.go-zpkg.abi.provides"

// sonamesFromTarball reads the ABI name of every shared library in a bottle.
//
// bottle.Decompressor, not a local one: every format this factory has ever
// published is handled there, and a reader taught two of the three fails with
// "gzip: invalid header" on a .tar.zst — which is the default, so the first
// version of this wrote the annotation on nothing at all.
//
// From the tarball rather than the build tree so it also describes a bottle we
// did not build — a mirrored one carries whatever upstream linked, and that is
// exactly the case where nobody knows what is inside (go-zpkg/packages#147).
//
// ⛔ ONLY FILES A CONSUMER COULD EVER LOAD. It used to read EVERY regular file
// in the tarball, and the published go.dev 1.27.3 bottle therefore announced
//
//	org.go-zpkg.abi.provides = libtiffxx.so.6
//
// on darwin/aarch64 AND linux/x86-64 — because the Go distribution ships
// `src/debug/elf/testdata/libtiffxx.so_`, a TEST FIXTURE of the standard
// library's ELF reader. Go ships no shared libraries at all. Reported as the
// second observation on go-zpkg/pkgm#73, where the stray `abi-libtiffxx.so.6
// -> v1.27.3` symlink turned up inside the go.dev store directory.
//
// That is not cosmetic: the whole point of the annotation is that the resolver
// keys ABI compatibility on sonames (go-zpkg/bottle#83) and a consumer binds
// through `abi-<soname>`. A claim to provide libtiffxx.so.6 is an offer to
// satisfy a libtiff consumer with the Go toolchain.
//
// So the publisher now describes exactly what the consumer can search:
// bottle.LibDirs puts `<prefix>/lib`, `<prefix>/lib64` and `lib/glibc-*` on
// LD_LIBRARY_PATH and nothing else, so a soname found anywhere else is a claim
// nothing could honour. Judge and subject count alike.
func sonamesFromTarball(tarball []byte, ext string) ([]string, error) {
	r, closeFn, err := bottle.Decompressor(ext, bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	defer closeFn()
	var out []string
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// Regular files only: a symlink IS the soname in most layouts
		// (libz.1.dylib -> libz.1.3.2.dylib) and would double-count.
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// And only where a consumer would look for it. Reading the rest is
		// what published libtiffxx.so.6 as an ABI of the Go toolchain.
		if !inLibDir(h.Name) {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if s := fixup.SonameOf(b); s != "" {
			out = append(out, s)
		}
	}
	return fixup.SortedUnique(out), nil
}

// inLibDir reports whether a tarball path is inside a directory the consumer
// puts on LD_LIBRARY_PATH. The list is bottle.LibDirs' own: `lib`, `lib64`,
// and lib's `glibc-*` sub-libdir.
//
// By path COMPONENT, not by prefix: `libexec/` starts with "lib" and holds
// helper programs nobody links against, and `src/.../testdata/` is where the
// defect came from. The components are checked all the way down rather than
// only at the top, because glibc's real libraries live in `lib/glibc-2.41/`
// and a bottle built with a `--libdir` of its own can nest one deeper.
func inLibDir(name string) bool {
	parts := strings.Split(path.Clean(name), "/")
	// The last element is the file itself, so a bare `lib` file is not "in"
	// a lib dir — there has to be a directory component above it.
	for _, p := range parts[:max(len(parts)-1, 0)] {
		if p == "lib" || p == "lib64" {
			return true
		}
	}
	return false
}

// bottle.Decompressor, for the reason sonamesFromTarball gives directly above
// — and this function is where that reason was NOT applied. It knew xz and
// assumed gzip for everything else, so on a .tar.zst, which is the default
// codec, glibc's publish died on
//
//	❌ PUBLISH FAIL gnu.org/glibc 2.44: gzip: invalid header
//
// after a build that had taken hours. Nothing else showed it because nothing
// else calls this: it is glibc's alone.
//
// The comment above was written when the SAME defect was found in the function
// above. A warning left beside the code it warns about is not a fix for the
// code next to it.
func glibcMinKernelFromTarball(tarball []byte, ext string) (string, error) {
	r, closeFn, err := bottle.Decompressor(ext, bytes.NewReader(tarball))
	if err != nil {
		return "", err
	}
	defer closeFn()
	tr := tar.NewReader(r)
	var linkTarget string         // what libc.so.6 points at, when it is a symlink
	images := map[string][]byte{} // candidate ELFs, by base name
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		base := filepath.Base(h.Name)
		switch {
		case h.Typeflag == tar.TypeSymlink && base == libcSoname:
			linkTarget = filepath.Base(h.Linkname)
		case h.Typeflag == tar.TypeReg && (base == libcSoname || isLibcImage(base)):
			b, err := io.ReadAll(tr)
			if err != nil {
				return "", err
			}
			images[base] = b
		}
	}
	image, ok := images[libcSoname]
	if !ok {
		image, ok = images[linkTarget]
	}
	if !ok {
		return "", fmt.Errorf("%s not found in tarball", libcSoname)
	}
	// GlibcMinKernel wants a path; stage the ELF to a temp file.
	f, err := osCreateTemp("", "libc-*.so.6")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(image); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	return bottle.GlibcMinKernel(f.Name())
}

// isLibcImage reports whether a file name is glibc's versioned C library image
// (libc-2.17.so), the real ELF that a pre-2.34 bottle's libc.so.6 links to.
func isLibcImage(base string) bool {
	return strings.HasPrefix(base, "libc-") && strings.HasSuffix(base, ".so")
}

// runPublish implements `bk publish`: push a built bottle to an OCI registry
// with a CycloneDX SBOM and an in-toto SLSA provenance statement attached as
// referrers.
func runPublish(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("publish", flag.ContinueOnError)
	f.SetOutput(stderr)
	to := f.String("to", "", "oci:// destination base, e.g. oci://ghcr.io/go-zpkg/bottles")
	project := f.String("project", "", "pkgx project, e.g. sqlite.org")
	version := f.String("version", "", "version, e.g. 3.46.0")
	platform := f.String("platform", "", "bottle os/arch, e.g. darwin/x86-64")
	signKey := f.String("sign", "", "sign the bottle with this go-attest/sign secret key file")
	glibc := f.String("glibc", "", "glibc version this bottle was built against; publishes under the flavored tag <version>-glibc<ver> so builds against different glibc coexist (linux only)")
	advisories := f.String("advisories", "", "advisory tree to look this project up in; attaches an OpenVEX document saying what was decided about each vulnerability")
	var specDeps depFlag
	f.Var(&specDeps, "spec-dep", "a resolved dependency of this build, `project=version[=hash]`, repeatable. For a lane that builds without a pantry plan — a Go cross-build, say — this is how the TOOLCHAIN gets into the identity, which is the whole point: a rebuild against a patched Go must not land on the first one's address")
	specRecipe := f.String("spec-recipe", "", "digest of the resolved build — the script after substitution, the environment, the flags. ⛔ NOT a digest of a recipe FILE: a reflowed comment would rebuild the world")
	specRecipeFrom := f.String("spec-recipe-from", "", "`file` describing the resolved build; its sha256 becomes the recipe digest. For a lane whose build is a command rather than a pantry script: write what decided the output — module, version, package, GOOS/GOARCH, flags, toolchain — and let this digest it, instead of computing a hash in the shell")
	allowUnsigned := f.Bool("allow-unsigned", false, "publish without a signature. ⛔ A CLIENT VERIFIES FAIL-CLOSED BY DEFAULT, so an unsigned bottle is one nobody can install without turning verification off")
	allowUnidentified := f.Bool("allow-unidentified", false, "publish without a build identity, under the bare version tag. For a bottle this process did not build — a mirror — where claiming an identity would be a claim nothing supports")
	if err := f.Parse(args); err != nil {
		return 2
	}
	if *to == "" || *project == "" || *version == "" || *platform == "" || f.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: bk publish --to oci://… --project P --version V --platform os/arch <bottle>")
		return 2
	}
	osn, arch, ok := splitPlatform(*platform)
	if !ok {
		fmt.Fprintf(stderr, "publish: bad --platform %q (want os/arch)\n", *platform)
		return 2
	}
	var kp *sign.Keypair
	if *signKey != "" {
		k, err := loadSigningKey(*signKey)
		if err != nil {
			fmt.Fprintln(stderr, "publish:", err)
			return 1
		}
		kp = k
	}
	// ⛔⛔ THE PLATFORM ALONE IS NOT AN IDENTITY, AND BUILDING ONE FROM IT
	// WOULD HAVE DEFEATED THE GATE BELOW. --platform is required, so filling
	// Concrete.Platform unconditionally makes IsZero() permanently false:
	// every publish would have looked identified. Worse, the resulting hash
	// is of the Concrete alone — project and version live in the TAG — so a
	// platform-only spec yields the SAME hash for every project built for
	// that platform. An address that collides across projects is not an
	// address. Found by the gate's own test, which could not make the
	// unidentified case happen.
	recipe, err := recipeDigestFromFlags(*specRecipe, *specRecipeFrom)
	if err != nil {
		fmt.Fprintln(stderr, "publish:", err)
		return 2
	}
	var spec bottle.Concrete
	if recipe != "" || len(specDeps.deps) > 0 {
		spec = bottle.Concrete{Platform: *platform, Deps: specDeps.deps, Recipe: recipe}
	}
	if err := everythingSignedAndIdentified(kp, spec, *allowUnsigned, *allowUnidentified); err != nil {
		fmt.Fprintln(stderr, "publish:", err)
		return 2
	}
	if _, _, err := publishBottle(publishOptions{
		Dist: *to, Project: *project, Version: *version,
		OS: osn, Arch: arch, Path: f.Arg(0), Glibc: *glibc, Key: kp,
		Advisories: *advisories, Concrete: spec,
	}); err != nil {
		fmt.Fprintln(stderr, "publish:", err)
		return 1
	}
	extra := ""
	if kp != nil {
		extra = " +signature"
	}
	fmt.Fprintf(stdout, "published %s %s %s/%s to %s (+SBOM +provenance%s)\n", *project, *version, osn, arch, *to, extra)
	return 0
}

// everythingSignedAndIdentified is the rule, enforced before anything is
// pushed: a bottle this factory publishes says WHO vouches for it and WHAT it
// is, or it is not published.
//
// ⛔⛔ BOTH WERE SILENT, AND SILENCE IS WHY THEY HAPPENED. On 2026-11-05 the
// wasip1 lane published 30 bottles to a fresh registry, green, and every one
// of them was unsigned and unidentified:
//
//	HASH    PUBLISHED  SIGNED BY   BUILT BY     WHAT
//	(none)  yes        ⚠ unsigned  zbk@v0.65.0  nothing recorded
//
// Neither was a bug in the code that ran. `--sign` was simply absent because
// the signing secret had not followed an organisation transfer, and the lane
// builds with a plain `go build` so there was no plan and so no Concrete.
// Both paths did exactly what they were written to do, quietly, and the
// result is thirty artefacts a fail-closed client will refuse to install and
// that no reader can name.
//
// ⛔ THE DEROGATIONS ARE FLAGS WITH NO DEFAULT, AND THEY ARE SEPARATE. One
// `--force` covering both would let a lane that only needed to mirror an
// unidentified bottle also start publishing unsigned ones. A workflow that
// wants either has to write it down, in its own source, where a reader sees
// it — which is the point of making it a flag rather than a warning.
func everythingSignedAndIdentified(kp *sign.Keypair, spec bottle.Concrete, allowUnsigned, allowUnidentified bool) error {
	if kp == nil && !allowUnsigned {
		return errors.New("refusing to publish unsigned: a client verifies fail-closed by default, so this bottle " +
			"would be refused at install time. Pass --sign <key>, or --allow-unsigned to publish one anyway")
	}
	if spec.IsZero() && !allowUnidentified {
		return errors.New("refusing to publish without a build identity: the tag would be the bare version, which " +
			"two different builds can both claim, and nothing would record what this one is. Pass --spec-dep and " +
			"--spec-recipe to state it, or --allow-unidentified for a bottle this process did not build")
	}
	return nil
}

// recipeDigestFromFlags settles --spec-recipe against --spec-recipe-from.
//
// ⛔ BOTH AT ONCE IS REFUSED, NOT RECONCILED. They are two spellings of one
// value, and a precedence rule between them is a second definition of the
// build's identity — the exact shape of a defect this project has already
// paid for once, where two definitions of one hash meant a bottle failed its
// own verification with a message that read as tampering.
//
// The file is digested here rather than in the caller's shell because a
// digest computed by a pipeline is a digest nobody tested, and because the
// bytes that decide an identity should be hashed by the thing that records
// it.
func recipeDigestFromFlags(literal, from string) (string, error) {
	if literal != "" && from != "" {
		return "", errors.New("--spec-recipe and --spec-recipe-from both given: they are two spellings of one value, " +
			"and choosing between them here would be a second definition of this build's identity")
	}
	if from == "" {
		return literal, nil
	}
	b, err := os.ReadFile(from)
	if err != nil {
		return "", fmt.Errorf("--spec-recipe-from: %w", err)
	}
	// ⛔ AN EMPTY FILE IS A MISTAKE, NOT A DIGEST. It hashes perfectly well,
	// to the same value for every project that makes the same mistake, so a
	// whole lane could publish under one shared identity and nothing would
	// say so.
	if len(b) == 0 {
		return "", fmt.Errorf("--spec-recipe-from %s is empty: every build that did this would share one identity", from)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// depFlag collects repeated --spec-dep values.
type depFlag struct{ deps []bottle.Dep }

func (d *depFlag) String() string { return "" }

// Set parses `project=version[=hash]`.
//
// ⛔ THE HASH IS OPTIONAL AND ITS ABSENCE IS NOT A FAILURE. A toolchain taken
// from the runner's own image — `setup-go` — has a version and no bottle
// identity, and that is the truth about it. Refusing it would push a lane
// back to publishing nothing at all, which is what this guard exists to end.
func (d *depFlag) Set(s string) error {
	parts := strings.Split(s, "=")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("want project=version[=hash], got %q", s)
	}
	dep := bottle.Dep{Project: parts[0], Version: parts[1]}
	if len(parts) == 3 {
		dep.Hash = parts[2]
	}
	d.deps = append(d.deps, dep)
	return nil
}

// loadSigningKey reads a go-attest/sign secret key file.
func loadSigningKey(path string) (*sign.Keypair, error) {
	kb, err := osReadFile(path)
	if err != nil {
		return nil, err
	}
	kp, err := sign.LoadSecretKey(string(kb))
	if err != nil {
		return nil, explainBadKey(string(kb), err)
	}
	return kp, nil
}

// explainBadKey turns `sign: malformed secret key` into a sentence that names
// the mistake it almost always is.
//
// ⛔⛔ THE BARE MESSAGE COST A WHOLE CYCLE. A factory run on 2026-11-06 said
// `signing: enabled` and then `publish: sign: malformed secret key`, and it
// took an experiment — feeding the parser nine spellings of a key file — to
// learn that the parser is tolerant of every formatting difference (trailing
// newline or not, CRLF, surrounding spaces, a missing comment line) and that
// exactly one thing produces that error: a PUBLIC key where the secret one
// belongs.
//
// It is the easy mistake to make. Both files open with `untrusted comment:`,
// both hold one base64 line, and the one you are told to publish is the
// public one. The only visible difference is the length — 56 characters
// against 96 — which nobody knows to look at.
//
// ⛔ AND IT PRINTS NO KEY MATERIAL. The content here may be a secret key that
// failed for some other reason; echoing it to explain itself would put it in
// a CI log. Only the shape is reported.
func explainBadKey(body string, err error) error {
	if _, _, perr := sign.ParsePublicKey(strings.TrimSpace(lastLine(body))); perr == nil {
		return fmt.Errorf("this is a PUBLIC key, not a secret one: it is the half you publish, "+
			"and it cannot sign. A secret key file's payload line is 96 characters; a public "+
			"key's is 56 (%w)", err)
	}
	return err
}

// lastLine is the payload line of a two-line key file, or the whole thing
// when there is only one.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	return lines[len(lines)-1]
}

// publishOptions describes one bottle push.
type publishOptions struct {
	Dist     string // oci:// destination base
	Project  string // pkgx project slug
	Version  string // TRUE software version (what the SBOM/provenance record)
	OS, Arch string // pkgx-form platform, e.g. linux + x86-64
	Path     string // the built bottle tarball on disk
	Glibc    string // glibc this bottle was built against ("" = system glibc)
	Key      *sign.Keypair
	Time     time.Time // attestation timestamp; zero = buildTime()
	// Source is what the build was made from — the candidate URL that answered
	// and the digest of what came back. Empty for `bk publish` on a bottle this
	// process did not build, and for the few recipes with no distributable.
	Source build.SourceRef
	// BuildEnv is every dependency the build resolved, at the version it used:
	// the compiler, its libc, the tools the recipe invoked. Empty for
	// `bk publish` on a bottle this process did not build — the same honest
	// gap as Source, and for the same reason.
	BuildEnv []moustache.Dep
	// Advisories is the advisory tree to look this project up in. Empty means
	// no VEX document is attached, which is the honest state for a project
	// nobody has triaged.
	Advisories string
	// Origin is what the factory knows about HOW this was built — see
	// provOrigin. Zero means nothing is stated, which is the honest value for
	// `bk publish` on a bottle this process did not build, and which a
	// promotion gate must treat as "not promotable" rather than as "fine".
	Origin provOrigin
	// Concrete is what the build IS: the platform, the resolved closure and
	// the digest of the canonical recipe. It becomes the tag's `-h<hash>` AND
	// the manifest's spec annotation, which is what lets a reader recompute
	// the address from the description instead of taking it on trust.
	//
	// ⛔ THE ZERO VALUE IS A STATEMENT, NOT A GAP TO PAPER OVER. `bk publish`
	// on a bottle this process did not build knows nothing about how it was
	// made, so it publishes an unhashed tag and no annotation — the honest
	// shape for a mirrored bottle, and distinguishable from a build whose
	// description we do hold. bottle.Concrete.Hash() returns "" for it, and
	// bottle.SpecOf reports "no spec" rather than an error.
	Concrete bottle.Concrete
}

// publishBottle pushes a built bottle with its SBOM, SLSA provenance and (given
// a key) signature attached as referrers, and reports the registry tag it landed
// under. Shared by `bk publish` and `bk factory`, so a factory-published bottle
// carries byte-identical attestations, tags and glibc annotations.
// publishBottle returns the registry tag it published under AND the descriptor
// of the per-platform manifest it pushed. The descriptor is what the end-of-run
// index check needs: it cannot discover the manifest, because that lookup would
// go through the very index whose contents are in question.
func publishBottle(o publishOptions) (string, ocispec.Descriptor, error) {
	tarball, err := osReadFile(o.Path)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}
	// The FILE decides the media type, not a flag: a bottle mirrored from an
	// upstream dist arrives in whatever codec that dist used, and mislabelling it
	// would make every puller decompress with the wrong decoder.
	ext := bottle.ExtTarGz
	switch {
	case strings.HasSuffix(o.Path, bottle.ExtTarXz):
		ext = bottle.ExtTarXz
	case strings.HasSuffix(o.Path, bottle.ExtTarZst):
		ext = bottle.ExtTarZst
	}
	// The SBOM/provenance keep the TRUE software version; only the registry TAG
	// gets the glibc flavor, so builds of the same version against different
	// glibc coexist as distinct artifacts (e.g. curl.se:8.20-glibc2.27.0 vs
	// :8.20-glibc2.44.0) instead of colliding on one tag.
	when := o.Time
	if when.IsZero() {
		when = buildTime()
	}
	refs, err := buildReferrers(o.Project, o.Version, o.OS, o.Arch, tarball, o.Source, o.BuildEnv, when, o.Key, o.Origin)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}
	// The JUSTIFICATION, where there is one. A broken advisory file stops the
	// publish rather than becoming a missing document, because an absent VEX
	// reads as "nothing was ever found".
	vexRef, err := vexReferrer(o.Advisories, o.Project, o.Version, o.OS, o.Arch, tarball, when)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}
	if vexRef != nil {
		refs = append(refs, *vexRef)
	}
	tag := buildTag(o.Project, o.Version, o.Glibc, o.Concrete)
	var annotations map[string]string
	// ⛔ THE SPEC GOES ON FIRST, so that nothing below can overwrite it by
	// assigning a fresh map. The tag says WHICH build; this says WHAT build,
	// and bottle.VerifySpec refuses the pair when they disagree — so a bottle
	// published with one and not the other is worse than one published with
	// neither.
	if spec := o.Concrete; !spec.IsZero() {
		annotations = map[string]string{bottle.SpecAnnotation: bottle.MarshalSpec(spec)}
	}
	// ⛔ EVERY BRANCH BELOW ADDS, NONE REPLACES. Each of these used to build a
	// fresh map, which was harmless while the spec did not exist and would
	// now drop it — leaving a tag that claims a hash and a manifest that does
	// not say what the hash is of, which bottle.VerifySpec reads as a bottle
	// that does not match its own description.
	set := func(k, v string) {
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[k] = v
	}
	switch {
	case o.Project == bottle.GlibcProject:
		// The glibc bottle IS the glibc — no flavored tag; instead self-describe
		// its min supported kernel (from libc.so.6's .note.ABI-tag) so a
		// glibc-by-kernel selector can pick it.
		mk, err := glibcMinKernelFromTarball(tarball, ext)
		if err != nil {
			return "", ocispec.Descriptor{}, err
		}
		set(bottle.GlibcMinKernelAnnotation, mk)
	case o.Glibc != "":
		// A tool built against a specific glibc: flavor the tag + self-describe
		// which glibc, so a glibc-aware resolver matches it without parsing tags.
		set(bottle.GlibcVersionAnnotation, strings.TrimPrefix(o.Glibc, "="))
	}
	// Every bottle says which ABIs it provides, whatever else is annotated.
	// A failure to read one is not a reason to refuse the publish: the bottle is
	// correct, the description of it is merely missing, and the alternative is a
	// factory that stops on a field nothing consumes yet.
	if names, err := sonamesFromTarball(tarball, ext); err != nil {
		fmt.Fprintf(os.Stderr, "zbk: could not read the sonames of %s %s: %v\n", o.Project, o.Version, err)
	} else if len(names) > 0 {
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[ABIProvidesAnnotation] = strings.Join(names, ",")
	}
	if err := refuseToMoveATag(o, tag, tarball); err != nil {
		return "", ocispec.Descriptor{}, err
	}
	desc, err := ociPush(o.Dist, o.Project, tag, o.OS, o.Arch, tarball, ext, refs, annotations)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}
	return tag, desc, nil
}

// refuseToMoveATag stops a push that would leave an existing HASHED tag
// resolving to bytes it did not resolve to before.
//
// ⛔⛔ A TAG WHOSE CONTENT CAN CHANGE IS NOT AN ADDRESS. The whole point of
// `<version>-h<hash>` is that it names one build; the hash is computed from
// {platform, variants, closure, recipe} and deliberately NOT from the builder,
// so a zbk whose output differs produces different bytes under the SAME tag.
// Re-publishing then silently rewrites what an existing lock, an existing
// install and an existing signature all refer to — and the signature is the
// loudest of the three, because the old one still verifies against the old
// bytes and now sits beside content it was never made for.
//
// The check is cheap and reads only the manifest: `BottleDigest` takes the
// layer digest off the per-platform manifest without pulling the bottle.
//
// ⛔ IT IS NOT A REBUILD GUARD. Re-publishing the SAME bytes is the normal,
// idempotent case — a retried run, a re-dispatch — and is allowed, silently.
// Only a change of content at a fixed address is refused.
//
// ⛔ AND IT NEVER FAILS CLOSED ON NOT KNOWING. An unreachable registry, a tag
// that does not exist yet, a manifest with no layer: all mean "nothing to
// contradict", and a factory that stopped because it could not reach ghcr
// would turn a network blip into a halted campaign. Only a digest that is
// present AND different refuses.
func refuseToMoveATag(o publishOptions, tag string, tarball []byte) error {
	// A bottle with no identity lands on the bare version, which has always
	// been a moving tag — `bk publish` of something this process did not
	// build cannot know what it is, and that is stated in buildTag.
	if o.Concrete.IsZero() {
		return nil
	}
	published, err := ociBottleDigest(o.Dist, o.Project, tag, o.OS, o.Arch)
	if err != nil || published == "" {
		return nil
	}
	sum := sha256.Sum256(tarball)
	mine := "sha256:" + hex.EncodeToString(sum[:])
	if published == mine {
		return nil
	}
	return fmt.Errorf("refusing to move %s %s (%s/%s): it already resolves to %s and this build is %s.\n"+
		"  A hashed tag names ONE build; rewriting it changes what every existing lock, install and\n"+
		"  signature refers to. If this build really is different, its identity should be too — see\n"+
		"  go-zpkg/zbk#416",
		o.Project, tag, o.OS, o.Arch, published, mine)
}

// flavoredTag is the registry tag a (project, version) lands under BEFORE the
// build's identity is appended: the plain version, or <version>-glibc<ver> for
// a tool built against a pinned glibc. The glibc package itself is never
// flavored (it IS the glibc).
//
// ⛔ THIS IS NOT AN ADDRESS ON ITS OWN ANY MORE. Two builds of one version
// land on it, which is the collision the hash exists to end — see buildTag.
// It survives as the prefix those tags share, which is what lets the builds
// of a version be LISTED.
func flavoredTag(project, version, glibc string) string {
	if glibc == "" || project == bottle.GlibcProject {
		return version
	}
	return version + "-glibc" + strings.TrimPrefix(glibc, "=")
}

// buildTag is the tag a BUILD lands under: the flavoured version with the
// build's identity appended, `1.3.2-habcdefghijklmnop`.
//
// ⛔⛔ THE HASH COMES FROM THE SPEC, NOT FROM A SECOND COMPUTATION. It is
// `Concrete.Hash()`, the same value `bottle.VerifySpec` recomputes from the
// annotation on the other side; a tag built from anything else would make
// every bottle fail its own verification, and the message — "the bottle does
// not match its own description" — reads as tampering rather than as a bug
// here.
//
// An empty spec yields the bare flavoured version. That is `bk publish` on a
// bottle this process did not build: we do not know what it is, so we do not
// give it an address that claims we do.
func buildTag(project, version, glibc string, spec bottle.Concrete) string {
	return flavoredTag(project, version, glibc) + spec.VariantTag()
}

// environmentMaterials renders the build environment as SLSA
// resolvedDependencies: every dependency the build resolved, at the version it
// actually used.
//
// ⛔ THIS IS THE AXIS A VULNERABILITY REBUILD MOVES ALONG. When a Go patch
// release fixes a standard-library defect, nothing about the recipe or the
// upstream version changes — only `go.dev` in this list does. A bottle that
// does not record it cannot be asked "were you built with the fixed
// compiler?", and a rebuild counter over such bottles would be a number
// nobody could derive or check.
//
// A purl rather than a path: the prefix is where this machine put it, which is
// not a fact about the artefact. No digest is claimed, because we have the
// version the build resolved and not the bytes it read — and a material
// asserting a digest it did not verify would be the same empty promise this
// whole change exists to remove.
func environmentMaterials(env []moustache.Dep) []provenance.Material {
	out := make([]provenance.Material, 0, len(env))
	for _, d := range env {
		out = append(out, provenance.Material{URI: purlFor(d.Project, d.Version)})
	}
	return out
}

// builderWithVersion is the SLSA builder id, carrying the bk that ran.
//
// A build with no version information is not one you can ask anything about
// later. bkVersion() reads debug.ReadBuildInfo, so it cannot disagree with the
// binary; a `go run` of a working tree answers "(devel)", which is a true
// statement about a build nobody should publish from and is better recorded
// than hidden.
func builderWithVersion() string { return builderID + "@" + bkVersion() }

// buildParams is what the SLSA statement records as externalParameters: the
// question this build was asked.
//
// ⛔ IT WAS `{}`. The shape of a provenance was published, signed, for every
// bottle in the registry, and it said nothing — not the platform, not the
// version, not even the project. An attestation whose presence implies a
// guarantee it does not give is worse than no attestation, because a reader
// stops looking once they see one.
//
// Only what is KNOWN here goes in. The build-dependency closure and the spec
// hash are the two that matter most and are not in hand at this call; they
// arrive with the plumbing, not with a placeholder, because a field that is
// always empty teaches readers to ignore the block.
func buildParams(project, version, osn, arch string, o provOrigin) map[string]string {
	p := map[string]string{
		"project":  project,
		"version":  version,
		"platform": osn + "/" + arch,
	}
	// Emitted only when STATED,, for the reason the note above gives: a key
	// that is always there and always empty teaches a reader to skip it.
	if o.Bootstrap != "" {
		p["bootstrap"] = o.Bootstrap
	}
	if o.Dist != "" {
		p["inputs-from"] = o.Dist
	}
	return p
}

// provOrigin is what the FACTORY knows about a build and the bottle cannot
// show: whether host tools drove it, and which registry its inputs came from.
//
// ⛔ IT EXISTS BECAUSE "WAS THIS BUILT SOVEREIGNLY" HAD NO ANSWER IN THE
// ARTEFACT. Measured 2026-11-01 on a published bottle:
//
//	$ bk buildenv -platform linux/s390x lz4.org 1.10.0
//	buildenv: lz4.org 1.10.0 (linux/s390x): the provenance records no build
//	environment
//
// An empty build environment is what a `--bootstrap` build produces, because
// it resolves no bottles — so the absence is a HINT and not a statement. It is
// also what an older bk produced, and what `bk publish` produces for a bottle
// this process did not build. Three different situations, one silence.
//
// That silence matters now: go-zpkg/packages#316 needs the s390x toolchain to
// reach ghcr, generations 0 and 1 both publish only to a throwaway loopback
// registry on the VM, and the gate on promoting anything out of it is exactly
// "prove this was not built with the host's compiler". A gate cannot read a
// hint.
//
// ⛔ THREE STATES, NOT A BOOL, AND THE EMPTY ONE MUST NOT BE SAFE. A `bool`
// zero value is false, which would read as "not a bootstrap" — so every
// bottle published before this existed, and every one published by a path
// that does not set it, would claim to be promotable. Unknown has to fail
// closed, so it is a distinct state and the promotion check requires an
// explicit "0".
type provOrigin struct {
	// Bootstrap is "1" when the build took its compiler and shell from the
	// host distribution, "0" when it did not, and "" when nothing was stated.
	Bootstrap string
	// Dist is the registry the build RESOLVED ITS INPUTS FROM — the fact that
	// distinguishes a bottle built against the seed's loopback registry from
	// one built against ghcr, which no digest or signature can show.
	Dist string
}

// boolParam renders a known boolean the way buildParams records it.
func boolParam(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// buildReferrers builds the CycloneDX SBOM and in-toto SLSA provenance
// attestations for a bottle (subject = the bottle itself; the tarball digest
// binds them).
func buildReferrers(project, version, osn, arch string, tarball []byte, src build.SourceRef, env []moustache.Dep, now time.Time, kp *sign.Keypair, origin provOrigin) ([]bottle.Referrer, error) {
	sum := sha256.Sum256(tarball)
	dg := hex.EncodeToString(sum[:])
	purl := purlFor(project, version)

	doc := sbom.Document{Name: project, Version: version, PURL: purl, SHA256: dg, Created: now}
	sb, err := sbomJSON(doc)
	if err != nil {
		return nil, err
	}
	stmt := provenance.Statement{
		Subjects:  []provenance.Subject{{Name: fmt.Sprintf("%s %s %s/%s", project, version, osn, arch), SHA256: dg}},
		BuildType: buildType,
		// ⛔ A BUILDER THAT NEVER CHANGES CANNOT TELL TWO BUILDS APART.
		// builderID was the bare string `https://github.com/go-zpkg/zbk`, so
		// every bottle ever published claimed the identical builder —
		// measured 2026-10-09 on stedolan.github.io/jq, whose signed SLSA
		// statement carries buildDefinition {} and that constant.
		//
		// SLSA says builder.id must identify the build platform closely
		// enough that a change in it is a change in the id. A rebuild for a
		// toolchain security fix is exactly such a change, and the question
		// "which bk built this?" had no answer in the artefact.
		BuilderID:  builderWithVersion(),
		StartedOn:  now,
		FinishedOn: now,
		Params:     buildParams(project, version, osn, arch, origin),
		Materials:  append(materialsOf(src), environmentMaterials(env)...),
	}
	pr, err := provJSON(stmt)
	if err != nil {
		return nil, err
	}
	refs := []bottle.Referrer{
		{ArtifactType: artifactCycloneDX, MediaType: artifactCycloneDX, Blob: sb},
		{ArtifactType: artifactInToto, MediaType: artifactInToto, Blob: pr},
	}
	if kp != nil {
		payload, err := simpleSigning(purl, "sha256:"+dg)
		if err != nil {
			return nil, err
		}
		refs = append(refs, signatureReferrer(payload, kp))
	}
	return refs, nil
}

// signatureReferrer is the one place a signature referrer is built, so the
// publishing path and `zbk sign` cannot drift apart in what they attach.
//
// ⛔ THE KEY ID GOES ON, THE SIGNER'S NAME DOES NOT. A cosign blob signature
// is a bare Ed25519 signature: it does not say which key made it, so a
// verifier facing several signatures would otherwise try every trusted key
// against every one of them. The key id turns that product back into a walk
// — and bottle treats it as a HINT only, trying it first and then the rest,
// so a wrong one costs microseconds and changes no verdict.
//
// A NAME is deliberately absent. It would be written by whoever pushed the
// referrer, and the line it would appear in — "signed by: …" — is the one a
// reader uses to decide whether to trust the artefact. The name a user sees
// comes from their own trust set, which is the only place it means anything.
func signatureReferrer(payload []byte, kp *sign.Keypair) bottle.Referrer {
	ann := map[string]string{
		bottle.CosignSignatureAnnotation: kp.SignPayload(payload),
		bottle.SignerKeyIDAnnotation:     hex.EncodeToString(kp.ID[:]),
	}
	return bottle.Referrer{
		ArtifactType: bottle.ArtifactTypeSignature,
		MediaType:    bottle.MediaSimpleSigning,
		Blob:         payload,
		Annotations:  ann,
	}
}

// buildTime is the timestamp stamped into attestations. It honours
// SOURCE_DATE_EPOCH (the reproducible-builds standard) so re-publishing the
// same bottle yields byte-identical SBOM/provenance — hence the same referrer
// digests, so a re-push is idempotent instead of accumulating duplicates. With
// the variable unset (or unparseable) it falls back to the wall clock.
func buildTime() time.Time {
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	return nowFn().UTC()
}

// splitPlatform parses "os/arch".
func splitPlatform(p string) (osn, arch string, ok bool) {
	i := strings.IndexByte(p, '/')
	if i <= 0 || i == len(p)-1 {
		return "", "", false
	}
	return p[:i], p[i+1:], true
}

// materialsOf renders the build's source as SLSA resolvedDependencies.
//
// A material with no digest of any kind would say only "this URL was involved",
// which the recipe already says and which no verifier can check — so an empty
// SourceRef produces no material at all rather than a decorative one. That is
// also what `bk publish` emits for a bottle this process did not build: it does
// not know what the source was, and inventing a URI from the recipe would
// attest a guess.
func materialsOf(src build.SourceRef) []provenance.Material {
	if src.SHA256 == "" && src.Commit == "" {
		return nil
	}
	return []provenance.Material{{URI: src.URI, SHA256: src.SHA256, GitCommit: src.Commit}}
}
