# bk — a pure-Go brewkit

`bk` is a from-scratch, `CGO_ENABLED=0` reimplementation of [pkgx](https://pkgx.sh)'s
build tool [brewkit](https://github.com/pkgxdev/brewkit) (originally Deno/TypeScript
with Ruby + `patchelf` helpers). It reads a pantry recipe — `package.hcl` or
`package.yml`, tried in that order — builds the package in a pkgx environment,
relocates the install tree, and packages a bottle.

The reference brewkit is a *native* build tool — everything pivots on the host it
runs on being the thing it builds for. `bk` is **Target ≠ Host by design**: the
build target (platform/arch/triple) is a first-class value, so cross-compilation —
notably **Windows PE bottles built on a linux/darwin host** — is a supported path
rather than a retrofit.

## Verifying a downloaded `bk`

⛔ **`SHA256SUMS` is a checksum of itself.** It says the binaries on a
[release](https://github.com/go-zpkg/zbk/releases) match a manifest published
beside them, and whoever replaced the binaries would replace the manifest.
The half that cannot be forged from the release page is GitHub's **provenance
attestation** — signed through Sigstore, saying that this repository's release
workflow built that file from that commit:

```sh
gh attestation verify -R go-zpkg/bk bk-linux-amd64
```

It matters more here than for the other binaries in this organisation:
`bk factory` is what signs and publishes every bottle, and a `bk lock`
records the version of the binary that wrote it. Every file of a release
published after 2026-10-20 carries an attestation; earlier ones carry none,
and `gh attestation verify` answers `HTTP 404` for those rather than failing
closed, so a 404 on an older binary means *unattested*, not *tampered with*.

## Status

In production: `bk factory` is what fills
[`ghcr.io/go-zpkg/packages`](https://github.com/orgs/go-zpkg/packages) —
**1585 projects, 42 746 signed (project, os, arch, version) bottles** as of
2026-10-04 17:00 UTC+2 — linux/aarch64 15 136, linux/x86-64 13 255,
darwin/x86-64 7 113, darwin/aarch64 6 649, windows/x86-64 554, and
**linux/s390x 39**, an architecture being brought up now.

It is a moving target, and more literally than that phrasing suggests: the
same `bk builder --dry-run --platform linux/s390x` reported 25 of 25 toolchain
roots unresolvable at 11:45 and 21 of 25 at 17:03 the same day, because
another session was publishing while this was measured. A registry count is
dated to the HOUR. Re-measure it rather than trusting this line: `go run
./catalog` in
[go-zpkg/packages](https://github.com/go-zpkg/packages) enumerates the registry
itself, and <https://go-zpkg.github.io/packages> browses it.

The packages, all at 100% statement coverage (`go test ./... -coverprofile` + `go tool cover -func`, enforced in CI):

| package  | what it does |
|----------|--------------|
| `target` | the single source of truth for the build **target** vs the **host** (`BREWKIT_TARGET` / `--platform`), incl. the llvm-mingw Windows cross triples and the `wasip1/wasm` target (`wasm32-wasip1`; no POSIX relocation; `wasm` is an arch of `wasip1` only). C/C++ for wasip1 uses our own toolchain from source — the `llvm.org` bottle's clang/wasm-ld, the `github.com/WebAssembly/wasi-libc` sysroot and the `compiler-rt.llvm.org/wasi` builtins — imposed through `$BK_CC`/`$BK_CXX` (`clang --target=wasm32-wasip1 --sysroot=… -resource-dir=… -mcpu=lime1`), which the cc/gcc/clang shims re-exec; `AR`/`RANLIB`/`NM`/`STRIP` are the LLVM ones, and recipes pass `--host={{hw.target}}` (= `wasm32-wasip1`) to configure |
| `config` | the build workspace layout, keyed on the target so a cross build never collides with a native one |
| `schema` | an authoritative **JSON Schema** for `package.yml` — there is no official one; this is derived from libpkgx's parser and validated against the entire pkgxdev/pantry corpus (0 rejections over 1890 recipes) |
| `pantry` | parses + schema-validates a `package.yml` into a shared `Recipe` |
| `pantry/hcl` | an **HCL2 front-end** — a `package.hcl` decodes into the *same* `Recipe` via the same schema, so a recipe written in HCL2 yields an identical build |
| `fixup`  | post-build relocatability: `.pc`/`.cmake` path rewriting, libtool `.la` cleanup, `lib64→lib`, single-dir header flattening, and a **pure-Go ELF RUNPATH rewriter** (`debug/elf`, no `patchelf`). A Windows target skips all POSIX relocation. |
| `moustache` | pkgx's `{{token}}` template substitution (version/deps/prefix/hw) |
| `buildscript` | the build/test script generator (`if:` guards vs the target, platform-reduced env, fixtures) + the porcelain `Wrap` (full runnable script) |
| `fetch` | source download + extract (tar.gz/xz/bz2/zip, git), zip-slip-safe |
| `bottlepkg` | package an install tree into a bottle + dist layout |
| `build` | the pipeline orchestrator (`Runner`): dep-closure, base toolchain, sanitized env, autotools maintainer-mode defeat |
| `overrides` | applies the factory's local recipe-override patches to a pantry checkout in pure Go — a `git diff` parsed and applied without shelling out to `git apply`, and idempotent (it resets the files it touches first) |
| `recipefile` | reads a recipe and applies the project's **logical** override on the way in — nothing on disk is touched, which is what lets the same pantry checkout be read twice |
| `logical` | the override algebra: `set`, substitute, `remove`, `append`, `prepend`, each reporting **applied / already true / premise gone**. A unified diff has two outcomes; the third is what distinguishes a defect from a job upstream has since done. A path (`build.dependencies["crates.io/semverator"]`) must be spellable in the form the parser reads: a step holding a quote, a backslash, a control character or invalid UTF-8 is refused, because `String` renders those with Go's `%q` and the reader understands no escapes — a backslash used to round-trip to *two* characters silently, so the diagnostic naming the place to fix named a different place. Found by this repository's first fuzz target in 0.03s |
| `httpretry` | which failed HTTP attempts are worth repeating. Measured on one 23-failure batch, **eleven** were transient HTTP and nothing else — a factory that gives a flaky host exactly one chance reports its own bad luck as a broken recipe |
| `useragent` | the one User-Agent every HTTP path in bk sends. It exists because they differed: `versions` set one and `fetch` did not, so bk could LIST a project's versions and then get 403 downloading the tarball it had just found |
| `versions` | resolves a project's upstream version from the recipe's `versions:` spec — deliberately distinct from what pkgx's dist advertises, which normalises versions the recipe's own source URL does not have |
| `cmd/zbk` | thirty-eight subcommands. The pipeline: `build`, `test`, `publish`, `factory`, `builder`, `source`, `sourcepin` — the last one prints the `sha256` a recipe should pin, fetched with **the builder's own fetcher** rather than with `curl` and `shasum`, because every other distribution computes that digest with a tool its build does not run and so never meets the host quirk the build will. It was written the day GitHub's release CDN answered 504 and `curl -sSL | shasum` produced a perfectly plausible digest of a 92-byte error page. Whether two builds AGREE: `reproduce` — it compares two bottles entry by entry and classes what differs, because "the digests differ" is the start of an afternoon with two tarballs rather than a finding. It exists because the question was asked once by hand, on 2026-09-29, and found one: zlib.net 1.3.2 built on the s390x seed VM before and after it was replaced had every file byte-identical and its directories 0755 against 0775 — the two hosts' umasks. Whether a second builder VOUCHES: `sign` — it attaches your signature to a bottle somebody else published, after checking your rebuild produced the same bytes, and refuses when it did not. What a recipe set SAYS: `target`, `versions`, `closure`, `lock`, `catalog`, `tools`, `overrides`, `tohcl`, `version`, `buildenv`, `origin`, `vulnid`, `advisories`, `vulnfetch`, `attest`, `eol`. What it gets WRONG: `depgaps`, `depsplit`, `undeclared`, `unlinked`, `unresolved`, `provides`, `lint`, `weather`, `sonames`, `runlog`. Build-time shims a recipe invokes rather than a person: `fixup`, `libtool`, `bkpyvenv`. `bk tools` is worth singling out: it reports which external commands a recipe set invokes, parsed rather than grepped, and `--scope build\|test\|all` separates two surfaces that disagree — a build's is what the IMAGE must hold, a test's is what the package's own acceptance check needs, and **260 tests call a compiler where 6 declare one**. `bk lint` is the other: `--require-provenance` asks whether a recipe of ours records which of the project's OWN files its build was written from, and `--require-standalone` asks the prior question — whether it is a recipe at all, or an amendment that resolves only because another tree is merged underneath it. Over the three trees that hold recipes of ours, **30 of 227 stand alone**; the rest are overlay fragments, correct as overlay entries and unusable as a pantry. `--subdir` exists because 14 of those recipes are not kept under `projects/` and so could not be reached at all. `--max-fragments N` is the ratchet that lets the check be switched on before the work is finished: more than `N` fails as a regression and **fewer than `N` fails too**, because a ceiling nobody lowers stops describing the tree and a regression then hides in the slack. |
| `cmd/venvlaunch` | the entry point `bkpyvenv seal` installs as `$PREFIX/bin/<cmd>` for a Python application, and **a binary rather than a script because a script has no `$ORIGIN`**: the kernel resolves a shebang by ordinary path lookup, so a script cannot find anything relative to itself, while `os.Executable` can. It execs the venv's interpreter with the entry point as an *argument*, so the venv's own shebangs are never read — which is what removes the need for `/usr/bin/env`, for `env -S` (absent from busybox, so the old form could not start on Alpine), for a shell, and for rewriting every console script in the tree. `CGO_ENABLED=0` gives it no `PT_INTERP` and no `DT_NEEDED`, measured on linux/amd64, s390x and loong64, so it runs in a literally empty image where **1 513 of 1 870 installed scripts cannot**. **It writes nothing — not "little", nothing.** `seal` makes `venv/bin/python` a *relative* symlink into the store, the same way `@loader_path/../../..` already reaches the store root for an rpath, so a relocated store needs no repair at all: no lock, no temporary file, no `rename`, nothing for NFS to refuse and nothing for two hosts sharing a home to fight over, and every signature stays valid because nothing is rewritten. `pyvenv.cfg` is never touched either — measured: a venv with a stale `home` still resolves to the venv, so only the file's presence is load-bearing. |

`bk build` runs the whole pipeline — resolve version → fetch source → parse
recipe → dependency closure → generate + wrap the build script → run it in a
sanitized env → fix-up → package a bottle. `bk factory` drives that over a whole
list of projects: it expands them to their topologically-ordered runtime-dependency
closure, skips any `(project, version, platform)` already published, applies the
overrides, and publishes each bottle signed with an SBOM and provenance. After
each publish it runs that package's own `test:` block and RECORDS the outcome in
`tests.txt` — four states, one line each — without ever changing the chunk's
result: measured over 120 packages, only 2 of 12 test failures were a package
that does not work, so a gate would stop a run over a missing host config file.
`--test=false` turns it off, `--test-timeout` bounds one package's test, and
`--test-only` builds nothing and tests what the registry already holds — the
factory tests what it publishes once, and that is how a bottle which stopped
working gets noticed afterwards.

`bk depsplit` finds the recipes that name ONE project in BOTH dependency
lists with constraints that select DIFFERENT versions. The two lists are kept
apart on purpose — the runtime list is the set a build LINKS against, the
build list is the set it RUNS — and that is what lets qt build with
`unicode.org ^71` to link and `^73` for nodejs. The case the separation does
not cover is the same project in both: two versions of one library then land
in one build environment, and which supplies headers and which supplies
libraries is decided by search order. `protobuf.dev` declared
`abseil.io: "*"` to link and `^20260526` to build, and on darwin/aarch64 the
link died on `absl::lts_20260817::Mutex::AssertHeld()` after 34 minutes.
When the same disagreement happens to link instead of failing it is worse —
the bottle ships an `@rpath` reference to the version its headers came from
while declaring the constraint a consumer will resolve differently.

Two things decide whether its answer is worth anything. The verdict is
**different VERSION, not different text**: `*` and `>=1` differ as strings
and almost never as answers, so both constraints are resolved against what
the registry actually carries **for that platform** — without the platform
check it reported `github.com/awslabs/dynein` as linking openssl 1.1.1w on
linux/x86-64, a version published for darwin/aarch64 alone. And it reads the
OVERRIDDEN recipe, because the fix for the one confirmed instance is an
override, and an operator who finds a repaired defect in a defect list stops
reading the list. A pair it prints is a **candidate**: harmful when the
doubly-named project is linked, normal when it is a tool.

`bk test` runs a recipe's own `test:` block against the INSTALLED package, in an
emptied sandbox holding that package, its `test.dependencies` and the recipe's
own files (recipes name fixtures by bare relative name: `cc test.c -lz`) — and a
compiler when the test's own script calls one, which 260 of them do. What it does
not get is the build's flags, its dependencies or its source tree, because the
question is whether what we published works and not whether the build did. It answers in four states, not
two: `0` passed, `1` ran and failed, `3` the recipe declares no test, and `4`
the test never ran (an unresolvable version, an unreachable version source, a
sandbox that could not be made). A 503 from a version source is not a broken
package, and a sweep that cannot tell the two apart files bugs for an outage.

## Building bottles that owe nothing to the build container

`--libc=pkgx` retargets the compiler at the pkgx `gnu.org/glibc` bottle — its crt
objects, its libc, its dynamic linker — instead of the build container's, so the
output runs `FROM scratch`. `--glibc <version>` pins that sysroot to an exact
glibc line, and `bk builder` stages the sovereign rootfs itself: static Go
binaries plus toolchain bottles from the signed registry, nothing else.

[`docs/from-scratch-toolchain.md`](docs/from-scratch-toolchain.md) is the design
note behind it, kept because its hazard list is still the one that bites.

⛔ **A tool that does not go through the compiler driver sees none of this.**
The sysroot, the `-isystem` dirs and the runtime choice reach a build through
`cc` — the shim that re-execs `$BK_CC` — or through `$CC`. **bindgen** drives
libclang in-process instead, so a Rust crate that generates bindings got the
container's idea of a libc, or none:

```
/pkgx/openssl.org/v3.6.4/include/openssl/asn1.h:27:10:
  fatal error: 'stdio.h' file not found
```

openssl 3.6.4 had been found and configured correctly in that build; the
first `#include` of a C library was simply unreachable. Sovereign mode
therefore also exports `BINDGEN_EXTRA_CLANG_ARGS` — the variable bindgen's
own documentation names for exactly this — with the header-finding flags
only, appended to whatever the recipe set. It is **not** exported outside
sovereign mode, where an empty `--sysroot` would hide the host headers a
build is entitled to use.

A scratch tree has nothing underneath it, so `bk builder` answers three
questions a build would otherwise answer hours later and attributed to the
wrong thing:

- `--dry-run` resolves the toolchain for `--platform` and stages nothing, so
  "does this architecture have the bottles" costs a round trip rather than a
  runner. On a refusal it names **every** blocked root, not the first — on an
  architecture being brought up, one gap per build is one build per gap — and
  it tells a CONFLICT between roots apart from a missing bottle.
- after staging, it reports every `NEEDED` soname the tree does **not**
  contain, naming who asks. A binary that wants one cannot start, and it says
  so only when something runs it. The s390x second generation met
  `libselinux.so.1` twice, a full build apart, before this existed.
- it says when a prefix is **already** on disk and will not be re-installed.
  `bottle.InstallFor` treats the existence of `<project>/v<ver>-h<hash>` as
  "already present", so a tree left half-written by a run that died — and
  inherited by the next job on a self-hosted runner — is indistinguishable
  from a complete one. Three runs reported "42 packages" and installed none.

None of the three refuses anything: the build that follows is the verdict.

### Recipes in YAML or HCL2

The `package.yml` schema (`schema/package.schema.json`) doubles as editor
autocompletion — add to a recipe:

```yaml
# yaml-language-server: $schema=https://go-zpkg.github.io/bk/package.schema.json
```

The same recipe in HCL2 (`package.hcl`) decodes to the identical `Recipe`:

```hcl
distributable {
  url              = "https://curl.se/download/curl-{{version}}.tar.bz2"
  strip-components = 1
}
dependencies = { "openssl.org" = "^1.1", "zlib.net" = "^1.2.11" }
build {
  script = ["./configure $ARGS", "make --jobs {{ hw.concurrency }} install"]
  env    = { ARGS = ["--prefix={{prefix}}", "--with-openssl"] }
}
provides = ["bin/curl", "bin/curl-config"]
```

## Why

Completes the pure-Go [`go-zpkg`](https://github.com/go-zpkg) family (bottle / pkgm /
pkgx / mirror) with the last Deno piece — a single static binary that builds pantry
recipes with no Deno/Ruby/patchelf runtime, and cross-builds cleanly.

## Naming a tree, not only a package

A recipe describes one package: `versions`, `distributable`, `build`, `test`,
`provides`, `dependencies`. Until recently the only way to name a **group**
was a flat text file beside the format — `seed/order.txt`, 106 lines, and
`builder/toolchain.txt`, 95 — which could not be versioned, published,
installed or depended on.

A recipe carrying `members` is a **set**:

```hcl
# go-zpkg/base-toolchain
members = {
  # clang, lld, compiler-rt — the compiler itself
  "llvm.org" = "*"

  # libc, crt objects and the dynamic loader
  "gnu.org/glibc" = "*"
}
```

`bk closure go-zpkg/base-toolchain` resolves it. So does `bk factory
--recipes go-zpkg/base-toolchain`, and so would anything else that takes a
project name — a set is expanded **at the root**, before the dependency walk
looks at it, so nothing downstream learns the word.

### Why a recipe and not a new kind of file

The three systems that solved this agree on the shape:

| | |
| --- | --- |
| **Nix** | a tree *is* a derivation. `buildEnv` takes a list of packages and its output is a tree of symlinks. No new kind of object. |
| **Guix** | a manifest names packages; a **profile** is the tree it makes. |
| **Spack** | `spack.yaml` is the abstract set, `spack.lock` the concrete one — the same root specs *"may concretize differently"*. |

Nix's answer is the one taken. A set is an ordinary recipe, so it is signed,
attested, published and installed by everything that already does those
things for a package — rather than a second kind of artefact to keep in step.

### A set is UNORDERED, and that is the point

All three of those manifests are. The order comes out of resolution, not out
of the file, and `bk closure` produces it from the dependency graph.

Which is why **`seed/order.txt` is not a set and must not become one**. That
file is a *build order*: inside a dependency cycle the topological order is a
guess, and `order.txt` is the hand-tuned guess that works — `bk closure
--check-order` exists to judge it. `builder/toolchain.txt` is a different
thing, an *install* list, where order carries nothing; that is the one that
moved.

### `zbk sign` — a second builder's word

`reproduce` answers *are these two bottles the same bottle?* locally. `sign`
is the half that makes the answer travel.

Two people who build the same inputs get the **same** bottle — deliberately,
since an identity that varied with the builder could never be compared. So
the artefact stays one artefact and what differs is the *attestation*: each
builder attaches their own signature referrer to the published bottle, and a
client counts how many distinct trusted keys it can verify
(`ZPKG_TRUST_THRESHOLD`).

```
$ zbk build …                                   # your own build
$ zbk reproduce yours.tar.gz theirs.tar.gz      # do they agree?
$ zbk sign -key you.sec -project fftw.org \
    -version 3.3.11-h27o3ysxva6swayci yours.tar.gz
signed fftw.org 3.3.11-h27o3ysxva6swayci (linux/x86-64) sha256:… with key 9f2c…
add it to a client's trust set with:
  ZPKG_EXTRA_TRUSTED_KEYS='<name>:RWQ…'
```

It **pushes no bottle**. Re-publishing to add a signature is how you end up
with two objects where the entire point was that there is one.

And it **refuses when the digests differ**, which is the interesting case —
`guix challenge` exists to report exactly that, and the report *is* the
finding: either the recipe is not reproducible or one of the two machines is
not what it claims. Both digests are printed, because "they differ" is not
something anyone can act on. `-force` exists and says what it does: it signs
bytes this build did not produce, which is the one claim a threshold must
never be able to make.

The referrer carries the signer's **key id** and no name. A name would be
written by whoever pushed it, and the line it would appear in — `signed by: …`
— is the one a reader uses to decide whether to trust the artefact. The name
a user sees comes from their own trust set.

### `bk lock` — the concrete half

Guix's manual puts it plainly: *"to reproduce a profile bit-for-bit,
manifests alone might not be enough"* — the same names resolve differently
against a different package set, so a manifest needs the channel revisions
beside it. Spack names the two halves: an environment from `spack.yaml` has
*"the same root specs... may concretize differently"*, one from `spack.lock`
has *"the same concrete specs"*.

`members` is the abstract half. `bk lock` is the concrete one:

```
$ bk lock --platform linux/x86-64 -o base-toolchain.lock.hcl go-zpkg/base-toolchain
set: go-zpkg/base-toolchain names 25 member(s)
lock: 41 project(s) pinned → base-toolchain.lock.hcl
```

```hcl
lockfile_version = 1
bk               = "v0.7.0"
platform         = "linux/x86-64"
generated        = "2026-10-05T09:10:39Z"
pantry           = "fd646990024e22f5752578cfdcfe2518b20c0797"
overlay          = "f8f6dcfd7b17410a6de780bdd58c81fbbb38d1b3"
roots            = ["go-zpkg/base-toolchain"]

locked = {
  "curl.se" = { version = "8.17.0", spec = "sha256:5284d597c180…" }
  "gnu.org/bash" = { version = "5.3", spec = "sha256:…" }
  …
}
```

**And it matters more here than in Guix.** A Guix manifest resolves
deterministically once the channel revision is pinned, because the version is
*in* the checkout. A pkgx recipe's `versions:` asks GitHub for tags **at
resolve time**, so pinning the pantry commit is not enough: the same pantry
resolves `gnu.org/binutils` to whatever the newest tag is the day you ask. The
resolved version has to be written down or it is not pinned at all.

The platform is in the header because it changes the answer: the same set
locks to **41** projects on `linux/x86-64` and **40** on `darwin/aarch64`,
`github.com/besser82/libxcrypt` being the difference. A lock that did not say
which platform it was taken on would be read as the other one's.

Two deliberate shapes:

- **Sorted by project, not in build order.** A lock is read as a diff, and a
  topological order makes every line move when one dependency does.
- **An unresolved project exits non-zero** and is named on stderr. A lock with
  a hole in it that reads as a success is a lock somebody commits.

### `-runnable` — build locks and run locks are different files

`bk lock` resolves each version from the recipe's `versions:` block, so it
pins **what the recipes can build**. That is exactly right for
`bk factory --lock`, which is about to build them, and wrong for
`pkgx --lock`, which can only install what the factory has already
**published**. The two run ahead of each other by construction.

Measured 2026-10-09, by generating a lock and running it in a `FROM scratch`
container rather than by reading the code:

```
$ bk lock -platform linux/aarch64 -o curl.lock.hcl curl.se
lock: 1 of 5 pin(s) NOT published for linux/aarch64 — `bk factory --lock` can
      build this file, `pkgx --lock` cannot run it:
    curl.se/ca-certs             2026.09.25     (published here: 2026.8.13)
    `bk lock -runnable` pins what is published instead.
lock: 5 project(s) pinned → curl.lock.hcl
```

Before this, that lock was written in silence and `pkgx --lock` refused it
with a message about a version nobody had chosen.

`-runnable` pins the newest **published** version that satisfies every demand
the closure places on each project — `PickVersionForAll`, the same function
the resolver itself asks, so the lock answers the question pkgx will ask of
it. A per-project "newest published" is **not** a closure: the first version
of this flag asked for `*`, pinned openssl 4.0.2 where `curl.se` demands
`^3`, and produced a file that could not resolve under a line saying it
could.

The mode is written into the file as `pinned = "recipes" | "published"`,
because `bk lock --check` re-resolves — and re-resolving by the other
question reports every pin as having moved.

The verdict is printed **every time**, including when everything is fine:
the defect being fixed was a silence, and a message that appears only on
failure leaves the clean case looking exactly like a `bk` that does not
check at all. It also refuses to endorse a lock with a **hole** in it: a
project that could not be pinned at all leaves the remaining pins all
installable and the file still not a closure.

### `spec` — because a version is not enough either

Spack's packaging guide says what goes into a spec hash: *"`build`, `link`,
and `run` dependencies all affect the hash of Spack packages (along with
`sha256` sums of patches and archives used to build the package, and a
**canonical hash of the `package.py` recipes**)"*.

The last clause is the one worth copying. Pinning a version catches an
upstream that moved; hashing the **recipe** catches the other half — a build
script edited in the pantry resolves to the same version and produces a
different package. A lock with versions alone calls those two builds the same,
which is the thing a lock exists not to do.

`spec` is a Merkle hash over the platform, the project, the resolved version,
the **parsed** recipe (every half of it the closure read) and the spec hashes
of the dependencies. It is taken over the parsed value, not the file, so
reformatting a recipe or rewriting its comments does not move it and changing
what it says does — Spack's "canonical", by a different route.

Measured: of **2091 recipes** in the pantry and the overlay, **0** fail to
serialise. The property that matters is tested both ways round — a change to a
leaf moves the leaf and everything above it; a change at the top moves the top
alone — and that test was checked against a deliberately broken hash, which
fails it, so it is not passing for free.

### The install prefix carries the build's identity

A bottle is installed at

```
<store>/<project>/v<version>-h<hash>
```

and never at `<store>/<project>/v<version>`. The hash is the short form of the
same Merkle identity `spec` takes — platform, project, resolved version,
canonical recipe, and the resolved prefix of every dependency — so a build is
addressed by **what it is** rather than by the version it claims.

Three things follow, and the first two are why pkgx's unhashed path had to go:

- **Two builds of one version are siblings.** `openssl.org@3.5.8` built against
  two different zlibs are two directories, both reachable, neither shadowing
  the other. Under `v<version>` the second install overwrote the first.
- **The prefix is baked into the binaries.** `otool -l` on a published
  `zlib.net` 1.3.2 shows `@rpath/zlib.net/v1.3.2/lib/libz.1.dylib`: the path
  is in every dependent, so a path that does not say which build it is makes
  the dependent unable to say either.
- **Dependencies make the hash Merkle for free.** An input is identified by
  its resolved prefix, and once that prefix carries its own hash, hashing it
  carries the whole dependency transitively — the mechanism Nix uses when a
  derivation references its inputs by store path.

The hash is a function of the **inputs**, computed before the compiler runs;
hashing the output into the output would be circular, which is why Nix hashes
the derivation and Spack the concrete DAG rather than the result.

#### The registry carries the same address, and the description to check it

A bottle is published under `<version>-h<hash>`, with the glibc flavour still
readable in between where there is one (`8.20-glibc2.27.0-h<hash>`), and its
per-platform manifest carries the spec it was hashed from:

```
io.github.go-zpkg.spec = {"v":1,"platform":"linux/x86-64","deps":[…],"recipe":"sha256:…"}
```

**The tag carries the address, the annotation carries the meaning**, and
`bottle.VerifySpec` recomputes the first from the second. That is what makes
the identity checkable rather than merely asserted: a reader does not have to
trust that the hash describes this build, it can recompute it. An identity
hashed over inputs the bottle does not carry — which is what `bk` briefly
did — cannot be checked at all.

It also settles a question Nix leaves open. A store path says *which* build
and never *what* build, so "the one with CUDA?" needs a second index; Spack
keeps the spec queryable (`spack find libdwarf +debug`) and conda writes its
hash inputs to `info/hash_input.json`. Readability here is a tooling property,
not a naming one.

A bottle `bk publish` only mirrored gets **neither**: no hash in the tag and no
annotation. We do not know how it was built, and a tag claiming an address
would say we do.

Because the tag is an address, `bk factory`'s "already published?" check asks
about the **build**: it plans first — resolving the version and the closure,
which is what the identity is a function of — and only then consults the
registry. Asking about the bare version, which is what it did while a version
was an address, skipped every package whose *recipe* had changed, because the
version had not.

Because the directory name can no longer be composed from a version, a reader
**asks** the store (`bottle.ResolveBuild`) instead of building the path. It
answers with the one installed build, or refuses when two are installed —
refuses rather than taking the newest, since two builds of one version are
exactly the case that has no order to take the first of.

A default version is **not** a property of the store: it lives in a view
(`bottle.LinkView`), which is what lets a shared read-only NFS export hold the
builds while each user, environment or container rootfs computes its own links
from it.

### `bk lock --check` — a lock nobody reads is a wish too

Cargo's `--locked` and npm's `ci` exist because a lock nobody verifies is a
lock nobody can rely on: both refuse to run when the lock and a fresh
resolution disagree.

```
$ bk lock --check base-toolchain.lock.hcl
lock: linux/x86-64 · 2026-10-05T09:10:39Z · 41 pinned, 2 hour(s) old · pinned from the recipes
lock: pantry revision differs: fd64699… → 9ab12cd…
  gnu.org/binutils                   2.47 → 2.48
  zlib.net                           spec 6a2d499db9ab → spec 90fae00e667c — same version, so something it is built FROM changed
lock: 2 of 41 moved
```

Exit **0** when nothing moved, **1** when something did, **2** when the check
could not be made at all.

**The second line of that diff is the one a version-only lock cannot
produce.** Measured on the real `zlib.net` recipe: a comment added to its
build block moves nothing, and one flag added to its `./configure` line moves
the spec hash while the version stays `1.3.2`.

It takes its roots, its platform, the revisions it expects **and how it was
pinned** from the file. Naming any of them again on the command line would let
the two disagree, and the check would then be of a different question from the
one the file answers — so it refuses a project name, and `-runnable`, beside
`--check`.

A **revision that moved is said and is not fatal**: a pantry can move without
moving any answer, and calling that drift would make the check cry wolf until
nobody ran it. An **unresolved project is kept apart from drift** for the
mirror-image reason — a registry outage must not read as a pantry that
changed.

### The header is data, not a comment

The first version wrote the platform, the roots and the revisions as `#`
lines. Right facts, wrong place: a comment cannot be read back. They are
attributes now, with `lockfile_version` beside them — Spack's lockfile carries
a `lockfile-version` and records which spack wrote it, and the compatibility
rule that comes with it (new readers read old locks; old readers refuse new
ones) is worth copying before it is needed rather than after.

### `bk version` — because a lock names a bk you have to be able to find

Every lock records which bk wrote it:

```hcl
bk = "v0.15.0"
```

Until now there was no way to ask a binary whether it was that one.
`bk --version` answered `flag provided but not defined: -version` and
`bk version` answered `unknown command: version`, so the question could only
be settled with `go version -m`, and only if you still had the binary rather
than a `bk` on your `PATH`.

```console
$ bk version
bk v0.15.0
```

Both spellings exist and are asserted to give the same answer, because two
code paths that can drift apart are how a tool starts reporting two versions
of itself.

It prints **exactly** what a lock carries, leading `v` included. A prettier
rendering would make the two disagree, and reading a lock and asking *"do I
have that bk?"* is the whole use of the command.

There is **no `-ldflags` stamp**. The sibling tools inject
`-X main.version=<tag>`, which can be set to anything regardless of what was
compiled — that is how a release workflow re-run published binaries labelled
with a tag they were not built from. This reads `debug.ReadBuildInfo`, so it
cannot disagree with the binary it is in, and the release workflow checks it
against the tag by equality alongside the build info of every binary it ships.

### `bk buildenv` — what a published bottle says it was built with

A rebuild for a toolchain vulnerability needs a **before**. When a Go patch
release fixes a standard-library defect, nothing about the recipe or the
upstream version changes — only the compiler in the build environment does. So
"should this be rebuilt?" is "was it built with the fixed one?", and that
question needs the artefact to have recorded an answer.

Until v0.17.0 it recorded nothing. Measured on the published
`stedolan.github.io/jq`, whose **signed** SLSA statement carried:

```json
"builder": { "id": "https://github.com/go-zpkg/zbk" },
"buildDefinition": { "externalParameters": {}, "internalParameters": {} }
```

— the same two constants every bottle in the registry holds. `DepTokens`
resolved the whole build and runtime closure on every build and threw the list
away.

Now the provenance carries it, and this reads it back:

```console
$ bk buildenv --platform linux/aarch64 stedolan.github.io/jq 1.8.2
github.com/kkos/oniguruma 6.9.10
go.dev 1.27.2
…
```

**`--list` sweeps**, and counts the three outcomes separately:

```
8 read · 0 record a build environment · 8 record none · 0 unreadable
```

⛔ Those three are never folded together. "Records nothing" is every bottle
published before v0.17.0; "unreadable" is a registry that told us nothing, and
counting it as an absence would be the same defect as a census that could not
read reporting zero. An empty list is a failure rather than a clean registry,
and a line the reader cannot use is named rather than skipped — a silent skip
makes the totals smaller for a reason nobody can see.

That first sweep is the answer to "can a rebuild counter be derived?": **not
from what is published today.** Nothing in the registry is comparable yet, so
the counter starts at zero for everything and becomes meaningful only after a
rebuild under v0.17.0 or later. Debian's rule — *"the absence of a
debian_revision is equivalent to a debian_revision of 0"* — is not a
convention here, it is the literal state of the registry.

#### `--needs` — which bottles a security release obsoletes

The operator's real question after a Go patch release is not "what was this
built with" but **"which of these need rebuilding"**:

```console
$ bk buildenv --platform linux/aarch64 --needs go.dev@1.27.2 --list recipes.txt
STALE   acme.org/tool 1.2.3: go.dev 1.27.1, want >=1.27.2
n/a     zlib.net 1.3.2: does not use go.dev
ok      other.org 2.0.0: go.dev 1.27.2

3 read · 3 record a build environment · 0 record none · 0 unreadable
of those: 1 need rebuilding for go.dev>=1.27.2 · 1 already have it · 1 never used it
```

⛔ **"Does not use it" is its own column.** A C package has no `go.dev`:
counted as stale it would rebuild the whole registry for a Go release, counted
as ok it would make the figure meaningless. That is the mistake a denylist
makes when it inherits a taxonomy's blind spot.

⛔ **And a rebuild of the compiler counts as the compiler.** `go.dev 1.27.1_1`
is 1.27.1 built again, which does not contain a fix that landed in 1.27.2 — so
it is stale, and the version comparison has to see the rebuild suffix to say
so.

The judgement is reported **beside** the reading, never instead of it. Run
against the registry as it stands today:

```
8 read · 0 record a build environment · 8 record none · 0 unreadable
of those: 0 need rebuilding for go.dev>=1.27.2 · 0 already have it · 0 never used it
and 8 record nothing, so this says nothing about them
```

`0 need rebuilding` would read as an all-clear on its own. The last line is
what stops it being one.

### `--rebuild` — a new build of a version that is already published

A recipe fix can change the binary without changing the upstream version.
Measured on 2026-11-02: go-zpkg/packages#399 gave `fftw.org` its SIMD
codelets, the darwin lane rebuilt it, and the result went out as **`3.3.11`**
— the same tag the scalar build had. `nm` on the two shows 0 → **207**
`_neon` symbols, so they are plainly different bottles; nothing in the
registry said so, and anyone holding the old one kept it.

`--rebuild` publishes such a build as the next **`_N`** instead:

```console
$ bk factory --platform darwin/aarch64 --recipes fftw.org --force --rebuild
rebuild: fftw.org 3.3.11 is already published for darwin/aarch64 — publishing as 3.3.11_1
```

`_N` is Homebrew's `rebuild` and Debian's `+bN`. bottle already understood it
— it parses, it sorts **after** the build it supersedes, and an exact pin
tells the two apart — and nothing produced it. This is the half that mints
it.

⛔ **The number comes from the REGISTRY, per platform.** A tag listing spans
every platform, so counting tags rather than publications would let a darwin
rebuild take its number from a linux one — a gap on one and a collision on
the other. And a read that fails **refuses**: a guessed number is a
collision, and falling through to "no counter" would quietly replace the tag
`--rebuild` exists to preserve.

⛔ **Opt-in, and deliberately not folded into `--force`.** Every manual
dispatch of the darwin lane already sets `FORCE=1` unconditionally. A counter
minted on every forced run would bump `N` each time a lane was retried after
failing at the publish step, littering the registry with tags nobody asked
for. A rebuild that *supersedes* is a decision about meaning, so it is stated.

⛔ **Upstream pkgx cannot read a `_N` tag.** libpkgx's `SemVer` constructor
(`src/utils/semver.ts:26-41`, read 2026-11-02) splits on `.` and accepts a
part only on `/^(\d+)([a-z])$/` — last part only — or `/^\d+$/`, else throws
`invalid version`. `3.3.11_1` has the part `11_1`, which matches neither. So
**pointing an upstream pkgx client at this registry is unsupported** once a
project carries a rebuild. That was weighed and accepted: it throws rather
than resolving the wrong bottle, which is the better of the two failures. The
alternatives are in bottle's README, with why each was rejected.

### `bk origin` — may this bottle be promoted?

Bringing up an architecture from nothing needs two registries. The first
generation takes its compiler and shell from the host distribution, because on
an architecture with no bottles there is nothing else to take them from, so it
publishes to a **throwaway** registry on the runner and never leaves it. The
question that gets anything out of there is one fact per bottle: *was the
host's toolchain involved?*

Measured 2026-11-01, the registry could not answer it:

```console
$ bk buildenv --platform linux/s390x lz4.org 1.10.0
buildenv: lz4.org 1.10.0 (linux/s390x): the provenance records no build environment
```

⛔ **An empty build environment is a hint, not a statement.** A `--bootstrap`
build resolves no bottles, so its environment is empty — but so is a mirrored
bottle's, and so is every bottle published before bk recorded one. Three
situations, one silence, and a gate cannot read a silence.

So the factory now states it, and this reads it back:

```console
$ bk origin --platform linux/s390x lz4.org 1.10.0
lz4.org 1.10.0 linux/s390x
  host toolchain used: no — built from bottles
  inputs resolved from: oci://ghcr.io/go-zpkg/packages
```

`--promotable` turns it into a gate: silent and exit 0 only when the
provenance **proves** the host toolchain was not used.

```console
$ bk origin --platform linux/s390x --promotable lz4.org 1.10.0
origin: lz4.org 1.10.0 (linux/s390x) is NOT promotable: its provenance does
not say whether the host toolchain was used, and an unstated answer is not a "no"
```

⛔ **It requires an explicit `0`, and treats every other answer as no** —
including silence. Not because unrecorded bottles are suspect, but because the
two failures do not cost the same: refusing a good bottle costs a rebuild,
while promoting a host-built one puts an unpinned distribution compiler's
output into the production registry under our signature. That is also why the
recorded value is a tri-state and not a boolean: a `bool` zero is `false`,
which would read as "not a bootstrap", and every bottle published before this
existed would have claimed to be promotable.

A mirrored bottle records where it was **put** and nothing about who compiled
it, so it fails the gate on purpose: recording a field is not the same as
answering the question.

#### `--require-origin` — promoting, as opposed to copying

`bk factory --mirror-from` already copies a bottle from one dist and
republishes it signed and attested. Adding `--require-origin` turns that into
a **promotion**: every bottle is refused unless its *source* provenance proves
the host toolchain was unused.

```console
$ bk factory --platform linux/s390x --mirror-from oci://127.0.0.1:5000/seed \
    --to oci://ghcr.io/go-zpkg/packages --require-origin --recipes "lz4.org"
❌ FAIL lz4.org 1.10.0: origin: not promotable: it was built with --bootstrap,
   so its compiler and shell came from the host distribution rather than from
   bottles
```

Three properties worth stating, because each one is a way this could have been
written wrong:

- **The check runs before the download.** Nothing about having the tarball in
  hand makes a bottle more promotable.
- **The verdict is carried, not restated.** The facts belong to the *build*,
  and copying an artefact between registries does not change what built it.
  Re-stating them as this run's own would launder a verdict it did not make,
  and would overwrite `inputs-from` — the only record that the bottle was
  built against the seed rather than against the production registry.
- **"I could not ask" is not "the answer was no."** An unreachable source
  registry is reported as a read failure naming the registry, never as a
  judgement about the bottle. A gate that folds the two together turns every
  network blip into a permanent verdict.

`--require-origin` without `--mirror-from` is refused at argument-parsing
time, beside the other argument checks rather than further into the run: there
is no source provenance to read, and a gate the operator believes ran is worse
than no gate.

### What is still missing, named rather than left out

The spec hash covers the **inputs**, as Nix's derivation hash and Spack's spec
hash do. It does not cover the **output bytes** of the built bottle. `bottle`
can *verify* a digest but has no exported way to be *asked* for one, and a lock
taken before anything is built has no output to name. The header of every lock
says so, rather than letting a reader assume a guarantee that is not there.

## `bk unresolved` — can what we published actually load?

It installs a project's closure into a store of its own and reports every
reference the store cannot answer: an ELF names a **soname** and the
loader searches for it, so the question is whether anything in the closure
provides that name; a Mach-O names a **path**, so the question is a stat.
Each project gets its own store, because a shared one rescues a missing
reference by accident — `gpgme`'s undeclared `libgpg-error` resolved for
months because something else in the same closure happened to bring it.

```console
bk unresolved -platform linux/aarch64 gnu.org/bash curl.se
```

⛔ **`-platform` exists because an audit that can only ask about its own
machine covers one platform of six.** Wired into CI (`sonames.yml` in
go-zpkg/packages) this found **967 unresolvable references over 259 of
1407 bottled projects** on linux/x86-64 — and said nothing about the other
five, which were not clean but **unasked**. The reader was never the
problem: it walks ELF and Mach-O in one pass precisely because a store
built on one platform is read on another. Only the install half was
host-bound, until `bottle.CompleteClosureFor` (bottle v0.55.0).

A half-parsed platform is refused before anything is fetched: resolved
against an empty arch, every bottle is absent, every closure is empty, and
the audit would report a flawless platform it never installed.

## `bk vulnid` — under what name does a CVE database know this package?

Rebuilding a bottle to fix a vulnerability needs a vulnerability to point at,
and pointing at one needs a name both sides agree on. `pkg:pkgx/openssl.org@4.0.2`
is a name **no database knows**: OSV answers `{}` to a `pkg:generic/…` purl, and
NVD's CPE route answers for anything and answers badly — measured on
2026-10-11, `cpeName=…openssl:3.5.7` returned **27 CVEs, four of them from
2009**, because every openssl criterion in the reply reads `openssl:*` with no
upper bound at all.

A recipe usually already names something better, in its `versions:` block.
`bk vulnid` reads it:

```
$ bk vulnid -dir ~/Library/Caches/pkgx/pantry
1563 recipe(s) read from …/pantry/projects
  declared  0
  derived   1241
  none      322
by database:
  GitHub         1186
  crates.io      114
  GitLab         40
  npm            14
  RubyGems       1
```

Three sources, and they rank. **derived** costs nothing: it is read off the
recipe's `versions:` block and off the project's own name. **declared** is an
entry a person wrote in an identity table, and wins, because it exists only
where the derivation was judged wrong or absent. **none** is the honest answer
for the rest — `bk vulnid -list none` names them, and they cluster on a handful
of upstream hosts (`ftp.gnu.org`, `www.x.org`, `sourceforge`), so the table that
fixes them is short.

### The project's own name is a source too

Measured: `crates.io/bpb`, `crates.io/huniq`, `crates.io/stego` and
`crates.io/albion_terminal_rpg` were reported as having **no identity at all**,
while their own names say both the registry and the package. That is four
projects the derivation could answer for and did not.

The larger half is the **110** `crates.io/*` projects that *do* derive a GitHub
repository from their recipe. For those this adds a second, better key rather
than a first one: OSV keys Rust advisories (RUSTSEC) by `crates.io` with
curated version ranges, where a repository-keyed advisory carries whatever
range its filer wrote. Both keys are emitted — two keys mean two databases can
be asked and neither has to be guessed.

This is **not** the same trick as reading a `url:`. A distributable URL says
where the source came from, which is a host and not a package name; that is the
322-project CPE case, and inventing a package name from it is what produced 27
openssl CVEs. A project called `crates.io/bpb` is different in kind: the
pantry's naming convention put the registry and the package name there, and the
package is what the registry calls it.

The host and the ecosystem are not always the same word — `npmjs.com` is the
host and `npm` is the OSV ecosystem — and getting that backwards produces a
query that matches nothing, silently. A test compares the two maps, because
`CPAN` and `CocoaPods` were in the first version of the host map and are not
OSV ecosystems at all.

No network call, ever. The alternative — one query per project — is 1908
requests against a budget this fleet shares with Renovate, and the question
"can this be asked at all?" is answered by the recipes.

### The identity table

```yaml
schema-version: 1
projects:
  openssl.org:
    cpe: [openssl:openssl]
  oracle.com/berkeley-db:
    cpe: [oracle:oracle_berkeley_db, oracle:berkeley_db]
```

Two rules it refuses to bend:

- **A `cpe` name must carry its vendor.** Yocto's documentation gives the reason
  from the other end: *"'tar' has been matching CVEs for the GNU tar package and
  also the node-tar node.js extension. To avoid this problem, use the vendor
  name as a prefix"*. A bare `openssl` is the 27-CVE answer above.
- **A database key is checked against an allowlist**, which is OSV's own list of
  defined ecosystems copied whole, spelling and case included — plus `cpe`,
  `GitHub` and `GitLab`, which are not ecosystems but repository-keyed
  advisories. A typo (`githb:`) in a denylist world is not a typo, it is a
  project that silently has no identity, indistinguishable from one nobody has
  looked at yet.

Several names per database is deliberate, not a mistake: NVD files Berkeley DB
under two product names, and dropping one loses the advisories filed there.

Note also what is **not** in OSV's ecosystem list: `pkgx`. It has `Homebrew`,
`Alpine`, `Wolfi`, `Chainguard` and `vcpkg`. The long-term answer for this fleet
is to become one of those rather than to keep translating into someone else's.

### `bk attest` — what a published bottle actually carries

Four kinds of thing are attached to a bottle as OCI referrers. Nothing could be
asked **which of them a given bottle has**.

```
$ bk attest --platform linux/x86-64 bitwarden.com 1.22.1
bitwarden.com 1.22.1 linux/x86-64: 4 referrer(s)
  application/vnd.cyclonedx+json       3412 bytes  pkg:pkgx/bitwarden.com@1.22.1
  application/vnd.in-toto+json         1890 bytes  https://github.com/go-zpkg/zbk@v0.26.0
  application/vnd.openvex+json         1204 bytes  1 statement(s): MAL-2026-3020=not_affected
  application/vnd.dev.cosign…          …           signed
```

That gap was not academic. `bk publish --advisories` attaches the VEX document
only when the tree holds a record for the project, and the factory passes the
tree through six lanes — one of which **mounts it into a chroot**. Every one of
those is a place the document can silently fail to appear, and a bottle with no
document looks exactly like a bottle nobody had anything to say about.
`bk source` and `bk buildenv` both *read* the provenance; neither **enumerates**.

**`--require` turns the report into a gate**, which is the point: a report is
what you read after something went wrong, a gate is what tells you.

```sh
bk attest --require application/vnd.openvex+json bitwarden.com 1.22.1
```

Two details that are not decoration. The summary **reads the blob**, not the
artifactType — a referrer that says OpenVEX and carries `{"statements":[]}`
reports `0 statement(s) — an empty document says nothing`, which `--require`
cannot see, because the type *is* present. And the output is ordered by
artifactType: a registry promises no order, and a report whose lines move
between runs cannot be diffed.

## `bk advisories` — what the answer was, and what we decided

Identity is half of it. The other half is the finding itself, and the record
that **justifies a rebuild**: one file per project, at
`advisories/<project>/advisories.yaml`.

```yaml
schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2026-0001
    aliases: [GHSA-xxxx-xxxx-xxxx]
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: detection
      - timestamp: 2026-10-11T09:00:00Z
        type: fixed
        fixed-version: 3.5.8_1
```

### Events, not a state

The shape is Wolfi's, and the reason is that a state cannot be superseded.
Wolfi's measured `curl.advisories.yaml` holds **59 advisories and 71 events** —
so most have one and some have three, which is exactly the history a single
`status:` field throws away. OpenVEX says the same from the other end:
`timestamp` is a required field, and a statement's timestamp is "the time at
which the information expressed in the Statement was known to be true". Two
contradictory undated statements cannot be ordered, so neither can be believed.

So: events, each **required** to carry a timestamp, and the last one in time
decides. They are sorted on read, so a rebase that reorders two appends cannot
change what a record means.

The vocabulary is Wolfi's too — `detection`, `true-positive-determination`,
`false-positive-determination`, `fixed`, `fix-not-planned`,
`pending-upstream-fix` — because each maps onto a VEX status, and a record that
cannot be emitted as VEX is a record only this fleet can read.

### `fixed-version` is where the rebuild counter earns its keep

`fixed-version: 3.5.8_1` says the **rebuild** carries the fix, not plain
`3.5.8`. `Advisory.FixedBy` asks `bottle` through the constraint language the
resolver already uses, so `3.5.8` does **not** satisfy it and `3.5.7_9` does
not either. Wolfi's own `fixed-version: 8.5.0-r0` carries the same counter, in
their spelling.

Which is why a Debian-style `3.5.8-1` is **refused**: that is how Debian and
Alpine spell the same thing, `bottle` splits a rebuild on `_`, and the record
would otherwise claim that plain `3.5.8` carries a fix it does not have.

### ⛔ `detected-version` is why a decision does not outlive its subject

A purl names a version, so the OpenVEX document we publish is a statement
**about a version**. A `false-positive-determination` carries none and reads
as "not affected, full stop" — so a determination made about 1.0.0 would be
re-emitted, unchanged, about every later version we publish.

```yaml
      - timestamp: 2026-10-10T12:00:00Z
        type: detection
        detected-version: 1.0.0        # what OSV was asked about
      - timestamp: 2026-10-11T09:00:00Z
        type: false-positive-determination
        justification: component_not_present
```

A known id reported at a version no event covers is **detected again**, as a
second event on the same record, and `vulnfetch -fail-on-new` then asks for a
decision about *that* version. Measured with a stub OSV that answers the same
id whatever version is asked:

| the record names | the catalogue publishes | gate |
|---|---|---|
| 1.0.0 | 1.0.0 | exit 0 — that is what was examined |
| 1.0.0 | **2.0.0** | exit **1** |
| *nothing* | 2.0.0 | exit 0 — a record written before this field keeps the old behaviour |

That last row is deliberate: reading "names no version" as "does not cover
2.0.0" would re-detect every legacy record at once — 90 over the real pantry
— and a gate that goes red for everything on its first run is one people
learn to scroll past.

Practitioner guidance on VEX is explicit that a "not affected" goes **stale**
when the component changes, and that a consumer-facing statement which is
stale is worse than none at all: it stops the reader looking. Wolfi's
`fixed-version` carries a version for the same reason; this is the field a
*determination* was missing.

### ⛔ The gate and the document read the same silence in opposite directions

`detected-version` is now meaningful on **every** event, not only a detection:
for a decision it says which version the decision was made for. And the two
readers of that field disagree on purpose about what an *absent* one means.

| | a record that names no version | why |
|---|---|---|
| the gate (`vulnfetch -fail-on-new`) | covers every version — stays green | it interrupts **us**, and 90 legacy records going red at once is a gate people learn to scroll past |
| the document (`EncodeVEX`) | covers no version — downgrades | it reassures a **stranger**, and a stale "not affected" stops them looking |

The harms are not symmetric, so the defaults are not either: *when in doubt do
not interrupt ourselves; when in doubt do not reassure somebody else.*

What the emitter does, for the two statuses that tell a reader to stop
looking — `not_affected` and `fixed`:

```
record determines not_affected for 1.0.0, bottle is 1.0.0  → not_affected + justification
record determines not_affected for 1.0.0, bottle is 2.0.0  → under_investigation, status_notes names 1.0.0
record names no version at all,           bottle is 1.0.0  → under_investigation, status_notes says so
```

Neither the `justification` nor the `impact_statement` travels onto a
downgraded statement: the prose was written about another artefact, and
carrying it over would put the reassurance back in by the side door — in the
one field a human actually reads.

`affected` is deliberately **not** downgraded. Restating it for an unexamined
version over-warns, which costs noise; downgrading it would turn a warning
into "we are looking into it", and nothing should move that way by itself.

A product therefore has to say which version it is, and `EncodeVEX` refuses
one that does not rather than guessing from the purl:

```
vuln: vex: demo: product pkg:pkgx/demo@1.0.0 has no version — a statement
names a version, so one cannot be written for an artefact that has none
```

One record can now produce **two** statements, when the versions it was handed
are not all covered. That is what #340 could not express: a single statement
for every product is only correct while every product is the same version.

### The path and the file must agree

`bk advisories` refuses a file whose `project:` disagrees with its directory. A
file copied from a neighbouring project and edited in part would otherwise
attach its findings to the wrong package, and nothing else in the record says
which project it is about.

```
$ bk advisories -dir advisories
2 project(s) read from advisories, 3 advisory(ies)
  detection                    2
  true-positive-determination  0
  false-positive-determination 0
  fixed                        1
  fix-not-planned              0
  pending-upstream-fix         0
```

### OpenVEX out

`vuln.EncodeVEX` writes the records as an OpenVEX v0.2.0 document, which is the
form a scanner already reads. The mapping is the design decision, so it is a
table and not a chain of ifs:

| event | VEX status | |
|---|---|---|
| `detection` | `under_investigation` | a database said our NAME matched |
| `true-positive-determination` | `affected` | + an action statement |
| `false-positive-determination` | `not_affected` | + the justification **label** |
| `fixed` | `fixed` | a version of ours carries it |
| `fix-not-planned` | `affected` | + why nothing is coming |
| `pending-upstream-fix` | `affected` | + what is being waited on |

`detection` becoming `under_investigation` rather than `affected` is the one
worth defending: a detection is a database saying our *name* matched, and the
27-CVE openssl measurement above says what that is worth. Emitting those as
`affected` would publish 23 false alarms with our signature on them.

A `not_affected` statement carries the machine-readable `justification` label
and puts the prose in `impact_statement` beside it, never instead of it —
OpenVEX allows the text form and then says it "breaks VEX automation and
interoperability".

Each statement is dated with **its own event's** timestamp, not the document's,
so a publish does not re-date the whole history to today. The encoding is
deterministic — subjects by project, statements by id — because a document that
differed run to run could not be compared with the one already attached to a
bottle.

### The bottle carries its own justification

```
bk publish --to oci://ghcr.io/go-zpkg/bottles --project openssl.org \
           --version 3.5.8_1 --platform linux/x86-64 \
           --advisories ./advisories  openssl.org-3.5.8_1.tar.xz
```

`bk factory --advisories` takes the same flag and passes it to **every** publish
it makes — the bottles it builds and the ones it mirrors, because what is known
about a package is not a property of who compiled it.

The factory also **validates the whole tree once, before the first build**.
`vexReferrer` refuses to publish a bottle whose record does not parse, which is
the right answer in the wrong place: a chunk of fifty runs for hours, and the
fortieth bottle is where that refusal would land. The check runs before the
pantry is read and before the closure walk resolves a single version over the
network, and says what it loaded:

```
advisories: 1 project(s) with records, from advisories
```

The count is there because a run that loaded the tree and one pointed at the
wrong path otherwise print the same thing — and an **empty** tree is an error,
for the same reason `bk advisories` makes it one.

With `--advisories`, the bottle gets a third referrer beside its CycloneDX SBOM
and its in-toto SLSA provenance:

| referrer | says |
|---|---|
| `application/vnd.cyclonedx+json` | what is inside |
| `application/vnd.in-toto+json` | how it was built, and by which `bk` |
| `application/vnd.openvex+json` | which vulnerabilities were considered, and what was decided |

This is what makes a rebuild **self-justifying**. Until now a bottle rebuilt
for a security fix looked exactly like one rebuilt for any other reason: the
version string said `_1` and nothing said why.

Three details earn their keep:

- The statement is bound to the **tarball digest**, the same anchor the SBOM,
  the provenance and the cosign payload use. Four attestations about one
  artefact, not four descriptions that happen to agree.
- The document is dated with the build timestamp, which honours
  `SOURCE_DATE_EPOCH`, and its `@id` carries no date or counter. So re-publishing
  an unchanged bottle produces a byte-identical document — the same referrer
  digest, an idempotent re-push rather than a second referrer beside the first.
  The `@id` *does* carry the platform, because two platforms' bottles are two
  artefacts.
- **A broken advisory file stops the publish.** A file that exists and cannot be
  parsed must not become a silent omission: the bottle would be pushed, look
  complete and assert nothing — and an absent VEX document reads as "nothing was
  ever found", which is the opposite of what a broken record means. A file that
  is simply *absent* is fine and attaches nothing, because most projects have
  never been triaged.

## `bk vulnfetch` — asking a database, once

```
$ bk vulnfetch -dir ~/Library/Caches/pkgx/pantry
1563 recipe(s) read from …/pantry/projects
129 identity(ies) asked, 1207 not answerable by OSV (repository- or CPE-keyed)
55 finding(s) across 14 project(s)
  bitwarden.com
    MAL-2026-3020            npm:@bitwarden/cli
  crates.io/bat
    GHSA-p24j-h477-76q3      crates.io:bat
    RUSTSEC-2021-0106        crates.io:bat
  …
nothing written — pass -write to record these as detections
```

**One HTTP request.** OSV's `/v1/querybatch` takes a list and answers in order,
so 129 questions cost one round trip and no API key. Nothing here touches the
GitHub API, so nothing here competes with Renovate.

It **reports by default**. A sweep that writes on its first run writes whatever
that run happened to find into files a person then has to audit; and the thing
worth knowing before writing anything is the scale.

### ⛔ Ask at the version we publish, or the number means nothing

Without `-catalog` the question is about the package **as a whole**, so the
answer is every advisory it has ever carried — including ones fixed long
before the version we ship. The two questions over the same pantry, the same
run, on **2026-10-17**:

```
$ bk vulnfetch -dir pantry
171 identity(ies) asked, 1500 not answerable by OSV (repository- or CPE-keyed)
748 finding(s) across 21 project(s)

$ bk vulnfetch -dir pantry -catalog catalog/darwin-aarch64.json
137 of them asked AT the version the catalogue publishes; the rest as a whole package
171 identity(ies) asked, 1500 not answerable by OSV (repository- or CPE-keyed)
90 finding(s) across 5 project(s)
```

**658 of the 748 do not affect anything we publish.** A list that large with
no decision behind any line is read once and then never again.

### ⛔ And read the remaining 90 carefully — it is not what it looks like

Every one of those five projects — `coder.com/code-server`, `nx.dev`,
`pi.dev`, `snyk.io`, `vercel.com/next` — answers **`no bottle here`** on
darwin/aarch64. They have no published version, so `-catalog` had none to
pin, and they fell back to being asked as **whole packages**. The 90 are the
unfiltered question surviving for the projects the filter could not reach.

Against what we actually ship on this platform the count is **zero**:
`bitwarden.com` is published at 1.22.1 and OSV returns nothing for it, which
is right — `MAL-2026-3020` affects 2026.4.0.

Checked with `pkgx ls <project>` on each of the six, after reading the
written records and finding **no `detected-version` in any of them** — the
field only appears when a version was asked about, so its absence was the
tell. The first version of this paragraph called the 90 "a list someone can
work", which was wrong: they are about packages this platform does not carry.

The honest next step is therefore not to triage them but to **skip a project
with no bottle for the platform**, so the unfiltered question is not asked at
all.

The output says **which** question it asked, in both modes, because the same
count means a different thing in each.

⛔ **It will not guess.** Two projects can carry one identity; if they publish
different versions there is no single version to ask about, and picking either
would under-report for the other. Under-reporting hides a vulnerability, so
the question widens back to the whole package and the count says so.

### `-fail-on-new` — a verdict, not just a report

`vulnfetch` returned 0 whatever it found. With `-fail-on-new` it exits
non-zero when a finding has **no decision recorded** in the advisory tree:

```
vulnfetch: 1 finding(s) with no decision in advisories —
  rebuild, or record why the published version is not affected
```

⛔ **The gate is on what is NEW, not on what exists.** A job that failed while
any finding existed would be red from its first run — 90 of them on
2026-10-17 — and a check that is red every day is one people learn to scroll
past. That is not hypothetical in this fleet: `versioncheck` on the landing
site was red for eight days running for exactly that reason, fixed by hand
each time rather than noticed.

Red on something **new** is a question with an answer, and the error names
both ways out because either one makes it green again.

### ⛔ OSV cannot be asked about a repository

Measured against the live API on 2026-10-11:

| asked | answered |
|---|---|
| `{"package":{"name":"time","ecosystem":"crates.io"}}` | 4 vulnerabilities |
| `{"package":{"name":"bpb","ecosystem":"crates.io"}}` | `{}` — nothing known |
| `{"package":{"purl":"pkg:github/curl/curl"}}` | `{}` |

The first two are the normal pair. The third is the one that shapes the tool: an
OSV query takes a package in an **ecosystem** (or a commit), and a GitHub
repository is neither — so the `{}` there is *not* "no known vulnerabilities".

Unanswerable identities are therefore **dropped before the request and counted
out loud**, rather than sent and found empty. Of this pantry's identities, 1207
are repository- or CPE-keyed: a sweep that stayed quiet about them would read as
a clean bill of health for three quarters of the fleet. Those need GitHub's own
advisory API, which does cost the shared budget, and that is a separate piece of
work not pretended to here.

### What `-write` does, and what it refuses to do

It adds a `detection` event per new id, whose note records **which key found
it** — with two identities per project that is not recoverable afterwards.

Three things it will not do:

- **Overwrite a decision.** An id already recorded is left entirely alone, and
  the check includes every advisory's `aliases`, because a record filed under
  its CVE is the same record OSV returns under a GHSA. Without this, every run
  would drag a `fixed` back to `under_investigation` and the triage would never
  converge.
- **Trust a positional answer blindly.** OSV answers in the order asked and says
  nothing about which query each result belongs to, so a response with fewer
  results than queries is an **error** — otherwise every finding from that point
  on would be attributed to the wrong package.
- **Replace a file it cannot read.** A file that exists and does not parse stops
  the sweep, rather than being replaced by one holding only today's detections,
  which would delete every decision in it.

### A known overstatement

The finding count counts **ids, not vulnerabilities**. `RUSTSEC-2021-0106` and
the GHSA beside it for `crates.io/bat` are the same defect — verified, its
`aliases` contain `CVE-2021-36753` — and OSV's *batch* answer carries no
aliases. So 55 ids are fewer than 55 distinct vulnerabilities. Resolving them
costs one `/v1/vulns/{id}` request each and is not done yet; `MergeDetections`
already de-duplicates against aliases *already recorded*, which is what keeps a
hand-written record from being doubled on the next run.

## Where the source came from, and whether it changed

`bk` extracts tarballs from **233 distinct upstream hosts**, and in the
sovereign lane the build that consumes them runs as root inside a chroot. What
checks that?

Almost nothing, before this. `bk` does verify a source checksum when a recipe
declares one — but measured over a fresh `pkgxdev/pantry`, exactly **one recipe
of 904** declares one, and that one (`openssl.org`) points at a `.sha256`
served by the *same host* as the tarball: it detects corruption, not
substitution. The same recipe declares `sig: ${{url}}.asc`, and nothing in bk
reads that field at all.

So `--source-mirror` grew a second job. It already kept every archive a build
downloads, addressed by its sha256; now it also records **which digest each URL
served**, and refuses bytes that disagree:

```
source pin: 9f86d0…  matches what https://ftp.gnu.org/…/sed-4.10.tar.xz served before
fetch: this URL has served different bytes before: https://…/x-1.2.tar.gz
  now serves 2c26b4…, and served 9f86d0… before
```

Trust on first use. It does not make an upstream trustworthy — it makes a
**change** visible, which is the part nobody had.

A version bump is not a change here: the version is in the URL, so a new
release asks a question that has never been asked and is recorded rather than
refused. What fires is the *same* URL serving *different* bytes — a re-cut
release, a compromised mirror, a hijacked domain.

The uncomfortable third case is a store that cannot be **asked**. That is not
an absent pin, and treating the two alike is how trust-on-first-use quietly
becomes trust-every-time. They are distinguished, said out loud, and
`--source-pin-strict` decides which one is fatal — warn and continue by
default, because an unreachable registry is not evidence of tampering and a
build must not die because ghcr hiccuped.

Still open (go-zpkg/bk#282): nothing reads `sig:`. Verifying a detached
signature needs a key policy — *whose* key — and that is a decision, not a
patch.

## What bounds an `.xz` source archive

`.tar.xz` sources are decoded with
[`go-compressions/xz`](https://github.com/go-compressions/xz), not
`ulikunitz/xz`. The latter allocates the LZMA2 dictionary whole from the block
header (`DictCap` is a minimum, not a ceiling): a 44-byte `.xz` declaring a
1.5 GiB dictionary allocated 1,610,663,976 bytes. Here the decoder's window
grows with the decoded data: the same kind of input — a stream declaring 1.5 GiB
over a few bytes — allocates about 22 KB (`fetch/xzbomb_test.go`, run in CI as a
compiled binary under `ulimit -v` and `GOMEMLIMIT`). The dictionary a stream may
make the decoder keep is capped at 256 MiB (`fetch.maxXzDictionary`, above the
64 MiB of `xz -9`); data that needs more is refused with `xz.ErrTooLarge`.
`ulikunitz/xz` remains in `go.mod` only for the tests that build `.xz` fixtures
(encode side).

## The ELF RUNPATH rewriter

`fixup.SetRunpath` overwrites an ELF's `DT_RUNPATH`/`DT_RPATH` string **in place**
(pure Go): it locates the string offset in `.dynstr` and rewrites the bytes,
zero-padding slack. It cannot grow `.dynstr`, so the build links binaries with a
long `-Wl,-rpath` placeholder that the final `$ORIGIN`-relative value fits inside —
the same budget model `patchelf --set-rpath` sidesteps by rewriting the file.

## Where it is proven to work

A build tool whose whole premise is *Target ≠ Host* has to be right about
widths and byte order, because that is exactly what it is manipulating: ELF
`DT_RUNPATH` strings rewritten in place, `.dynstr` offsets, tar and xz streams,
OCI manifests. None of that is checked by a compiler. So CI builds eight
targets — linux on amd64, arm64, riscv64, ppc64le, s390x and loong64, plus
darwin/arm64 and windows/amd64, all `CGO_ENABLED=0` — and then **runs the
suite** on five of them under `qemu-user`:

```
test (arm64, qemu)  test (riscv64, qemu)  test (ppc64le, qemu)
test (s390x, qemu)  test (loong64, qemu)
```

`s390x` is there because it is big-endian and nothing else here is; an ELF
header read through the host's byte order instead of `encoding/binary` is wrong
on that machine and on no other. `-count=1`, so a cached PASS from the host
architecture cannot stand in for a run that never happened. The same job holds
the 100% statement-coverage gate: below it, CI prints the uncovered blocks and
fails.

## `bk catalog`

Builds the catalogue a browser (`pkgx ls`, `<TAB>`) reads: every project named
by the pantry and the overlay, with its runtime dependencies, and — with
`--versions` — the newest version the registry really carries for
`--platform`. `--publish` pushes it signed.

`--recipes DIR` (repeatable) names a **flat** recipe tree
(`<DIR>/<project>/package.yml`, the layout of `go-zpkg/packages/wasip1/recipes`)
whose projects are listed too. A platform lane can build a project that neither
the pantry nor the overlay carries — `github.com/simdjson/simdjson` for
`wasip1/wasm` — and without this flag its published bottle was missing from
that platform's catalogue (go-zpkg/packages#387).

**The lane's recipe wins** for a project both trees have (since go-zpkg/bk#376;
v0.45.0 had the pantry winning). A recipe in a platform lane's tree is the
recipe *for that lane*: its `provides` and `dependencies` describe the bottle
that was actually built, whereas the pantry's describe the host build. With the
pantry winning, the published `wasip1/wasm` catalogue gave `zlib.net` no command
although its bottle ships `bin/minigzip.wasm`, listed `age-keygen` for
`filippo.io/age` although the lane builds `./cmd/age` only, and made `lua.org`
depend on `gnu.org/readline`, which the lane does not build against and which
is not published for that platform. The recipe is read whole, never merged key
by key, so a catalogue entry never mixes two builds. The rule for a caller:
pass `--recipes` **only** for a platform whose tree is its authoritative recipe
set (the packages workflow does so for `wasip1/` alone). A tree that is not
would now override the pantry for every project it shares; there is no merge
mode, by design.

## `bk provides` — does the bottle say what the catalogue says?

```
bk provides --catalog catalog.json --platform wasip1/wasm [--fail] [project...]
```

Installs each project for `--platform` (every published project of the
catalogue when none is named), lists the commands in the bottle's `bin/`
(`.wasm` stripped on `wasip1`, `.exe` on `windows`) and compares them with the
`provides` the catalogue states. The two differences are reported **apart**,
because they are different failures:

- **LISTED, NO FILE**: `pkgx -Q age-keygen` names a package that cannot supply
  the command.
- **FILE, NOT LISTED**: the command exists and is invisible to `pkgx -Q`,
  `pkgs search` and the `<TAB>` index (`minigzip` in the zlib.net bottle).

`--catalog` takes `catalog.json` or the catalogue bottle's `.tar.gz`. `--fail`
exits 1 on any finding or on a project that could not be checked. It lives in
`bk` because it needs the catalogue types, the platform-explicit closure
install and the same `provides` reduction `bk catalog` applies; a workflow runs
it right after `bk catalog`. Found by running every published wasm module, not
by comparing the two (go-zpkg/bk#376).

## License

BSD-3-Clause. Copyright the bk authors.
