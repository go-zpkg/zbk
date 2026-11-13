# Isolation Phase B — building artifacts that link only our own glibc

**Written 2026-08-04 as a design note. It shipped; this is the rationale behind
what shipped, kept because the hazards below are still the ones that bite.**

## What shipped, and how to read this note

The mechanism is `--libc=zpkgx` on `zpkb build` and `zpkb factory` — not the
`ZPKB_ZPKG_LIBC=1` environment variable the body of this note names. That name was
the design-time one; every occurrence below should be read as "the sovereign-libc
mode". The rest of the analysis stands as written.

⛔ The commands were `bk` and `pkgx` when this was written, and the flag value
was `pkgx`. They are `zpkb` and `zpkgx`, and the value is `zpkgx`
(go-zpkg/zpkb#457). This note has been brought in line throughout: where it
says `zpkb` or `zpkgx` it means the tool, and where it says **upstream pkgx**
it means the project this one forked from.

Two other things changed on the way from note to code:

- **No `clang.cfg`.** The envoy pattern that inspired this (a config file beside
  the packaged clang) was generalised into flags the build wrapper emits directly:
  `--sysroot`/`-isystem`/`-B`/`-L` at the glibc artifact plus
  `--rtlib=compiler-rt -fuse-ld=lld` and `--unwindlib=none`, carried **inside
  `$CC`/`$CXX`** rather than in `CFLAGS`. That last detail is not cosmetic:
  libtool does not pass `CFLAGS`/`LDFLAGS` to its own link line but preserves
  `$CC` verbatim, so a recipe linking through libtool gets the sovereign
  toolchain only this way.
- **C++ works too.** The note scopes the mode to C because the `llvm.org` artifact
  ships no C++ runtime. `libcxx.llvm.org` now supplies libc++/libc++abi/libunwind,
  so C++ recipes link `-stdlib=libc++` instead of the container's libstdc++.

`--glibc <version>` pins the sysroot to an exact glibc line (see the
"old-CI-base glibc" hazard below), and `zpkb builder` stages the FROM-scratch
rootfs the whole thing was for: three static Go binaries plus toolchain artifacts
from the signed registry, nothing else.

## The problem

`zpkb` builds C/C++ recipes with whatever compiler `zpkb` resolves onto `PATH`. On
Linux that is the packaged `llvm.org` clang (added implicitly by
`buildscript.WrapOptions.depPlus`), but clang still links against **the build
host's glibc** — in CI that is the Debian container's `/usr/lib/.../libc.so.6`
and its `/lib64/ld-linux-*.so.*` loader. The produced artifact therefore:

* carries a `PT_INTERP` pointing at the *host* dynamic linker
  (`/lib64/ld-linux-x86-64.so.2` / `/lib/ld-linux-aarch64.so.1`), and
* resolves `libc.so.6`, `libm.so.6`, … from the host at runtime.

That breaks the promise of a **relocatable artifact that runs `FROM
scratch`**: on a host with an older glibc (or none — Alpine/musl, a scratch
image) the artifact fails to start with the classic `/lib64/ld-linux-...: no such
file` or `version 'GLIBC_2.NN' not found`.

The fix already exists as a recipe-level pattern — the **envoy recipe** on the
`new/envoyproxy` branch writes a `clang.cfg` that re-targets clang at the
`gnu.org/glibc` artifact. This note generalises that pattern into a `zpkb`
build-env mechanism that applies to **every** recipe without the recipe having
to opt in.

## The proven recipe-level pattern (envoy)

The envoy recipe (`projects/envoyproxy.io/package.yml`, branch `new/envoyproxy`)
declares three toolchain artifacts as build deps —

```yaml
build:
  dependencies:
    llvm.org: '~22'            # clang (llvm.org ships clang, no libc)
    gnu.org/glibc: '*'         # relocatable libc: crt*.o + libc.so.6 + ld-linux
    gnu.org/gcc/libstdcxx: '*' # libgcc_s.so.1 (the unwinder)
```

— then writes, next to the clang binary, a **`clang.cfg`** that clang
auto-loads on every invocation:

```sh
GLIBCLIB=$(dirname "$(ls "{{deps.gnu.org/glibc.prefix}}"/lib/glibc-*/libc.so.6 | head -1)")
GLIBCLD=$(ls "$GLIBCLIB"/ld-linux*.so.* | head -1)
GCCLIB=$(dirname "$(ls "{{deps.gnu.org/gcc/libstdcxx.prefix}}"/lib*/libgcc_s.so.1 | head -1)")
cat > "$CLANGBIN/clang.cfg" <<CFG
-B$GLIBCLIB
-L$GLIBCLIB
-Wl,--dynamic-linker=$GLIBCLD
-Wl,-rpath,$GLIBCLIB
-Wl,-rpath,$GCCLIB
-Wl,--disable-new-dtags
CFG
```

What each flag buys:

| flag | effect |
|------|--------|
| `-B$GLIBCLIB` | clang finds the glibc artifact's `crt1.o crti.o crtn.o` (startup objects) here instead of `/usr/lib` |
| `-L$GLIBCLIB` | link-time library search resolves `-lc`, `-lm`, … to the packaged glibc |
| `-Wl,--dynamic-linker=$GLIBCLD` | sets the binary's `PT_INTERP` to the **artifact's own** `ld-linux` — the single most important line: it decides which loader the OS hands the process to at exec time |
| `-Wl,-rpath,$GLIBCLIB` | bakes the glibc artifact's dir into `DT_RPATH`/`DT_RUNPATH` so `libc.so.6` resolves inside our own closure at runtime |
| `-Wl,-rpath,$GCCLIB` | same for `libgcc_s.so.1` (the C++/unwind runtime), which lives in the gcc artifact, not glibc |
| `-Wl,--disable-new-dtags` | emit **`DT_RPATH`** rather than `DT_RUNPATH`. `DT_RUNPATH` is *not* consulted for the transitive deps of a `dlopen`'d library; `DT_RPATH` *is*. This matters for any binary that `dlopen`s a plugin whose own `NEEDED` must resolve inside the closure |

The decisive property: a `clang.cfg` sitting beside the clang binary reaches
**every** clang invocation — the recipe's own compiles, autotools/CMake
`configure` probes, sub-makes, and even *foreign* host tools a build spawns
(bazel/`foreign_cc` running luajit's `minilua`) — **with no wrapper script**, so
clang's `/proc/self/exe` self-location for its resource dir and libc++ headers
still works. A `CC="clang <flags>"` wrapper would not reach a sub-build that
resets `CC`; a config file beside the binary does.

Note the envoy pattern redirects only the **link** side (crt, `-L`, loader,
rpath). It deliberately leaves the **header** search on the host `/usr/include`.
That is safe because glibc is backward-compatible at the *symbol-version* level:
the glibc artifact is chosen to be **≥** the host glibc used for headers, so
every symbol version referenced by a host header is present in the linked
packaged libc. (The stricter `-nostdinc -isystem $glibc/include` "sysroot" regime from
`gnu.org/glibc/README.md` is only needed when the packaged glibc is *older* than the
host — e.g. deliberately building a manylinux-2.28 floor. See Hazard (f).)

## Generalising into a `zpkb` build-env mechanism

The insertion points in `zpkb` are already the right shape. Two functions own the
build environment:

* `build.EvalDeps` (`build/build.go`) assembles the `zpkgx +…` closure: a
  `BaseToolchain()` plus the recipe's runtime + build deps.
* `buildscript.Wrap` (`buildscript/wrapper.go`) emits the runnable script:
  `eval "$(zpkgx +…)"`, then the target-keyed `LDFLAGS`/`CFLAGS`, then the user
  script. `depPlus` is exactly where `+llvm.org` is appended today.

The mechanism adds, **for a linux target only, when `ZPKB_ZPKG_LIBC=1`**:

1. **Implicit toolchain deps.** Inject `gnu.org/glibc` and
   `gnu.org/gcc/libstdcxx` into the `zpkgx +…` closure (clang from `llvm.org` is
   already injected by `depPlus`). This is a one-line addition to a new
   `libcToolchain()` helper consumed by `EvalDeps`, mirroring `BaseToolchain()`.
   These are *build-time* deps; whether the produced artifact also lists
   `gnu.org/glibc` as a **runtime** dep is a recipe decision (envoy does, so its
   glibc ships in the artifact's closure — see "Runtime closure" below).

2. **A generated `clang.cfg`.** In the wrapper, before `cd $SRCROOT`, emit the
   shell that (a) locates the glibc artifact's lib dir + loader + libgcc_s from the
   already-`eval`'d `$ZPKG_DIR`, (b) writes `clang.cfg` next to the resolved
   clang, and (c) symlinks `clang++.cfg`, `clang-cpp.cfg`, `<versioned>.cfg` to
   it. Because the zpkgx env is `eval`'d with `set -a` just above, the glibc/gcc
   prefixes are discoverable by globbing `$ZPKG_DIR/gnu.org/glibc/v*/lib` — no
   `{{deps.*}}` moustache needed (though the `{{deps.gnu.org/glibc.prefix}}`
   token is available too, since `DepTokens` already resolves it).

   Locating clang itself: `command -v clang` after the zpkgx `eval` gives the
   shimmed path; `readlink -f` resolves it into the real
   `$ZPKG_DIR/llvm.org/v*/bin` dir where the `.cfg` must land (a `.cfg` beside a
   symlink is *not* read — clang reads it beside the **real** binary, located
   via `/proc/self/exe`).

3. **No change for recipes with no compile step.** Pure-script recipes never
   invoke clang, so a `clang.cfg` on disk is inert — the mechanism is a no-op
   for them by construction (Hazard (e)).

Sketch of the wrapper addition (see the experimental Go at the end):

```sh
# --- ZPKB_ZPKG_LIBC: retarget clang at the pkgx glibc artifact (linux only) ---
if [ -n "$ZPKB_ZPKG_LIBC" ]; then
  GLIBCLIB=$(dirname "$(ls "$ZPKG_DIR"/gnu.org/glibc/v*/lib/glibc-*/libc.so.6 2>/dev/null | sort | tail -1)")
  GLIBCLD=$(ls "$GLIBCLIB"/ld-linux*.so.* 2>/dev/null | head -1)
  GCCLIB=$(dirname "$(ls "$ZPKG_DIR"/gnu.org/gcc/libstdcxx/v*/lib*/libgcc_s.so.1 2>/dev/null | head -1)")
  CLANGREAL=$(readlink -f "$(command -v clang)")
  cat > "$(dirname "$CLANGREAL")/clang.cfg" <<CFG
-B$GLIBCLIB
-L$GLIBCLIB
-Wl,--dynamic-linker=$GLIBCLD
-Wl,-rpath,$GLIBCLIB
-Wl,-rpath,$GCCLIB
-Wl,--disable-new-dtags
CFG
  for a in clang++ clang-cpp "$(basename "$CLANGREAL")"; do
    ln -sf clang.cfg "$(dirname "$CLANGREAL")/$a.cfg"
  done
fi
```

## Hazards (concrete)

### (a) The "old-CI-base glibc" / `GLIBC_2.29 not found` class

This is the sharpest hazard and it cuts **both ways**:

* *Produced binaries* linked against the (newer) pkgx glibc will not run on an
  older host — which is the whole point, and is fine because we ship the pkgx
  glibc in the artifact's runtime closure.
* *Build-time host tools* are the trap. A large build compiles a helper (a code
  generator, `minilua`, a `foreign_cc` sub-tool) and then **runs it during the
  build**. If that helper was linked with our `clang.cfg`, its `PT_INTERP` is
  the pkgx `ld-linux` — which must exist and be executable at that path *during
  the build* (it does: it is in the `eval`'d pkgx closure). Conversely a helper
  linked *before* clang.cfg exists, or by a *different* compiler (the host gcc a
  `configure` picked), may need a glibc symbol version the host lacks. The
  envoy comment records exactly this: `minilua: libm.so.6: version GLIBC_2.29
  not found`. The `clang.cfg`-beside-the-binary approach is what fixes it,
  because it reaches those foreign host-tool compiles too. **Mitigation:** put
  the pkgx glibc on the toolchain closure *and* keep `clang.cfg` in place for
  the whole build, so every host tool built during the build is itself
  self-consistent against the pkgx loader.

### (b) Recipes that set their own `CC` / `CFLAGS`

If a recipe hard-codes `CC=gcc` (host gcc) or `export CC=cc`, the `clang.cfg`
never applies and the artifact links the host glibc — silently. Likewise a recipe
that sets `LDFLAGS` may or may not clobber ours depending on order.
**Mitigations, in order of preference:**

1. Prefer the config-file mechanism over `CC=`, so a recipe that only *appends*
   to `CFLAGS`/`LDFLAGS` still inherits the loader retarget.
2. Detect the hazard: after the build, the verifier (below) fails the build if
   any produced ELF's `PT_INTERP` is not the pkgx loader. This converts a silent
   host-glibc leak into a hard build error. Under `ZPKB_ZPKG_LIBC=1` this check is
   the real guarantee; the `clang.cfg` is best-effort, the verifier is the gate.
3. A recipe that legitimately needs the host gcc (e.g. a kernel module) opts out
   via a per-recipe skip (analogous to the existing `skip: [fix-patchelf]`).

### (c) Static vs dynamic libc

`-static`/`-static-libgcc` recipes produce a binary with **no `PT_INTERP` and no
`DT_NEEDED`** — fully self-contained already, and the loader flag is a harmless
no-op (nothing to interpret). The verifier must treat "no `PT_INTERP`" as a
**pass**, not a failure (a static binary is *more* self-contained than a
dynamic one). Partially-static (`-static-libgcc` but dynamic libc) still needs
the pkgx loader, so the mechanism still applies. glibc itself is only *partly*
static-friendly (NSS `dlopen`s modules), but that is a property of the recipe's
choice, not of this mechanism.

### (d) Cross-compile (Target ≠ Host)

`bk` is Target ≠ Host by design. The `clang.cfg` here targets **the build
host's** arch loader (`ld-linux-<hostarch>`). For a genuine cross build
(linux/x86-64 target on a linux/aarch64 host, or the Windows-PE cross path) the
loader/glibc must be the **target's**, and a single host-local `clang.cfg` is
wrong. Constraints:

* The Windows cross path has **no glibc and no `PT_INTERP`** (PE, not ELF) — the
  mechanism must be **skipped** for `Target.Platform == "windows"` (it already
  is: `depPlus` doesn't even add clang there).
* A linux→linux cross to a different arch needs the **target-arch** pkgx glibc
  artifact and a target-arch `--dynamic-linker`. pkgx artifacts are per-arch, so
  this is expressible, but the prototype and first landing scope to
  **Target.Arch == Host.Arch** (native). Cross-arch libc retarget is future
  work; the gate is `ZPKB_ZPKG_LIBC=1 && linux && Target==Host arch`.

### (e) Recipes with no compile step (pure scripts)

A recipe whose `build.script` only copies files / runs a language package
manager never invokes clang. Writing `clang.cfg` is then inert and injecting
`gnu.org/glibc` as a build dep is wasted download but not incorrect. To avoid
the waste, the mechanism can be gated on the recipe actually declaring a
compiler dep or on a heuristic, but **correctness does not depend on it** —
these recipes are unaffected either way. Default: only add the glibc/libstdcxx
build deps when clang is being added (i.e. the same condition `depPlus` uses to
add `+llvm.org`).

### (f) Header/symbol-version skew

Because the envoy pattern keeps host `/usr/include`, the pkgx glibc **must be ≥
the host glibc** or a host header may reference a symbol version the older pkgx
libc lacks (link error, or worse a runtime `GLIBC_2.NN not found`). pkgx's
current glibc is 2.41–2.43, newer than any supported CI base, so this holds
today. If a recipe deliberately targets an *older* floor (manylinux), it must
use the stricter `-nostdinc -isystem $glibc/include` sysroot regime from
`gnu.org/glibc/README.md` — that is out of scope for this mechanism and belongs
to a per-recipe opt-in.

## Verifying a produced artifact is self-contained

The guarantee is checkable with pure-Go `debug/elf` — no `readelf`/`ldd`
shell-out. `bk`'s `fixup` package already exposes `ReadNeeded` and
`ReadRunpath`; the missing primitive is a **`PT_INTERP` reader**. A binary is
self-contained against the pkgx closure iff:

1. **`PT_INTERP`** is either absent (static — pass) **or** equal to the pkgx
   `ld-linux` path (inside `$ZPKG_DIR/gnu.org/glibc/...`). It must **not** be
   `/lib64/ld-linux-*` or `/lib/ld-linux-*` (host loader → fail).
2. Every **`DT_NEEDED`** resolves along the binary's own `DT_RPATH`/`DT_RUNPATH`
   into the pkgx closure — no needed lib is satisfiable *only* from the host
   `/usr/lib`. (After `bk`'s existing rpath fix-up the entries are
   `$ORIGIN`-relative into the artifact; the check resolves them relative to the
   binary.)

`readelf` cross-check for humans (what the prototype below captures):

```
readelf -l <bin> | grep -A1 INTERP     # → pkgx ld-linux, not /lib64/...
readelf -d <bin> | grep -E 'NEEDED|RPATH|RUNPATH'
```

Proposed Go helper (in `fixup`, so it can gate the build under
`ZPKB_ZPKG_LIBC=1`):

```go
// ReadInterp returns an ELF's PT_INTERP (the requested dynamic linker), or ""
// when the file has no interpreter (a static executable). Pure debug/elf.
func ReadInterp(path string) (string, error)
```

`debug/elf` gives this directly: iterate `f.Progs`, find `elf.PT_INTERP`, read
its `Open()` bytes, trim the trailing NUL. The gate then asserts
`interp == "" || strings.HasPrefix(interp, pkgxGlibcDir)`.

## Runtime closure

Linking the pkgx loader is necessary but not sufficient: the artifact's *runtime*
closure must actually **contain** that loader + `libc.so.6` + `libgcc_s.so.1`.
Two ways, matching what the recipes already do:

* declare `gnu.org/glibc` (and, for C++, `gnu.org/gcc/libstdcxx`) as a
  **runtime** dependency so pkgx installs it alongside the artifact (envoy does
  this), or
* vendor the needed `.so`s into the artifact's own `lib/` and let `bk`'s rpath
  fix-up point `$ORIGIN` at them (heavier artifact, but truly `FROM scratch` with
  no pkgx dep).

The first is the pkgx-idiomatic choice and is what `ZPKB_ZPKG_LIBC=1` should pair
with; the verifier checks link-correctness, the runtime-dep declaration checks
closure-completeness.

## Measured prototype (executed, not asserted)

Run on the `debian` Tart VM — **aarch64 Linux, host glibc 2.41-12+deb13u3**, no
clang installed on the host (`which clang` → not found, so clang can only come
from pkgx). Artifacts used, pulled from `dist.pkgx.dev` and laid out in the pkgx
`<project>/v<version>/` convention under a user-owned prefix:

* `gnu.org/glibc` **v2.44.0** — `lib/glibc-2.44/{libc.so.6, libm.so.6,
  ld-linux-aarch64.so.1, crt1.o, crti.o, crtn.o}`
* `llvm.org` **v22.1.8** — `bin/clang` (clang 22.1.8,
  `Target: aarch64-unknown-linux-gnu`)
* `gnu.org/gcc/libstdcxx` **v16.1.0** — `lib/libgcc_s.so.1`

(The `debian` VM's own outbound network to `dist.pkgx.dev` was timing out during
this session, so the three artifacts were fetched on the macOS host and copied to
the VM over the local `socket-vmnet` link. The artifact *contents* are the real
`dist.pkgx.dev` artifacts, byte-for-byte — the `llvm.org` tarball is the exact
1 016 328 920-byte object dist serves for `linux/aarch64/v22.1.8`.)

### The test program (`hello.c`)

```c
#include <stdio.h>
#include <math.h>
int main(void){ printf("hello pkgx-glibc, sqrt(2)=%f\n", sqrt(2.0)); return 0; }
```

### The clang.cfg written beside the pkgx clang

```
-B/home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44
-L/home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44
-Wl,--dynamic-linker=/home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/ld-linux-aarch64.so.1
-Wl,-rpath,/home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44
-Wl,-rpath,/home/admin/bkproto/pkgx/gnu.org/gcc/libstdcxx/v16.1.0/lib
-Wl,--disable-new-dtags
```

with `clang++.cfg`, `clang-cpp.cfg`, `clang-22.cfg` symlinked to it — exactly
the envoy pattern.

### Compile — bare `clang`, no explicit flags (the config auto-loads)

```
$ clang hello.c -lm -o hello_clang        # config auto-loaded from bin/clang.cfg
compile EXIT=0
```

### Proof — the produced binary (captured `readelf` / `file` / `ldd`)

```
$ file hello_clang
hello_clang: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
  dynamically linked,
  interpreter /home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/ld-linux-aarch64.so.1,
  for GNU/Linux 3.10.0, not stripped

$ readelf -l hello_clang | grep -A1 INTERP
  INTERP  0x00000000000002a8 ...
      [Requesting program interpreter: /home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/ld-linux-aarch64.so.1]

$ readelf -d hello_clang | grep -E 'NEEDED|RPATH|RUNPATH'
 0x000000000000000f (RPATH)   Library rpath: [/home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44:/home/admin/bkproto/pkgx/gnu.org/gcc/libstdcxx/v16.1.0/lib]
 0x0000000000000001 (NEEDED)  Shared library: [libm.so.6]
 0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]

$ ldd hello_clang
	libm.so.6 => /home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/libm.so.6
	libc.so.6 => /home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/libc.so.6
	/home/admin/bkproto/pkgx/gnu.org/glibc/v2.44.0/lib/glibc-2.44/ld-linux-aarch64.so.1 => /lib/ld-linux-aarch64.so.1

$ ./hello_clang
hello pkgx-glibc, sqrt(2)=1.414214        # run EXIT=0
```

Reading the proof:

* **`PT_INTERP` is the pkgx `ld-linux`**, not `/lib/ld-linux-aarch64.so.1`. This
  is the single decisive fact: the OS will hand this process to the **pkgx**
  loader at exec time.
* **`DT_NEEDED` (`libm.so.6`, `libc.so.6`) resolve inside the pkgx closure** —
  `ldd` shows both satisfied from `…/pkgx/gnu.org/glibc/…`, not the container's
  `/usr/lib`. (The `ld-linux → /lib/…` line in `ldd`'s output is `ldd`'s own
  cosmetic display of the interpreter name; the *requested* interpreter is the
  pkgx path, as `readelf`/`file` confirm.)
* The rpath is emitted as **`DT_RPATH`, not `DT_RUNPATH`** — the effect of
  `-Wl,--disable-new-dtags`, as designed (Hazard notes above).

### Control — same clang, config removed

Moving `clang.cfg` aside and recompiling the identical source with the identical
command reverts the interpreter to the host loader, proving the `clang.cfg` is
exactly what re-targets the toolchain:

```
$ mv bin/clang.cfg bin/clang.cfg.off && clang hello.c -lm -o hello_clang_nocfg
$ readelf -l hello_clang_nocfg | grep -A1 INTERP
      [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]     # host loader
```

### Corroboration — host `gcc` with the same explicit flags

The flags are compiler-agnostic; `clang.cfg` is only the auto-load *delivery*
vehicle. The same `-B/-L/-Wl,--dynamic-linker=/-rpath/--disable-new-dtags`
passed explicitly to the VM's host **gcc** produced an equally-retargeted binary
(`PT_INTERP` = pkgx `ld-linux`, `RPATH` into the pkgx closure, `libc.so.6`
resolving to the pkgx artifact, `./hello_pkgx` → `sqrt(2)=1.414214`, exit 0),
while a plain `gcc hello.c` control kept `/lib/ld-linux-aarch64.so.1`. This
confirms the mechanism is the *linker flags*, not anything clang-specific — so a
gcc-based build path (using a gcc **spec file** in place of `clang.cfg`) is a
viable future variant.

### What this does and does not prove

* **Proven, executed:** on aarch64 Linux, a trivial C binary compiled by the
  real pkgx clang 22.1.8 with a `clang.cfg` targeting the pkgx `gnu.org/glibc`
  artifact has its `PT_INTERP` set to the pkgx `ld-linux` and its `libc`/`libm`
  `DT_NEEDED` resolve inside the pkgx closure, and it runs. The config-file
  delivery reaches a *bare* `clang` invocation with no explicit flags (the
  property that makes it reach `configure` probes and sub-makes).
* **Not yet proven here:** the x86-64 arch (mechanically identical, only the
  loader/glibc name differs); a full autotools package with `configure` probes
  and host-tool sub-builds (the Hazard (a) `GLIBC_2.29` class); and the
  cross-arch (Target ≠ Host) libc retarget (Hazard (d)). Those are the next
  milestones before wiring `ZPKB_ZPKG_LIBC=1` into a default path.

## Experimental Go (off by default)

A first, deliberately-minimal slice of the mechanism is implemented in `bk`
behind an off-by-default switch — see `buildscript`:

* `WrapOptions.LibcZpkgx` (Go-side gate, default `false`) makes `Wrap` emit the
  clang.cfg-generation shell, itself additionally guarded at runtime by
  `if [ -n "$ZPKB_ZPKG_LIBC" ]`. With `LibcZpkgx` false the wrapper output is
  byte-identical to before, so nothing in the default build path changes.
* The emitted block is skipped for a `windows` target and for a cross-arch build
  (`Target.Arch != Host.Arch`) — Hazards (d)/(e).
* `LibcToolchain()` returns the implicit toolchain artifacts
  (`gnu.org/glibc`, `gnu.org/gcc/libstdcxx`) a caller would add to the `pkgx +…`
  closure under the switch. It is intentionally **not** yet wired into
  `build.EvalDeps`/`Runner` — this is the "sketch behind a flag", not a landed
  feature.

The remaining verification primitive the design calls for — `fixup.ReadInterp`
(assert a produced ELF's `PT_INTERP` is the pkgx loader) — is specified above
but left unimplemented pending the ELF-program-header test fixtures needed to
cover it to 100%; it is the natural next commit.
