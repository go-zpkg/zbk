package fixup

import (
	"bytes"
	"path/filepath"
	"strings"
)

// fixStagingScripts strips the +brewing staging prefix out of the scripts a
// build installs.
//
// A recipe configures with the staging prefix, so anything the build bakes into
// an installed file names a directory that CEASES TO EXIST the moment the tree
// is staged onto its final versioned prefix. Measured in the published
// registry:
//
//	openssl.org/v3.0.19/bin/c_rehash:
//	  my $dir = "…/openssl.org/v3.0.19+brewing/ssl";
//	perl.org/v5.28.0/bin/perlivp:
//	  my $perlpath = '…/perl.org/v5.28.0+brewing/bin/perl';
//
// Neither directory exists anywhere, on any machine, including the one that
// built it. Pointing them at the final prefix does not make the artifact
// relocatable — a consumer whose ZPKG_DIR differs is still out of luck, and
// only the tool itself can fix that (bison's yacc, for one, carries gnulib's
// relocatable-sh and works out its own prefix from $0) — but it turns a path
// that is wrong everywhere into one that is right wherever the artifact is
// installed under the same ZPKG_DIR, which is the case for the factory's own
// builds and for the sovereign builder.
//
// Only files beginning with `#!` are touched. Rewriting an ELF or Mach-O this
// way would corrupt it: the replacement is shorter, and every offset after it
// would shift. rpath.go and macho.go handle those, in place and at fixed width.
func fixStagingScripts(prefix, buildInstall string, log func(string, ...any)) error {
	if buildInstall == "" || buildInstall == prefix {
		return nil
	}
	for _, part := range []string{"bin", "sbin", "libexec"} {
		if err := walkScripts(filepath.Join(prefix, part), buildInstall, prefix, log); err != nil {
			return err
		}
	}
	return nil
}

// walkScripts recurses a directory rewriting the staging prefix in every file
// that opens with a shebang.
func walkScripts(dir, buildInstall, prefix string, log func(string, ...any)) error {
	if !isDir(dir) {
		return nil
	}
	ents, err := osReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := walkScripts(p, buildInstall, prefix, log); err != nil {
				return err
			}
			continue
		}
		// REGULAR files only, as walkExes next door already does.
		//
		// A symlink is not a script, and reading through one is wrong twice
		// over: a link to a script inside the prefix is rewritten anyway when
		// the walk reaches the target, and a link pointing outside is not ours
		// to rewrite.
		//
		// A DANGLING one failed the whole build. gnu.org's gcc recipe links
		// ar, nm and ranlib to `../../../binutils/v*/bin/…`, where the star is
		// ESCAPED in the recipe and is not a glob at all: pkgx writes a `v*`
		// alias beside `v<version>` when it installs a package
		// (artifact.writeVersionLinks), so the target is a real path — for a
		// ZPKG_DIR that has binutils in it. For one that does not, the link
		// dangles, and the fix-up then said
		//
		//	fix-up: open …/gnu.org/gcc/v14.4.0/bin/ar: no such file or directory
		//
		// after twenty-five minutes of compiling — naming a file the recipe
		// had created and nothing had asked to read.
		if !e.Type().IsRegular() {
			continue
		}
		b, err := osReadFile(p)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(b, []byte("#!")) || !strings.Contains(string(b), buildInstall) {
			continue
		}
		if err := rewriteFile(p, buildInstall, "", prefix, log); err != nil {
			return err
		}
	}
	return nil
}
