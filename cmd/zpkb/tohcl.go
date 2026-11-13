package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-zpkg/zpkb/pantry/hcl"
	"github.com/go-zpkg/zpkb/recipefile"
)

// Seams for the two failure paths a filesystem owns. The write and the remove
// are ordered on purpose — the hcl lands before the yaml goes, so a recipe
// directory is never left with neither — and an ordering is only worth having
// if both halves can be shown to fail safely.
var (
	toHCLWriteFile = os.WriteFile
	toHCLRemove    = os.Remove
)

// runToHCL implements `bk tohcl`: convert package.yml recipes to package.hcl.
//
// It never writes text it has not read back. hcl.Convert parses what it
// produced and compares the RECIPE against the one the YAML gives, so a
// conversion that changed anything is a refusal rather than a file.
//
// That matters more than it sounds. HCL reads `${…}` as an interpolation and
// recipe scripts are full of shell expansions; a renderer that forgot to
// double the sigil would either fail to parse or quietly evaluate part of a
// build script. The check is what makes a 183-file migration something other
// than an act of faith.
func runToHCL(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("tohcl", flag.ContinueOnError)
	fset.SetOutput(stderr)
	write := fset.Bool("write", false, "write package.hcl beside each package.yml and remove the yaml, instead of printing")
	dir := fset.String("dir", "", "convert every recipe under this pantry checkout, instead of the files named")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	paths := fset.Args()
	if *dir != "" {
		paths = ymlUnder(*dir)
	}
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "tohcl: name some package.yml files, or pass --dir")
		return 2
	}

	ok, refused := 0, 0
	for _, p := range paths {
		src, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "tohcl: %s: %v\n", p, err)
			refused++
			continue
		}
		out, err := hcl.Convert(src)
		if err != nil {
			// Named, not counted silently: a refusal is the tool working, and
			// which recipe it refused is the whole information.
			fmt.Fprintf(stderr, "tohcl: %s: %v\n", p, err)
			refused++
			continue
		}
		ok++
		if !*write {
			fmt.Fprintf(stdout, "# %s\n%s\n", p, out)
			continue
		}
		dst := filepath.Join(filepath.Dir(p), "package.hcl")
		if err := toHCLWriteFile(dst, out, 0o644); err != nil {
			fmt.Fprintf(stderr, "tohcl: %s: %v\n", dst, err)
			refused++
			continue
		}
		// The yaml goes only after the hcl is on disk: a recipe directory with
		// neither file is a project that has vanished.
		if err := toHCLRemove(p); err != nil {
			fmt.Fprintf(stderr, "tohcl: %s: %v\n", p, err)
			refused++
		}
	}
	fmt.Fprintf(stdout, "\n%d converted, %d refused\n", ok, refused)
	if refused > 0 {
		return 1
	}
	return 0
}

// ymlUnder finds every package.yml in a pantry checkout. Only the yaml: a
// package.hcl is already converted, and re-emitting it would be a no-op at
// best.
func ymlUnder(dir string) []string {
	var out []string
	_ = filepathWalkDir(filepath.Join(dir, "projects"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "package.yml" && recipefile.IsRecipe(d.Name()) {
			out = append(out, p)
		}
		return nil
	})
	return out
}
