package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/versions"
)

// runVersions is the `bk versions --recipe <package.yml>` subcommand: it prints
// every candidate version of a recipe as one `version<TAB>tag` line, newest
// first. The factory drives this to enumerate all versions to build (see
// packages/factory.sh); `bk build --version <v>` then builds a chosen one.
func runVersions(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("versions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recipe := fs.String("recipe", "", "path to the recipe (package.hcl or package.yml; required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *recipe == "" {
		fmt.Fprintln(stderr, "usage: zpkb versions --recipe <package.hcl|package.yml>")
		return 2
	}
	// By extension. This read YAML unconditionally, so asking an HCL recipe
	// what versions it resolves failed with a yaml unmarshal error about its
	// first attribute — go-zpkg/bk#389.
	rec, err := recipefile.LoadFile(*recipe)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	vts, err := versions.List(rec.Versions)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	for _, vt := range vts {
		fmt.Fprintf(stdout, "%s\t%s\n", vt.Version, vt.Tag)
	}
	return 0
}
