// Package hcl is an HCL2 front-end for pkgx pantry recipes. A package.hcl is
// decoded into the SAME pantry.Recipe as a package.yml — via the same schema
// validation — so a recipe written either way produces an identical build.
//
// Example (equivalent to the curl.se package.yml):
//
//	distributable {
//	  url              = "https://curl.se/download/curl-{{version}}.tar.bz2"
//	  strip-components = 1
//	}
//	dependencies = { "openssl.org" = "^1.1", "zlib.net" = "^1.2.11" }
//	build {
//	  script = ["./configure $ARGS", "make --jobs {{ hw.concurrency }} install"]
//	  env    = { ARGS = ["--prefix={{prefix}}", "--with-openssl"] }
//	}
//	provides = ["bin/curl", "bin/curl-config"]
//
// Blocks express nested maps (build, test, distributable); object attributes
// express maps whose keys aren't HCL identifiers (eg. "openssl.org").
package hcl

import (
	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/pantry"
)

// Parse decodes a package.hcl into a validated pantry.Recipe.
func Parse(src []byte, filename string) (*pantry.Recipe, error) {
	r, _, err := ParseWithDoc(src, filename)
	return r, err
}

// ParseWithDoc is Parse, and also returns the document it validated — the keys
// the file states. See pantry.ParseWithDoc for why both come from one reading.
func ParseWithDoc(src []byte, filename string) (*pantry.Recipe, map[string]any, error) {
	// bottle converts HCL to the YAML the schema validates, because the CLIENT
	// has to read these files too — the overlay is fetched at install time.
	// Keeping a second converter here would be two readings of one format,
	// and the day they disagreed the factory and the installer would build
	// different things from the same recipe.
	y, err := bottle.HCLToYAML(src, filename)
	if err != nil {
		return nil, nil, err
	}
	return pantry.ParseWithDoc(y)
}

// ToMap parses package.hcl into the generic map[string]any document shape that
// a package.yml decodes to. It is bottle's reading, re-exported so a caller
// here need not know where the parser lives.
func ToMap(src []byte, filename string) (map[string]any, error) {
	return bottle.HCLToMap(src, filename)
}
