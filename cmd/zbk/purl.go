package main

import "strings"

// ⛔⛔ THE PURL TYPE IS `generic`, AND `pkgx` WAS A NAMESPACE NOBODY OWNS.
//
// `oci.go:47-59` in go-zpkg/bottle already ruled this question for media
// types — *"`vnd.pkgx.*` WAS A VENDOR NAMESPACE WE DO NOT OWN, FOR A FORMAT
// ITS OWNER DOES NOT DEFINE"* — and moved them to `vnd.go-zpkg.*`. The purl
// was left behind (go-zpkg/bottle#221), so every signature payload, SBOM
// component, VEX statement and provenance material still named pkgx's
// ecosystem for packages this project is not compatible with.
//
// `pkgx` is not a registered purl type. Neither is `zpkg`, and neither is
// `go-zpkg` — so swapping one unregistered namespace for another would have
// reproduced the defect one name over. `generic` IS registered, and the purl
// specification defines it for exactly this case: a package that is not in an
// ecosystem a database indexes.
//
// ⛔ IT IS NOT A FUNCTIONAL LOSS, because there was no function to lose.
// Measured 2026-10-11 and recorded in versions/identity.go: *"`pkg:pkgx/
// openssl.org@4.0.2` is known to NO database — OSV answers `{}` to a
// `pkg:generic/...` purl"*. BOTH answer nothing. The key a database will
// accept is derived separately by [versions.Identity] from what the recipe
// names — a GitHub repository, an npm or crates.io package — which is what
// `zbk vulnid` queries with. A bottle's own purl is an identity LABEL, and
// the only question about a label is whether it claims something untrue.
const purlType = "generic"

// legacyPurlPrefix is what every bottle published before this change carries.
//
// ⛔ IT IS READ AND NEVER WRITTEN. The read path must accept it or `zbk
// buildenv` cannot answer about a single published bottle; the mint path must
// not, or the two spellings would both be current and the change would never
// finish.
const legacyPurlPrefix = "pkg:pkgx/"

// purlPrefix is the prefix of a purl this command mints today.
const purlPrefix = "pkg:" + purlType + "/"

// purlFor renders the identity of one project at one version.
//
// A project name is a path (`gnu.org/bash`), which the purl specification
// allows: everything before the last segment is the namespace. It is passed
// through rather than escaped per-segment because that is what the four call
// sites did before this function existed, and changing the encoding and the
// type in one commit would make a verifier's disagreement unattributable.
func purlFor(project, version string) string {
	return purlPrefix + project + "@" + version
}

// cutPurl splits a purl this command may READ into its project and version,
// accepting the retired spelling as well as the current one.
//
// ⛔ THE LAST "@" IS THE SEPARATOR, not the first: a project name is a path
// and may itself hold one, while a version never does. Cutting at the first
// would split `pkg:generic/x@1@2` in the wrong place and would silently
// shorten a project whose name contained one. This rule came from the code it
// replaces and is kept deliberately.
func cutPurl(uri string) (project, version string, ok bool) {
	rest := ""
	switch {
	case strings.HasPrefix(uri, purlPrefix):
		rest = strings.TrimPrefix(uri, purlPrefix)
	case strings.HasPrefix(uri, legacyPurlPrefix):
		rest = strings.TrimPrefix(uri, legacyPurlPrefix)
	default:
		return "", "", false
	}
	i := strings.LastIndex(rest, "@")
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}
