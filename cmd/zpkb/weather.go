package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/go-zpkg/bottle"
)

// defaultWeatherPlatforms are the ones the factory publishes today. Naming
// more would report every unbuilt target as a gap, which is true and useless:
// the question this answers is "did a platform LOSE something its sibling
// has", not "have we finished".
var defaultWeatherPlatforms = []string{"darwin/aarch64", "darwin/x86-64", "linux/aarch64", "linux/x86-64"}

// weatherPick is a seam: choosing a version needs the registry, and the
// reporting is the part worth testing.
var weatherPick = bottle.PickVersionForAll

// runWeather implements `bk weather`: for each project, which platforms have
// something published, and which do not.
//
// Named after `guix weather`, which answers the same question — "the fraction
// of all the packages for which substitutes are available on the server", with
// a repeatable --system — and which we did not have. That absence cost two
// silent days: the base toolchain pins gawk ~5.3, only darwin/aarch64 had a
// bottle for it, and darwin/x86-64 could not assemble a tool environment at
// all. Every build there failed naming the package being built, never the
// toolchain, until somebody happened to dispatch one.
//
// It asks PickVersionForAll, which is what the RESOLVER asks. Two proxies were
// tried first and both lied:
//
//   - counting `--<os>-<arch>` image tags: the convention is not universal,
//     and projects that install perfectly carry none. It invented eight gaps.
//   - VersionsFor: the registry's tags span platforms, so gnupg.org answers 22
//     for both arches while being installable on one. It hid the real gap.
//
// A refusal from the resolver is the fact. Anything that merely resembles the
// question measures itself.
func runWeather(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("weather", flag.ContinueOnError)
	fset.SetOutput(stderr)
	plats := fset.String("platforms", strings.Join(defaultWeatherPlatforms, ","),
		"comma-separated os/arch list to query")
	quiet := fset.Bool("quiet", false, "print only the projects with a gap")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	platforms, err := parsePlatforms(*plats)
	if err != nil {
		fmt.Fprintln(stderr, "weather:", err)
		return 2
	}
	projects, err := undeclaredProjects(fset.Args(), unresolvedStdin)
	if err != nil {
		fmt.Fprintln(stderr, "weather:", err)
		return 1
	}
	if len(projects) == 0 {
		fmt.Fprintln(stderr, "weather: no projects (name them, or pipe them in)")
		return 2
	}

	gaps, skews := 0, 0
	for _, spec := range projects {
		project, cons := splitConstraint(spec)
		var cells []string
		got := map[string][]bool{}
		picked := map[string][]string{}
		for _, pl := range platforms {
			v, err := weatherPick(project, cons, pl.os, pl.arch)
			key := pl.os + "/" + pl.arch
			if err != nil {
				cells = append(cells, key+"=none")
				got[pl.os] = append(got[pl.os], false)
				continue
			}
			cells = append(cells, key+"="+v.Raw)
			got[pl.os] = append(got[pl.os], true)
			picked[pl.os] = append(picked[pl.os], v.Raw)
		}
		mark := ""
		switch {
		case asymmetric(got):
			mark = "   <- ASYMMETRIC"
			gaps++
		case skewed(picked):
			mark = "   <- SKEW"
			skews++
		}
		if mark != "" || !*quiet {
			fmt.Fprintf(stdout, "%-36s %s%s\n", spec, strings.Join(cells, "  "), mark)
		}
	}
	fmt.Fprintf(stdout, "\n%d project(s), %d asymmetric within an OS, %d version-skewed\n",
		len(projects), gaps, skews)
	// Only an asymmetry fails. A skew is a weaker finding and this exit status
	// already gates things; making it fail on the weaker one too would turn a
	// report into a refusal for callers that never asked for the stricter test.
	if gaps > 0 {
		return 1
	}
	return 0
}

// skewed reports whether the architectures of one OS that DO have the project
// resolved to different versions.
//
// asymmetric works on presence, so it cannot see this, and the blind spot is
// the gawk failure one level down. gnupg.org/gpgme resolves on both darwin
// arches -- 2.2.0 on aarch64, 2.1.2 on x86-64 -- and the report said "0
// asymmetric". Ask the same pair for `@^2.2` and one of them answers none.
//
// So a skew is a bottle that exists for one architecture and not its sibling,
// seen from the side where the older one still satisfies an open constraint.
// It is weaker than an asymmetry -- everything installable stays installable
// -- and it is the state an asymmetry passes through, which is the useful
// moment to see it.
//
// Versions are compared as the registry spells them, not parsed: two spellings
// of one version would be a different defect, and calling them equal here
// would hide it.
func skewed(byOS map[string][]string) bool {
	for _, vs := range byOS {
		for _, v := range vs[1:] {
			if v != vs[0] {
				return true
			}
		}
	}
	return false
}

// asymmetric reports whether some architecture of an OS has the project and
// another does not.
//
// WITHIN an OS, deliberately. gnu.org/glibc is absent from darwin because
// darwin has Apple's libc, and kernel.org/linux-headers for the same reason;
// counting those would bury the one finding that matters under three that
// cannot be otherwise. The first run of this said "4 gaps" and every one of
// them was a category error.
func asymmetric(byOS map[string][]bool) bool {
	for _, have := range byOS {
		yes, no := false, false
		for _, h := range have {
			if h {
				yes = true
			} else {
				no = true
			}
		}
		if yes && no {
			return true
		}
	}
	return false
}

type platform struct{ os, arch string }

// parsePlatforms reads "darwin/aarch64,linux/x86-64". A platform with no slash
// is refused rather than guessed at: "linux" is not a platform, and answering
// for some default architecture would be a different question quietly.
func parsePlatforms(s string) ([]platform, error) {
	var out []platform
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		o, a, ok := strings.Cut(p, "/")
		if !ok || o == "" || a == "" {
			return nil, fmt.Errorf("%q is not an os/arch platform", p)
		}
		out = append(out, platform{o, a})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no platforms")
	}
	return out, nil
}

// splitConstraint reads "perl.org@~5.44", so builder/toolchain.txt and a
// BaseToolchain listing feed this unchanged.
//
// "Is anything published" and "is the PINNED constraint satisfiable" are
// different questions, and the second is the one that killed the x86-64 lane:
// gawk had a 5.4.1 bottle for both arches while the toolchain pins ~5.3, which
// existed for one.
func splitConstraint(spec string) (string, []string) {
	if i := strings.Index(spec, "@"); i > 0 {
		return spec[:i], []string{spec[i+1:]}
	}
	return spec, nil
}
