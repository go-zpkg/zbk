package main

import (
	"flag"
	"fmt"
	"io"
	"sort"

	"github.com/go-zpkg/zpkb/artifactpkg"
)

// runReproduce implements `zpkb reproduce`: are two artifacts the same artifact,
// and if not, in what way.
//
// ⛔⛔ THE FACTORY HAS NEVER HAD A STANDING ANSWER TO THIS, AND THE ONE TIME
// IT WAS ASKED BY HAND IT FOUND A DEFECT. On 2026-09-29 zlib.net 1.3.2 was
// built on the s390x seed VM before and after the VM was replaced:
//
//	every FILE byte-identical, 14 entries either side
//	directories   0755 → 0775      the two hosts' umasks, 0022 and 0002
//
// artifactpkg.normalise fixes that class now, citing reproducible-builds.org.
// But a class of defect that is only ever found by hand is a class that comes
// back, and "the digests differ" is not a finding — it is the start of an
// afternoon with two tarballs. This reports WHICH entry and HOW.
//
// ⛔ IT DOES NOT BUILD ANYTHING, AND THAT IS DELIBERATE. Driving two
// sovereign builds belongs in a workflow with a runner and an hour; the
// comparison is the part with a verdict in it, and it is useful on its own
// the moment anyone has two artifacts — a rebuild against a published one, one
// architecture's build against another's, before and after a toolchain bump.
// Shipping the verdict first means the workflow has something to call.
//
// ⛔ TWO QUESTIONS, NAMED SEPARATELY. artifactpkg does NOT fix mtime to an
// epoch: an artifact's timestamps say when it was made, which that package
// documents as a policy choice rather than an oversight. So two builds an
// hour apart differ BY DESIGN, and `-ignore-mtime` asks the other question —
// "identical apart from timestamps" — instead of quietly relaxing the first.
// A reader of the output can always tell which was asked, because the summary
// says so.
func runReproduce(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reproduce", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ignoreMTime := fs.Bool("ignore-mtime", false,
		"ask whether the artifacts are identical APART FROM timestamps. artifactpkg does not fix mtime to an epoch, so two builds at different times differ by design; this is a different question from bit-identity, not a looser one")
	quiet := fs.Bool("quiet", false, "print the summary only, not every difference")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: zpkb reproduce [-ignore-mtime] [-quiet] <artifact-a> <artifact-b>")
		fmt.Fprintln(stderr, "  Each is an artifact tarball (.tar.gz or .tar — the envelope is sniffed, not")
		fmt.Fprintln(stderr, "  assumed from the name), so a rebuild can be compared against a published one.")
		return 2
	}
	a, b := fs.Arg(0), fs.Arg(1)

	rep, err := artifactpkg.Compare(a, b)
	if err != nil {
		// ⛔ AN UNREADABLE ARCHIVE IS AN ERROR, NEVER "no differences". The
		// two must not reach a reader looking the same, which is the whole
		// lesson of a sweep that could not read and reported zero.
		fmt.Fprintf(stderr, "zpkb reproduce: %v\n", err)
		return 1
	}

	asked := rep
	question := "bit-identical"
	if *ignoreMTime {
		asked = rep.WithoutMTime()
		question = "identical apart from timestamps"
	}

	if !*quiet {
		for _, d := range asked.Diffs {
			fmt.Fprintln(stdout, d)
		}
	}

	// The denominator, always. A comparison of two empty archives finds no
	// differences and proves nothing; printing the count is what lets a
	// reader tell that apart from a clean result.
	fmt.Fprintf(stdout, "\n%d entries compared · %d difference(s) · question: %s\n",
		rep.Entries, len(asked.Diffs), question)
	if c := asked.Classes(); len(c) > 0 {
		kinds := make([]string, 0, len(c))
		for k := range c {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			fmt.Fprintf(stdout, "  %-10s %d\n", k, c[k])
		}
	}
	// And when timestamps were set aside, say how many were set aside. A
	// verdict that hid them would be the relaxed check this flag exists not
	// to be.
	if *ignoreMTime {
		if n := rep.Classes()["mtime"]; n > 0 {
			fmt.Fprintf(stdout, "  (%d mtime difference(s) set aside by -ignore-mtime)\n", n)
		}
	}

	if rep.Entries == 0 {
		fmt.Fprintln(stderr, "zpkb reproduce: the first artifact holds no entries — this comparison proves nothing")
		return 1
	}
	// ⛔ EVERY ENTRY MISSING ON BOTH SIDES MEANS THE PATHS DISAGREE, NOT THAT
	// THE BUILD IS UNREPRODUCIBLE. An artifact's paths carry the version —
	// `zlib.net/v1.3.1/…` against `zlib.net/v1.3.2/…` — so comparing two
	// VERSIONS yields nothing but only-in-a and only-in-b, a report that is
	// technically true and completely uninformative. Measured on the real
	// published artifacts: 14 entries, 28 differences, all of them that.
	cls := asked.Classes()
	if cls["only-in-a"] == rep.Entries && cls["only-in-b"] == rep.Entries {
		fmt.Fprintln(stderr, "zpkb reproduce: the two artifacts share no entry path at all — they are")
		fmt.Fprintln(stderr, "  almost certainly different projects or versions. Reproducibility is a")
		fmt.Fprintln(stderr, "  question about two builds of the SAME version.")
		return 1
	}
	if len(asked.Diffs) > 0 {
		return 1
	}
	fmt.Fprintf(stdout, "the two artifacts are %s\n", question)
	return 0
}
