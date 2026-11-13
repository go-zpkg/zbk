package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ⛔⛔ THIS FILE EXISTS BECAUSE THE SAME DEFECT WAS WRITTEN TWICE IN ONE DAY,
// AND THE SWEEP THAT WAS SUPPOSED TO CATCH THE SECOND ONE CAME BACK CLEAN.
//
// A package's build probes the PATH for a program and compiles — or substitutes
// — the ABSOLUTE PATH it found. In a versioned store that path belongs to
// another package AT A VERSION, so the consumer carries a reference that goes
// stale the day the producer is rebuilt. go-zpkg/zpkb#397 is the class: "a store
// path is compiled into binaries as data … no rpath rewrite reaches it".
//
// Three occurrences are on the record:
//
//	gnu.org/diffutils  AC_PATH_PROG([PR_PROGRAM],[pr]) would have baked
//	                   coreutils' bin/pr into `diff` (pantry-overlay#92)
//	gnu.org/findutils  AC_PATH_PROG([SORT],[sort]) would have baked coreutils'
//	                   bin/sort into the installed `updatedb` (#93)
//	gnu.org/libtool    upstream's own artifact SHIPS one:
//	                   : ${SED="/__w/_actions/pkgxdev/brewkit/v1/libexec/sed"}
//	                   — three of ten recipes in one batch died on it
//
// ⛔ AND THE REASON THIS IS A TREE SCAN RATHER THAN A SOURCE SCAN. The rule
// that came out of diffutils was `grep -n AC_PATH_PROG configure.ac`, run
// before writing a recipe. On findutils that command prints NOTHING: the macro
// is in m4/nullsort.m4, reached from configure.ac by one word. The check's
// SCOPE was wrong, and a clean result from it reads exactly like an absence.
//
// A built tree cannot be wrong about its own bytes. It does not care whether
// the path arrived through AC_PATH_PROG, a hand-written default, a .pc file, a
// shebang or a config header — it is either in there or it is not. That is why
// the gate lives here and not in front of configure.ac.

// ⛔⛔ AND THE FIRST VERSION OF THIS CHECK WOULD HAVE PASSED ALL THREE OF THEM.
//
// It looked only for "another project's versioned store path", which is the
// shape the two recipes PREDICTED. Then the store on a real machine was read,
// and not one of the three measured instances has that shape:
//
//	~/.pkgx/gnu.org/diffutils/v3.12.0/bin/diff   holds  /usr/bin/pr
//	  — AC_PATH_PROG's value, the BUILD HOST's path, compiled in beside the
//	    string "pagination not supported on this host"
//	~/.pkgx/gnu.org/findutils/v4.10.0/bin/updatedb holds sort="/usr/bin/sort -z"
//	  — and `/usr/bin/sort` is not even GNU sort on a darwin builder
//	~/.pkgx/gnu.org/findutils/v4.10.0/bin/updatedb also holds
//	    : ${LOCATE_DB=/opt/gnu.org/findutils/v4.10.0+brewing/var/locate/locatedb}
//	    : ${LIBEXECDIR=/opt/gnu.org/findutils/v4.10.0+brewing/libexec}
//	    : ${BINDIR=/opt/gnu.org/findutils/v4.10.0+brewing/bin}
//	  — the STAGING tree, which does not exist after the artifact is installed,
//	    so updatedb cannot find its own frcode. go-zpkg/zpkb#152's class, in a
//	    script rather than an rpath.
//
// So the scope was drawn around the hypothesis instead of the population —
// which is the same mistake as grepping configure.ac, one level up. The three
// rules below each come from an instance that was READ, and the third is a
// CENSUS rather than a refusal because its population has not been read yet.

// storePathHit is one occurrence of a baked path inside one file.
type storePathHit struct {
	File    string // relative to the scanned root
	Project string // the project the path names, eg. "gnu.org/coreutils"
	Version string
	Path    string // the matched path, verbatim
	Offset  int64  // where in the file, so a second reader can find it
}

// bakedScan is what one tree says about itself.
type bakedScan struct {
	ByProject map[string][]storePathHit // rule A: <store>/<project>/v<ver>
	Staging   []storePathHit            // rule B: anything under a +brewing tree
	Host      map[string][]storePathHit // rule C: absolute paths outside the store, keyed by the path
	Files     int
	ExecFiles int
}

// stagingPattern recognises a staging tree, wherever it is rooted.
//
// ⛔ IT DOES NOT TAKE THE STORE ROOT, and that is the measured part: the
// staging path found in a shipped artifact is rooted at /opt, while the machine
// reading it has its store at ~/.pkgx. A rule anchored on the local store root
// would have seen nothing. `+brewing` is zpkb's own staging suffix
// (buildscript/wrapper.go:384, fixup/macho.go:591), so the string is ours to
// recognise anywhere it appears.
var stagingPattern = regexp.MustCompile(`/[A-Za-z0-9._+/-]*\+brewing(?:/[A-Za-z0-9._+-]+)*`)

// hostToolPattern recognises an absolute path that is not in the store.
//
// Deliberately narrow: the first segment must be one of the places a builder's
// own filesystem puts programs. A wider pattern matches every path in a man
// page, and a census of 500 documentation strings tells nobody anything —
// which is `a-sweep-that-measured-its-own-regex` exactly.
var hostToolPattern = regexp.MustCompile(
	`/(?:usr|opt|bin|sbin|home|Users|__w|work|tmp|private)(?:/[A-Za-z0-9._+-]+)+`)

// hostToolAllowed are the absolute paths an artifact may legitimately name.
//
// ⛔ EVERY ENTRY IS HERE FOR A STATED REASON, because an allow-list assembled
// to make a check quiet is how the check stops meaning anything.
var hostToolAllowed = map[string]bool{
	"/usr/bin/env":               true, // the portable shebang; a store path here would be WORSE
	"/bin/sh":                    true, // POSIX guarantees it, and configure bakes it on purpose
	"/usr/lib/dyld":              true, // darwin's loader, named by every Mach-O
	"/usr/lib/libSystem.B.dylib": true, // darwin's libc, which no artifact provides
}

// storePathPattern builds the regexp that recognises "<store>/<project>/v<ver>".
//
// ⛔ THE PROJECT SEGMENT IS NON-GREEDY ON PURPOSE, which was a measured choice
// rather than a stylistic one. A project name legitimately contains slashes
// (gnu.org/gcc/libstdcxx), so the segment has to span them; but greedy spanning
// resolves "<store>/foo/v1.0/libexec/v8/bin" to project "foo/v1.0/libexec" and
// version "8", because it prefers the LAST "/v<digit>". Non-greedy takes the
// first, which is the one the store layout puts there.
//
// ⛔ AND THE TRAILING PATH IS PART OF THE MATCH, which the first version of this
// got wrong and its own test caught. Stopping at the version reports "something
// in gnu.org/coreutils v9.7.0" — true, and useless: the whole finding is WHICH
// binary is referenced, because `bin/pr` and `bin/sort` are two different
// recipes' defects. The tail stops at the first byte no path can hold, which is
// the NUL after a compiled-in string and the space or quote after a shell one.
func storePathPattern(store string) *regexp.Regexp {
	store = strings.TrimRight(store, string(filepath.Separator))
	return regexp.MustCompile(
		regexp.QuoteMeta(store) +
			`/((?:[A-Za-z0-9][A-Za-z0-9._+-]*/)*?[A-Za-z0-9][A-Za-z0-9._+-]*)/v([0-9][A-Za-z0-9._-]*)` +
			`(?:/[A-Za-z0-9._+-]+)*`)
}

// chunk sizes for the streaming scan.
//
// ⛔ THE SCAN IS CHUNKED AND OVERLAPPED RATHER THAN SIZE-CAPPED, because a file
// this check could not read would have to be reported as unknown, and an
// unknown that nobody reads becomes a pass — the failure mode recorded in
// `unread-answer-reads-as-a-negative`. Overlapping means there is no file it
// cannot answer for, so the verdict has no hole to fall through.
//
// The overlap is larger than any path these filesystems can hold (PATH_MAX is
// 1024 on darwin, 4096 on linux), so a match straddling a boundary is seen
// whole in the next window; offsets dedupe the ones seen twice.
const (
	scanChunk   = 1 << 20
	scanOverlap = 1 << 12
)

// scanFile reports every match of each pattern in one file's bytes, in ONE
// pass, returning one slice of hits per pattern in the order given.
//
// ⛔ ONE PASS RATHER THAN THREE, which started as a coverage finding and is a
// correctness argument too. Opening the same file three times gave three
// identical error paths — the gate counted them and none was reachable from a
// test without three injected failures — and it also meant three reads of every
// byte of every binary in a tree. The patterns differ in what they CAPTURE, not
// in how the file is read.
//
// The store pattern carries (project, version); the staging and host patterns
// are about the path as a whole and carry neither.
func scanFile(r io.Reader, rel string, res []*regexp.Regexp) ([][]storePathHit, error) {
	hits := make([][]storePathHit, len(res))
	seen := make([]map[int64]bool, len(res))
	for i := range seen {
		seen[i] = map[int64]bool{}
	}
	var (
		buf  = make([]byte, 0, scanChunk+scanOverlap)
		base int64
	)
	window := make([]byte, scanChunk)
	for {
		n, err := io.ReadFull(r, window)
		if n > 0 {
			buf = append(buf, window[:n]...)
			for i, re := range res {
				for _, m := range re.FindAllSubmatchIndex(buf, -1) {
					off := base + int64(m[0])
					if seen[i][off] {
						continue
					}
					seen[i][off] = true
					h := storePathHit{File: rel, Path: string(buf[m[0]:m[1]]), Offset: off}
					if len(m) >= 6 && m[2] >= 0 && m[4] >= 0 {
						h.Project = string(buf[m[2]:m[3]])
						h.Version = string(buf[m[4]:m[5]])
					}
					hits[i] = append(hits[i], h)
				}
			}
			// Keep the tail as the next window's prefix.
			if len(buf) > scanOverlap {
				base += int64(len(buf) - scanOverlap)
				buf = append(buf[:0], buf[len(buf)-scanOverlap:]...)
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return hits, nil
		}
		if err != nil {
			return hits, err
		}
	}
}

// runsThings says whether a file is one something EXECUTES.
//
// Rule C is restricted to these, which is a scope choice with a cost: a baked
// host path in a .pc file or a cmake module would not be seen. It is made
// because an artifact's man pages and texinfo mention /usr/bin by the hundred,
// and a census drowned in documentation is one nobody reads. Stated here so
// the next person widens it on purpose rather than discovering the gap.
//
// ⛔ A FILE WHOSE MODE CANNOT BE READ IS NOT EXECUTABLE HERE, in one expression
// rather than an unreachable branch: WalkDir's Info() fails only when the entry
// has gone away between the walk and the question, and the walk's own error
// path is what reports that.
func runsThings(rel string, d fs.DirEntry) bool {
	switch strings.Split(filepath.ToSlash(rel), "/")[0] {
	case "bin", "sbin", "libexec":
		return true
	}
	info, err := d.Info()
	return err == nil && info.Mode().Perm()&0o111 != 0
}

// scanOneFile is the seam for the read itself.
//
// ⛔ IT EXISTS SO THE I/O FAILURE PATH CAN BE EXERCISED. Reading a regular file
// off a local disk fails about as often as the disk does, so that branch cannot
// be reached by arranging files — and an untested error path in a GATE is worse
// than elsewhere: the one case it covers is "the check could not read this",
// which must not be reported as "this is clean".
var scanOneFile = scanFile

// scanStorePaths walks a tree and answers all three rules in one pass.
//
// A file it cannot open is an ERROR, not a skip: see the chunking note.
func scanStorePaths(root, store string) (bakedScan, error) {
	res := []*regexp.Regexp{storePathPattern(store), stagingPattern, hostToolPattern}
	out := bakedScan{
		ByProject: map[string][]storePathHit{},
		Host:      map[string][]storePathHit{},
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if d.IsDir() || !d.Type().IsRegular() {
			// A symlink's TARGET is read when something follows it; its own
			// name is not file content. Dangling links are #152's business.
			return nil
		}
		rel, _ := filepath.Rel(root, p)

		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		hits, err := scanOneFile(f, rel, res)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}

		out.Files++
		for _, h := range hits[0] {
			out.ByProject[h.Project] = append(out.ByProject[h.Project], h)
		}
		out.Staging = append(out.Staging, hits[1]...)

		// Rule C's narrower scope is applied AFTER the read, not by skipping
		// the read: the file is open once for all three questions.
		if runsThings(rel, d) {
			out.ExecFiles++
			for _, h := range hits[2] {
				if hostToolAllowed[h.Path] || strings.HasPrefix(h.Path, store) {
					continue
				}
				out.Host[h.Path] = append(out.Host[h.Path], h)
			}
		}
		return nil
	})
	return out, err
}

// reportStorePaths turns the census into the verdict.
//
// `self` is the project being built: a reference to its OWN prefix is reported
// and allowed, because a package legitimately names its own libexec, its own
// data directory and its own loader. What it may not do is name another
// package's versioned path.
//
// ⛔ THE DEROGATION STAMPS. `--allow` does not silence a finding, it prints it
// as an allowed one with the project named, so a build log shows which
// exemptions were in force. A flag that removes evidence is how a gate becomes
// a formality (`turn-a-repeated-lesson-into-a-gate`).
func reportStorePaths(scan bakedScan, self string, allowed map[string]bool, censusLimit int) (string, bool) {
	byProject, files := scan.ByProject, scan.Files
	var foreign, exempt []string
	selfHits := 0
	for project, hits := range byProject {
		switch {
		case project == self:
			selfHits += len(hits)
		case allowed[project]:
			exempt = append(exempt, project)
		default:
			foreign = append(foreign, project)
		}
	}
	sort.Strings(foreign)
	sort.Strings(exempt)

	var b strings.Builder
	for _, project := range exempt {
		hits := byProject[project]
		fmt.Fprintf(&b, "⚠ ALLOWED by --allow %s: %d reference(s), eg. %s in %s\n",
			project, len(hits), hits[0].Path, hits[0].File)
	}
	// ⛔ RULE B, AND IT IS FATAL WITH NO DEROGATION. A staging tree does not
	// exist once the artifact is installed, so a reference to one is wrong in
	// every tree, for every consumer, with no case in which it is the intent.
	if len(scan.Staging) > 0 {
		sortHits(scan.Staging)
		fmt.Fprintf(&b, "bakedpaths: %d reference(s) to a +brewing STAGING tree, which does not exist once this artifact is installed — measured in gnu.org/findutils v4.10.0, whose updatedb cannot find its own frcode (go-zpkg/zpkb#152):",
			len(scan.Staging))
		for _, h := range firstFew(scan.Staging, 5) {
			fmt.Fprintf(&b, "\n      %s at +%d: %s", h.File, h.Offset, h.Path)
		}
		fmt.Fprintln(&b)
	}

	if len(foreign) > 0 {
		fmt.Fprintf(&b, "bakedpaths: %d file(s) read, and %d project(s) OTHER THAN %s have a versioned store path in this tree — each goes stale the day that project is rebuilt (go-zpkg/zpkb#397):",
			files, len(foreign), self)
		for _, project := range foreign {
			hits := byProject[project]
			sortHits(hits)
			more := ""
			if len(hits) > 3 {
				more = fmt.Sprintf(" (+%d more)", len(hits)-3)
			}
			fmt.Fprintf(&b, "\n  %s v%s — %d reference(s)%s", project, hits[0].Version, len(hits), more)
			for _, h := range firstFew(hits, 3) {
				fmt.Fprintf(&b, "\n      %s at +%d: %s", h.File, h.Offset, h.Path)
			}
		}
		fmt.Fprintln(&b)
	}

	// ⛔ RULE C IS A CENSUS, NOT A REFUSAL — ON PURPOSE AND FOR ONE TURN ONLY.
	// Two of the three measured instances are exactly this shape
	// (/usr/bin/pr in diffutils' `diff`, /usr/bin/sort in findutils'
	// `updatedb`), so it is the most valuable rule here. It is not fatal yet
	// because its POPULATION has not been read: the allow-list above holds four
	// entries chosen from one machine, and a gate built on that would fail
	// honest artifacts and be switched off within the day. Counting first, with a
	// sample printed, is how the allow-list gets written from what is there
	// rather than from what I expect (`a-sweep-that-measured-its-own-regex`).
	if len(scan.Host) > 0 {
		paths := make([]string, 0, len(scan.Host))
		for p := range scan.Host {
			paths = append(paths, p)
		}
		sort.Slice(paths, func(i, j int) bool {
			if n, m := len(scan.Host[paths[i]]), len(scan.Host[paths[j]]); n != m {
				return n > m
			}
			return paths[i] < paths[j]
		})
		fmt.Fprintf(&b, "⚠ CENSUS (not a refusal): %d distinct absolute path(s) outside the store, in %d executable file(s) — the shape of BOTH defects measured on 2026-11-09:",
			len(paths), scan.ExecFiles)
		shown := paths
		if censusLimit > 0 {
			shown = firstFewStrings(paths, censusLimit)
		}
		for _, p := range shown {
			hits := scan.Host[p]
			sortHits(hits)
			fmt.Fprintf(&b, "\n      %-48s %d× eg. %s", p, len(hits), hits[0].File)
		}
		if len(paths) > len(shown) {
			fmt.Fprintf(&b, "\n      … and %d more distinct path(s) — --census-limit 0 lists every one",
				len(paths)-len(shown))
		}
		fmt.Fprintln(&b)
	}

	if len(foreign) == 0 && len(scan.Staging) == 0 {
		fmt.Fprintf(&b, "bakedpaths: %d file(s) read, no versioned store path of another project and no staging path",
			files)
		if selfHits > 0 {
			fmt.Fprintf(&b, " (%d reference(s) to %s's own prefix, which is its to name)",
				selfHits, self)
		}
		return b.String(), true
	}
	return strings.TrimRight(b.String(), "\n"), false
}

// sortHits puts hits in file-then-offset order so a report is stable.
func sortHits(hits []storePathHit) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Offset < hits[j].Offset
	})
}

func firstFew(hits []storePathHit, n int) []storePathHit {
	if len(hits) > n {
		return hits[:n]
	}
	return hits
}

func firstFewStrings(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// runBakedPaths is `zpkb bakedpaths`.
//
// ⛔ EVERY FLAG IS REQUIRED AND NONE HAS A DEFAULT. A default store root or a
// default project is how this check would come to run against the wrong tree
// and pass: a gate whose arguments can be omitted answers a question nobody
// asked (`turn-a-repeated-lesson-into-a-gate`).
func runBakedPaths(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bakedpaths", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "the staged tree or installed prefix to read (required)")
	store := fs.String("store", "", "the store root whose <store>/<project>/v<version> layout to recognise (required)")
	project := fs.String("project", "", "the project this tree belongs to, whose own prefix is its to name (required)")
	var allow multiFlag
	fs.Var(&allow, "allow", "a project whose versioned path is accepted here; repeatable, and every use is PRINTED")
	// ⛔ THE CENSUS IS TRUNCATED FOR READING, AND THE TRUNCATION HID THE ONE
	// PATH THIS CHECK WAS BUILT FOR. gnu.org/diffutils v3.12.0 holds
	// /usr/bin/pr — read out of `strings bin/diff` — and it did not appear in
	// the first ten, which are ranked by count: the builder's own object-file
	// paths occur 147 times and the baked tool path twice. A cap that cannot be
	// lifted turns "not shown" into "not found", which is the failure recorded
	// in `unread-answer-reads-as-a-negative`.
	censusLimit := fs.Int("census-limit", 10, "how many distinct census paths to list; 0 lists every one")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	missing := []string{}
	if *dir == "" {
		missing = append(missing, "--dir")
	}
	if *store == "" {
		missing = append(missing, "--store")
	}
	if *project == "" {
		missing = append(missing, "--project")
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "bakedpaths: %s required — this check has no defaults, because a default is how it ends up answering about the wrong tree\n",
			strings.Join(missing, " and "))
		return 2
	}

	allowed := map[string]bool{}
	for _, a := range allow {
		allowed[a] = true
	}

	scan, err := scanStorePaths(*dir, *store)
	if err != nil {
		fmt.Fprintln(stderr, "bakedpaths:", err)
		return 2
	}
	report, ok := reportStorePaths(scan, *project, allowed, *censusLimit)
	fmt.Fprintln(stdout, report)
	if !ok {
		return 1
	}
	return 0
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
