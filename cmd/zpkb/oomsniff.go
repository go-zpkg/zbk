package main

import (
	"io"
	"strings"
)

// oomSignatures are what a kernel OOM kill LOOKS like by the time it reaches
// bk. It never arrives as a signal: the compiler driver reaps its own cc1plus,
// prints one line and exits 1, so `cmd.ProcessState` says status 1 and nothing
// distinguishes it from a syntax error. The only witness is the text.
//
// Measured 2026-09-28 on the s390x seed. llvm.org 23.1.2 died after 1h43 at
// object 3880 of 7967, and bk said:
//
//	❌ BUILD FAIL llvm.org 23.1.2: run: exit status 1
//
// The cause was six thousand lines up, in a line nobody was looking for:
//
//	c++: fatal error: Killed signal terminated program cc1plus
//
// The difference matters because the two failures have opposite remedies. A
// recipe defect is fixed in the recipe; this one is fixed by giving the
// machine swap or fewer parallel jobs, and the recipe is innocent. Three
// people-hours here went into reading a recipe that was fine.
var oomSignatures = []string{
	"Killed signal terminated program", // the gcc and clang drivers
	"cc1plus: out of memory",
	"virtual memory exhausted",    // gcc's own allocator giving up first
	"ld terminated with signal 9", // collect2, for the linker
}

// NOT in the list: "ninja: build stopped: interrupted by user". It reads like
// a kill and it is not one — ninja prints it on SIGINT and on a workflow
// CANCELLATION, which is how the run before this one ended. A signature that
// fires on a cancellation turns every cancelled build into a memory diagnosis,
// and a diagnosis that is sometimes invented is worth less than none.
// The line ninja prints when a child dies is "subcommand failed", which says
// nothing about why and is already covered by the driver's own line.

// oomSniffer passes bytes through untouched and remembers whether any
// signature went past. It carries a TAIL between writes, because a build's
// output arrives in whatever chunks the pipe delivers and a signature split
// across two of them is the one that would be missed — which is exactly the
// case a detector like this exists for.
type oomSniffer struct {
	w    io.Writer
	tail string
	seen bool
}

// maxSignature bounds the carried tail. Anything shorter than the longest
// signature cannot span a boundary undetected.
const maxSignature = 64

func (s *oomSniffer) Write(p []byte) (int, error) {
	if !s.seen {
		hay := s.tail + string(p)
		for _, sig := range oomSignatures {
			if strings.Contains(hay, sig) {
				s.seen = true
				break
			}
		}
		if n := len(hay); n > maxSignature {
			s.tail = hay[n-maxSignature:]
		} else {
			s.tail = hay
		}
	}
	return s.w.Write(p)
}
