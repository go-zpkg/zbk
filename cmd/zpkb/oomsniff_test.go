package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOOMSnifferSpansAWriteBoundary. The output of a build arrives in whatever
// chunks the pipe delivers, and a signature split across two of them is
// precisely the one a detector like this exists for — a single-Write test
// would pass while the real case slipped through.
func TestOOMSnifferSpansAWriteBoundary(t *testing.T) {
	line := "c++: fatal error: Killed signal terminated program cc1plus\n"
	for cut := 0; cut <= len(line); cut++ {
		var buf bytes.Buffer
		s := &oomSniffer{w: &buf}
		if _, err := s.Write([]byte(line[:cut])); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write([]byte(line[cut:])); err != nil {
			t.Fatal(err)
		}
		if !s.seen {
			t.Fatalf("cut at %d: missed the signature", cut)
		}
		// And every byte still reaches the writer, in order: this sits in
		// front of a build log people read.
		if buf.String() != line {
			t.Fatalf("cut at %d: output = %q", cut, buf.String())
		}
	}
}

// A long innocent build must not accumulate its whole output in the carried
// tail, and must not report an OOM.
func TestOOMSnifferOnAnInnocentBuild(t *testing.T) {
	var buf bytes.Buffer
	s := &oomSniffer{w: &buf}
	for i := 0; i < 500; i++ {
		if _, err := s.Write([]byte("[1/7967] Building CXX object Killed.cpp.o\n")); err != nil {
			t.Fatal(err)
		}
	}
	if s.seen {
		t.Error("a file called Killed.cpp is not an OOM kill")
	}
	if len(s.tail) > maxSignature {
		t.Errorf("tail grew to %d bytes", len(s.tail))
	}
	if buf.Len() != 500*len("[1/7967] Building CXX object Killed.cpp.o\n") {
		t.Errorf("bytes were lost: %d", buf.Len())
	}
}

// TestRunBashToNamesAnOOMKill, end to end through the real script runner: a
// script that prints the driver's line and then fails must say what happened.
// Without this it is "exit status 1", which is what llvm.org 23.1.2 reported
// after 1h43 on the s390x seed, and the cause was six thousand lines up.
func TestRunBashToNamesAnOOMKill(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "b.sh")

	// Killed, then a failure. Both are needed: the diagnosis is attached to a
	// FAILURE, never to a build that went on to succeed.
	if err := os.WriteFile(script, []byte(
		"echo 'c++: fatal error: Killed signal terminated program cc1plus'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runBashTo(&out, &out)(script, os.Environ())
	if err == nil || !strings.Contains(err.Error(), "OUT OF MEMORY") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), "cc1plus") {
		t.Errorf("the line must still reach the log: %q", out.String())
	}

	// Separate streams: the signature on stderr alone is still found.
	if err := os.WriteFile(script, []byte(
		"echo 'virtual memory exhausted: Cannot allocate memory' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var o, e bytes.Buffer
	if err := runBashTo(&o, &e)(script, os.Environ()); err == nil || !strings.Contains(err.Error(), "OUT OF MEMORY") {
		t.Fatalf("err = %v", err)
	}

	// An ordinary failure keeps its ordinary message. A diagnosis attached to
	// everything is read as noise and then ignored on the one that matters.
	if err := os.WriteFile(script, []byte("echo no such file >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.Reset()
	e.Reset()
	if err := runBashTo(&o, &e)(script, os.Environ()); err == nil || strings.Contains(err.Error(), "OUT OF MEMORY") {
		t.Fatalf("err = %v", err)
	}

	// And a build that PRINTS the line and then succeeds is not a failure.
	if err := os.WriteFile(script, []byte(
		"echo 'c++: fatal error: Killed signal terminated program cc1plus'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	o.Reset()
	if err := runBashTo(&o, &o)(script, os.Environ()); err != nil {
		t.Errorf("err = %v", err)
	}
}

// A cancelled build is not an out-of-memory build. ninja prints "interrupted
// by user" on SIGINT and on a workflow cancellation — which is how the s390x
// run before this work ended — and a signature that fired on it would turn
// every cancellation into a memory diagnosis.
func TestOOMSnifferIgnoresACancellation(t *testing.T) {
	for _, line := range []string{
		"ninja: build stopped: interrupted by user.\n",
		"ninja: build stopped: subcommand failed.\n",
		"##[error]The operation was canceled.\n",
	} {
		var buf bytes.Buffer
		s := &oomSniffer{w: &buf}
		if _, err := s.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		if s.seen {
			t.Errorf("%q must not read as an OOM kill", line)
		}
	}
}
