package main

import (
	"strings"
	"testing"
)

// ⛔ bk COULD NOT SAY WHICH bk IT WAS. Measured 2026-10-09:
//
//	$ bk --version
//	flag provided but not defined: -version
//	$ bk version
//	unknown command: version
//
// That matters more here than in the sibling tools, because bk writes its
// own version into every lock it produces (`bk = "v0.15.0"`): "which bk
// wrote this lock" was a question only `go version -m` could answer, and
// only if you still had the binary.
func TestBothVersionSpellingsGiveTheSameAnswer(t *testing.T) {
	codeFlag, outFlag, errFlag := run2(t, "--version")
	if codeFlag != 0 {
		t.Fatalf("bk --version: code=%d err=%q", codeFlag, errFlag)
	}
	codeCmd, outCmd, errCmd := run2(t, "version")
	if codeCmd != 0 {
		t.Fatalf("bk version: code=%d err=%q", codeCmd, errCmd)
	}
	// ⛔ ONE ANSWER, TWO SPELLINGS. Two code paths that can drift apart are
	// how a tool starts reporting two versions of itself.
	if outFlag != outCmd {
		t.Errorf("the two spellings disagree:\n  --version %q\n  version   %q", outFlag, outCmd)
	}
}

// ⛔ IT PRINTS WHAT A LOCK CARRIES, byte for byte. The lock's `bk = "…"`
// field comes from bkVersion(); a prettier rendering here — stripping the
// leading "v", say — would make the two disagree, and reading a lock and
// asking "do I have that bk?" is the whole use of this command.
func TestTheVersionPrintedIsTheOneWrittenIntoLocks(t *testing.T) {
	_, out, _ := run2(t, "version")
	fields := strings.Fields(out)
	if len(fields) != 2 {
		t.Fatalf("version line is not `zpkb <version>`: %q", out)
	}
	// ⛔ `zpkb`, AND THE NAME IS PART OF THE CONTRACT. The command is `zpkb`
	// since the rename, and `bk` is now free for upstream's brewkit to sit on
	// the same PATH — the point of renaming ours. A binary that answers with
	// the other program's name undoes that. Field POSITION is unchanged, so
	// the release guard's `awk '{print $2}'` still reads the version.
	if fields[0] != "zpkb" {
		t.Errorf("the line does not name the tool: %q", out)
	}
	// THIS IS ALSO WHAT THE RELEASE GUARD EXTRACTS (awk '{print $2}') and
	// compares to the tag by equality, so the field position is part of the
	// contract and not a presentation detail.
	if fields[1] != bkVersion() {
		t.Errorf("printed %q, but a lock would say %q", fields[1], bkVersion())
	}
}

// A VERSION REQUEST IS NOT A USAGE ERROR. `bk --version` carries no
// subcommand, and the empty-args check sits right after the flag parse —
// so the order of those two is load-bearing.
func TestVersionAloneIsNotAUsageError(t *testing.T) {
	code, out, errb := run2(t, "--version")
	if code != 0 {
		t.Errorf("bk --version alone: code=%d err=%q", code, errb)
	}
	if strings.Contains(errb, "usage:") {
		t.Errorf("bk --version printed usage:\n%s", errb)
	}
	if !strings.HasPrefix(out, "zpkb ") {
		t.Errorf("nothing was printed to stdout: %q", out)
	}
	// And the usage line, when it IS shown, offers the command.
	//
	// ⛔ `strings.Contains(errb, "version")` is NOT good enough and was the
	// first spelling of this check: the usage line already lists `versions`,
	// a different subcommand, so deleting `version|` left the test green. A
	// mutation caught it. The vocabulary has to be narrow enough to tell the
	// two apart.
	_, _, errb = run2(t)
	if !strings.Contains(errb, "<version|") {
		t.Errorf("usage does not offer the version command:\n%s", errb)
	}
}
