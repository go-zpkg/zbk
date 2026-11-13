package build

import (
	"log"
	"os"
	"time"

	"github.com/go-zpkg/zpkb/buildscript"
)

// logf is a seam over log.Printf so Build's mirror-fallback notice is emitted
// through a single, silenceable sink (tests swap it to capture / mute output).
var logf = log.Printf

// osChtimes is a seam so TouchAutotools' error branch is testable.
var osChtimes = func(name string, atime, mtime time.Time) error {
	return os.Chtimes(name, atime, mtime)
}

// Injectable os seams for the Runner's glue, so every error branch is testable.
var (
	osRemoveAll = os.RemoveAll
	osMkdirAll  = os.MkdirAll
	osWriteFile = os.WriteFile
	osRename    = os.Rename
	osStat      = os.Stat
	osReadDir   = os.ReadDir
	osReadFile  = os.ReadFile
)

// copyProps is a seam over copyPropsTree so Build's copy-error branch is
// testable without a real filesystem failure.
var copyProps = copyPropsTree

// writeLibexec is a seam over buildscript.WriteLibexec so Build's shim-write
// error branch is testable.
var writeLibexec = buildscript.WriteLibexecFor
