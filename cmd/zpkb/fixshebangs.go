package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// shebangSpace is the whitespace cutset used to locate the interpreter token,
// matching the POSIX `[[:space:]]` class the upstream shim's sed relied on.
const shebangSpace = " \t\n\v\f\r"

// os seams so fixShebangs' read/write error branches are testable.
var (
	fsStat      = os.Stat
	fsReadFile  = os.ReadFile
	fsWriteFile = os.WriteFile
)

// fixShebangs is a pure-Go, dependency-free port of pkgx brewkit's
// libexec/fix-shebangs.ts. It is bk's multi-call helper dispatched when the
// binary is invoked under the name "fix-shebangs.ts". Recipes exec it by
// filename to make installed scripts' shebangs relocatable: for each file
// argument it rewrites a `#!<abs-interpreter> [args]` line into the relocatable
// form `#!/usr/bin/env <interpreter-basename>` so the built artifact does not
// bake in the absolute path of a build-time toolchain prefix.
//
// It faithfully matches the upstream behaviour:
//   - arguments that are not regular files (missing paths included) are skipped;
//   - files that do not begin with the bytes `#!` (binaries/ELF, data, empty)
//     are skipped;
//   - an already-relocatable shebang (`/usr/bin/env` or `/bin/sh`) is left
//     untouched;
//   - the interpreter MUST be an absolute path — a malformed shebang is a hard
//     error (non-zero exit + message), matching upstream's thrown exception;
//   - only the interpreter's basename is kept — any interpreter arguments on the
//     shebang line are dropped, exactly as upstream does;
//   - the rest of the file and the file's permission bits are preserved.
func fixShebangs(args []string, stderr io.Writer) int {
	for _, path := range args {
		fi, err := fsStat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue // skip missing paths and non-regular files
		}
		data, err := fsReadFile(path)
		if err != nil {
			continue
		}
		// only `#!` scripts are candidates; binaries (ELF starts with 0x7f 'E'),
		// data and empty/short files fall through untouched.
		if len(data) < 2 || data[0] != '#' || data[1] != '!' {
			continue
		}

		// split off the first line (without its trailing newline) from the rest.
		line0, rest := data, []byte(nil)
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line0, rest = data[:i], data[i+1:]
		}

		// the interpreter is the first non-whitespace token after `#!`.
		token := strings.TrimLeft(string(line0[2:]), shebangSpace)
		if i := strings.IndexAny(token, shebangSpace); i >= 0 {
			token = token[:i]
		}

		// the interpreter must be an absolute path (upstream's regex requires a
		// leading `/`); a malformed shebang is a hard error.
		if !strings.HasPrefix(token, "/") {
			fmt.Fprintf(stderr, "fix-shebangs.ts: cannot parse shebang in %s: %s\n", path, line0)
			return 1
		}
		// already-relocatable shebangs are acceptable as-is.
		if token == "/usr/bin/env" || token == "/bin/sh" {
			continue
		}

		mode := fi.Mode().Perm()
		_ = os.Chmod(path, mode|0o200) // ensure writable, matching `chmod u+w`

		var buf bytes.Buffer
		buf.WriteString("#!/usr/bin/env ")
		buf.WriteString(filepath.Base(token))
		buf.WriteByte('\n')
		buf.Write(rest)
		if err := fsWriteFile(path, buf.Bytes(), mode); err != nil {
			fmt.Fprintf(stderr, "fix-shebangs.ts: %s: %v\n", path, err)
			return 1
		}
	}
	return 0
}
