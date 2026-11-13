package buildscript

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

// TestLibtoolToolVarsBeatTheBakedDefault is the claim itself, run rather than
// asserted: libtoolize's opening line is `: ${SED="<abs path>"}`, which assigns
// only when SED is unset. With the preamble in front of it, the baked path
// loses; without it, it wins. The second half is the control — without it this
// test would pass against a preamble that does nothing.
func TestLibtoolToolVarsBeatTheBakedDefault(t *testing.T) {
	const libtoolizeOpening = `: ${SED="/__w/_actions/pkgxdev/brewkit/v1/libexec/sed"}
: ${GREP="/bin/grep"}
: ${EGREP="/bin/grep -E"}
: ${FGREP="/bin/grep -F"}
echo "$SED|$GREP|$EGREP|$FGREP"`

	got := shOut(t, libtoolToolVars+libtoolizeOpening)
	if want := "sed|grep|grep -E|grep -F"; got != want {
		t.Fatalf("with the preamble: got %q, want %q", got, want)
	}

	// Control: the same script alone keeps the path baked at libtool's build
	// time, which is what the bottle does today.
	ctl := shOut(t, libtoolizeOpening)
	if !strings.HasPrefix(ctl, "/__w/_actions/pkgxdev/brewkit/") {
		t.Fatalf("control did not reproduce the baked default: %q", ctl)
	}
}

// TestWrapExportsLibtoolToolVars: the preamble reaches the generated script,
// ahead of the user script that runs autoreconf.
func TestWrapExportsLibtoolToolVars(t *testing.T) {
	out := Wrap(WrapOptions{
		Target:     target.Target{Platform: "linux", Arch: "x86-64"},
		Host:       target.Target{Platform: "linux", Arch: "x86-64"},
		UserScript: "autoreconf -fvi",
	})
	i := strings.Index(out, `export SED="${SED:-sed}"`)
	if i < 0 {
		t.Fatalf("the tool vars are not exported:\n%s", out)
	}
	if j := strings.Index(out, "autoreconf -fvi"); j < i {
		t.Fatal("the tool vars are exported after the user script, too late to matter")
	}
}

func shOut(t *testing.T, script string) string {
	t.Helper()
	b, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %v\n%s", err, b)
	}
	return strings.TrimSpace(string(b))
}
