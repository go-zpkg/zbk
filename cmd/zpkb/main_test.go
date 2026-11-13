package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run2(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	// run() mutates ZPKB_TARGET from --platform; clear it first so each
	// invocation is isolated from a previous call's override.
	os.Unsetenv("ZPKB_TARGET")
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestTargetCommand(t *testing.T) {
	code, out, _ := run2(t, "target")
	if code != 0 || !strings.Contains(out, "triple=") {
		t.Errorf("target: code=%d out=%q", code, out)
	}
	// with --platform override
	code, out, _ = run2(t, "--platform", "windows/x86-64", "target")
	if code != 0 || !strings.Contains(out, "windows/x86-64") || !strings.Contains(out, "x86_64-w64-mingw32") {
		t.Errorf("cross target: code=%d out=%q", code, out)
	}
}

func TestFixupCommand(t *testing.T) {
	// host-independent success: a windows target skips all relocation → exit 0
	if code, _, errs := run2(t, "--platform", "windows/x86-64", "fixup", t.TempDir()); code != 0 {
		t.Errorf("windows fixup: code=%d err=%q", code, errs)
	}
	// also the native (host-platform) path on an empty prefix
	if code, _, errs := run2(t, "fixup", t.TempDir()); code != 0 {
		t.Errorf("native fixup: code=%d err=%q", code, errs)
	}
	// missing arg
	if code, _, _ := run2(t, "fixup"); code != 2 {
		t.Errorf("fixup no-arg code=%d", code)
	}
}

func TestFixupError(t *testing.T) {
	// lib is a regular file while lib64/ exists → the linux consolidate step's
	// MkdirAll(lib) fails deterministically → run returns exit 1.
	prefix := t.TempDir()
	os.WriteFile(filepath.Join(prefix, "lib"), []byte("file"), 0o644)
	os.MkdirAll(filepath.Join(prefix, "lib64"), 0o755)
	os.WriteFile(filepath.Join(prefix, "lib64", "x.so"), []byte("x"), 0o644)
	code, _, errs := run2(t, "--platform", "linux/x86-64", "fixup", prefix)
	if code != 1 {
		t.Errorf("fixup error: code=%d err=%q", code, errs)
	}
}

func TestUsageAndErrors(t *testing.T) {
	if code, _, _ := run2(t); code != 2 {
		t.Errorf("no-args code=%d", code)
	}
	if code, _, _ := run2(t, "bogus"); code != 2 {
		t.Errorf("unknown code=%d", code)
	}
	if code, _, _ := run2(t, "-badflag"); code != 2 {
		t.Errorf("bad-flag code=%d", code)
	}
	// invalid ZPKB_TARGET → target.Resolve errors → exit 1
	if code, _, _ := run2(t, "--platform", "plan9/x86-64", "target"); code != 1 {
		t.Errorf("bad platform code=%d", code)
	}
}

func TestMainSeam(t *testing.T) {
	old := osExit
	defer func() { osExit = old }()
	got := -1
	osExit = func(c int) { got = c }
	main()
	if got < 0 {
		t.Error("main did not call osExit")
	}
}

// TestTrustEmbeddedCAs: bk's HTTPS calls must trust the embedded bundle, which
// on a FROM-scratch builder is the ONLY trust store there is.
func TestTrustEmbeddedCAs(t *testing.T) {
	oldTr, oldClient := http.DefaultTransport, http.DefaultClient.Transport
	defer func() { http.DefaultTransport, http.DefaultClient.Transport = oldTr, oldClient }()

	trustEmbeddedCAs()
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("default transport carries no trust store")
	}
	if http.DefaultClient.Transport != http.DefaultTransport {
		t.Fatal("the default client must use the same transport")
	}
	// a transport we cannot configure is left alone rather than replaced
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	trustEmbeddedCAs()
	if _, ok := http.DefaultTransport.(*http.Transport); ok {
		t.Fatal("an unknown transport must not be swapped out")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
