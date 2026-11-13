package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// provenanceRef builds an in-toto referrer naming the given sources.
func provenanceRef(t *testing.T, uris, digests []string) artifact.Referrer {
	t.Helper()
	var deps []string
	for i := range uris {
		d := ""
		if digests[i] != "" {
			d = `,"digest":{"sha256":"` + digests[i] + `"}`
		}
		deps = append(deps, `{"uri":"`+uris[i]+`"`+d+`}`)
	}
	body := `{"predicate":{"buildDefinition":{"resolvedDependencies":[` + strings.Join(deps, ",") + `]}}}`
	return artifact.Referrer{ArtifactType: artifactInToto, Blob: []byte(body)}
}

func TestSourcesAttestedBy(t *testing.T) {
	t.Run("reads the uri and the digest", func(t *testing.T) {
		got, err := sourcesAttestedBy([]artifact.Referrer{
			{ArtifactType: artifactCycloneDX, Blob: []byte(`{}`)},
			provenanceRef(t, []string{"https://x/a.tar.gz"}, []string{"abc"}),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].URI != "https://x/a.tar.gz" || got[0].SHA256 != "abc" {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("an artifact with no provenance says so", func(t *testing.T) {
		_, err := sourcesAttestedBy([]artifact.Referrer{{ArtifactType: artifactCycloneDX, Blob: []byte(`{}`)}})
		if err == nil || !strings.Contains(err.Error(), "no provenance") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("provenance that is not JSON says so", func(t *testing.T) {
		_, err := sourcesAttestedBy([]artifact.Referrer{{ArtifactType: artifactInToto, Blob: []byte(`{`)}})
		if err == nil || !strings.Contains(err.Error(), "provenance:") {
			t.Fatalf("err = %v", err)
		}
	})
	// A git-built recipe attests a COMMIT, not an archive digest: there is
	// nothing content-addressed to fetch and the message must say which it is.
	t.Run("a source with no sha256 is not fetchable", func(t *testing.T) {
		_, err := sourcesAttestedBy([]artifact.Referrer{
			provenanceRef(t, []string{"git+https://x/r"}, []string{""}),
		})
		if err == nil || !strings.Contains(err.Error(), "no source archive digest") {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestSourceOutputName: the name is a convenience, the digest is the identity.
// A URI is attacker-adjacent data even when signed — the signature says the
// builder saw it, not that it is safe to use as a path.
func TestSourceOutputName(t *testing.T) {
	for _, tc := range []struct{ uri, want string }{
		{"https://x/y/yajl-2.1.0.tar.gz", "yajl-2.1.0.tar.gz"},
		// the HOST is not a filename: path.Base of the whole URI would say "x"
		{"https://x/", "DIG"},
		{"", "DIG"},
		// a query is not part of the name
		{"https://x/a.tar.gz?token=secret", "a.tar.gz"},
		// path.Base yields ONE segment, so no amount of ../ escapes the directory
		{"https://x/../../etc/passwd", "passwd"},
		{"https://x/a/..", "DIG"},
		{"://not a url", "DIG"},
	} {
		if got := sourceOutputName(attestedSource{URI: tc.uri, SHA256: "DIG"}); got != tc.want {
			t.Errorf("%q -> %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// withSourceSeams points the command at canned attestations and bytes.
func withSourceSeams(t *testing.T, refs []artifact.Referrer, refErr error, data []byte, pullErr error) {
	t.Helper()
	a, p := sourceAttestations, sourcePuller
	t.Cleanup(func() { sourceAttestations, sourcePuller = a, p })
	sourceAttestations = func(_, _, _, _, _ string) ([]artifact.Referrer, error) { return refs, refErr }
	sourcePuller = func(_, _ string) ([]byte, error) { return data, pullErr }
}

func runSourceIn(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(wd) })
	var out, errb bytes.Buffer
	return runSource(args, &out, &errb), out.String(), errb.String()
}

func TestRunSourceFetchesWhatTheArtifactAttests(t *testing.T) {
	dir := t.TempDir()
	withSourceSeams(t, []artifact.Referrer{
		provenanceRef(t, []string{"https://x/yajl-2.1.0.tar.gz"}, []string{"deadbeef"}),
	}, nil, []byte("SOURCE BYTES"), nil)

	code, out, errs := runSourceIn(t, dir, "lloyd.github.io/yajl", "2.1.0")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, errs)
	}
	if !strings.Contains(out, "yajl-2.1.0.tar.gz  deadbeef  (12 bytes)") {
		t.Fatalf("stdout = %q", out)
	}
	b, err := os.ReadFile(filepath.Join(dir, "yajl-2.1.0.tar.gz"))
	if err != nil || string(b) != "SOURCE BYTES" {
		t.Fatalf("file = %q, err = %v", b, err)
	}
}

func TestRunSourcePrintsWithoutFetching(t *testing.T) {
	dir := t.TempDir()
	pulled := false
	withSourceSeams(t, []artifact.Referrer{
		provenanceRef(t, []string{"https://x/a.tar.gz"}, []string{"abc"}),
	}, nil, nil, nil)
	old := sourcePuller
	sourcePuller = func(_, _ string) ([]byte, error) { pulled = true; return nil, nil }
	t.Cleanup(func() { sourcePuller = old })

	code, out, _ := runSourceIn(t, dir, "--print", "p", "1")
	if code != 0 || out != "abc  https://x/a.tar.gz\n" {
		t.Fatalf("code = %d, out = %q", code, out)
	}
	if pulled {
		t.Error("--print fetched")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("--print wrote %v", ents)
	}
}

// TestRunSourceSaysTheMirrorNeverSawIt: the distinction that matters. The
// artifact is fine; the mirror simply predates it. Fetching the URI instead
// would be a DIFFERENT artefact unless it still hashes right.
func TestRunSourceSaysTheMirrorNeverSawIt(t *testing.T) {
	dir := t.TempDir()
	withSourceSeams(t, []artifact.Referrer{
		provenanceRef(t, []string{"https://x/a.tar.gz"}, []string{"abc"}),
	}, nil, nil, artifact.ErrSourceAbsent)

	code, _, errs := runSourceIn(t, dir, "p", "1")
	if code != 1 || !strings.Contains(errs, "the mirror does not hold abc") {
		t.Fatalf("code = %d, stderr = %q", code, errs)
	}
}

func TestRunSourceSurfacesEveryOtherFailure(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		args []string
		set  func(t *testing.T)
		code int
		want string
	}{
		{"no arguments", nil, func(t *testing.T) {}, 2, "usage: bk source"},
		{"one argument", []string{"p"}, func(t *testing.T) {}, 2, "usage: bk source"},
		{"unknown flag", []string{"--nope"}, func(t *testing.T) {}, 2, "flag provided but not defined"},
		{"attestations unreachable", []string{"p", "1"}, func(t *testing.T) {
			withSourceSeams(t, nil, boom, nil, nil)
		}, 1, "boom"},
		{"no provenance", []string{"p", "1"}, func(t *testing.T) {
			withSourceSeams(t, []artifact.Referrer{}, nil, nil, nil)
		}, 1, "no provenance"},
		{"pull fails", []string{"p", "1"}, func(t *testing.T) {
			withSourceSeams(t, nil, nil, nil, boom)
		}, 1, "boom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "pull fails" {
				withSourceSeams(t, []artifact.Referrer{
					provenanceRef(t, []string{"https://x/a"}, []string{"abc"}),
				}, nil, nil, boom)
			} else {
				tc.set(t)
			}
			code, _, errs := runSourceIn(t, t.TempDir(), tc.args...)
			if code != tc.code || !strings.Contains(errs, tc.want) {
				t.Fatalf("code = %d (want %d), stderr = %q (want %q)", code, tc.code, errs, tc.want)
			}
		})
	}
}

// TestRunSourceRefusesOneNameForManySources: -o names one file, and a recipe
// with a mirror list attests more than one.
func TestRunSourceRefusesOneNameForManySources(t *testing.T) {
	withSourceSeams(t, []artifact.Referrer{
		provenanceRef(t, []string{"https://a/x.tgz", "https://b/x.tgz"}, []string{"aa", "bb"}),
	}, nil, []byte("x"), nil)
	code, _, errs := runSourceIn(t, t.TempDir(), "-o", "one.tgz", "p", "1")
	if code != 2 || !strings.Contains(errs, "attests 2 sources") {
		t.Fatalf("code = %d, stderr = %q", code, errs)
	}
}

func TestRunSourceReportsAnUnwritableTarget(t *testing.T) {
	dir := t.TempDir()
	withSourceSeams(t, []artifact.Referrer{
		provenanceRef(t, []string{"https://x/a.tgz"}, []string{"abc"}),
	}, nil, []byte("x"), nil)
	code, _, errs := runSourceIn(t, dir, "-o", filepath.Join(dir, "no", "such", "dir", "a.tgz"), "p", "1")
	if code != 1 || errs == "" {
		t.Fatalf("code = %d, stderr = %q", code, errs)
	}
}

// TestRunSourceReportsABadPlatform: target.Resolve is the first thing that can
// fail, and its message is the only thing a user sees of it.
func TestRunSourceReportsABadPlatform(t *testing.T) {
	t.Setenv("ZPKB_TARGET", "nonsense")
	code, _, errs := runSourceIn(t, t.TempDir(), "p", "1")
	if code != 1 || errs == "" {
		t.Fatalf("code = %d, stderr = %q", code, errs)
	}
}

// TestSourceIsReachableFromTheDispatcher: the subcommand has to be wired, and
// a case nothing calls is a command nobody has.
func TestSourceIsReachableFromTheDispatcher(t *testing.T) {
	code, _, errs := run2(t, "source")
	if code != 2 || !strings.Contains(errs, "usage: bk source") {
		t.Fatalf("code = %d, stderr = %q", code, errs)
	}
}

// TestSourceSeamsReachTheRegistry exercises the DEFAULT seams — the code the
// other tests replace. Both branches: a base that is not an oci:// ref, so the
// client cannot be built, and one that is well-formed but unreachable, so the
// call itself is made and fails.
func TestSourceSeamsReachTheRegistry(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	t.Run("attestations", func(t *testing.T) {
		if _, err := sourceAttestations("not-an-oci-ref", "p", "1", "darwin", "aarch64"); err == nil {
			t.Error("a base that is not an oci:// ref built a client")
		}
		if _, err := sourceAttestations("oci://127.0.0.1:1/x", "p", "1", "darwin", "aarch64"); err == nil {
			t.Error("an unreachable registry answered")
		}
	})
	t.Run("puller", func(t *testing.T) {
		if _, err := sourcePuller("not-an-oci-ref", "abc"); err == nil {
			t.Error("a base that is not an oci:// ref built a client")
		}
		if _, err := sourcePuller("oci://127.0.0.1:1/x", "abc"); err == nil {
			t.Error("an unreachable registry answered")
		}
	})
}
