package pantry

import "strings"

// Supports reports whether a recipe's `platforms:` admits one target.
//
// The field was parsed and read by nobody. 81 recipes in the pantry declare a
// platforms: that excludes darwin — elfutils.org, systemd.io, x.org/xserver,
// kernel.org/linux, github.com/vmware/tdnf among them — and every consumer
// treated them as darwin candidates: `bk factory` on darwin attempted them and
// collected the failures, and `bk depgaps` ranked THEIR unmet dependencies as
// darwin gaps, which is how rpm.org/rpm and opensuse.org/libsolv came to sit in
// a darwin/aarch64 ranking.
//
// Honouring it removes only work that cannot succeed. Measured against the
// published registry: of those 81, seven do have a darwin artifact
// (freedesktop.org/libbsd, github.com/containerd/nerdctl,
// github.com/containers/buildah, github.com/rui314/mold, gnupg.org/v2.5,
// google.com/fullycapable, mercure.rocks) and all seven are MIRRORS —
// platform-tags=0, upstream's layer format. Our factory has never built one.
//
// Three spellings are accepted, because the pantry uses all three:
//
//	platforms: linux                        # a bare string
//	platforms: [linux]                      # a list of OS names
//	platforms: [linux/x86-64, linux/aarch64]  # os/arch slugs
//
// An absent field means every platform. An entry naming only an OS admits every
// arch of it; an os/arch slug admits exactly that pair.
func Supports(r *Recipe, platform, arch string) bool {
	if r == nil || r.Platforms == nil {
		return true
	}
	for _, e := range platformEntries(r.Platforms) {
		os, a, hasArch := strings.Cut(e, "/")
		if os != platform {
			continue
		}
		if !hasArch || a == arch {
			return true
		}
	}
	return false
}

// platformEntries flattens the field's three spellings into a list of entries.
// A value shaped like none of them yields no entries, which reads as "supports
// nothing" — the conservative answer for a declaration we do not understand,
// and one the schema gate would have rejected before it reached here.
func platformEntries(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{strings.TrimSpace(x)}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			// A non-string entry (`platforms: [1]`) is dropped rather than
			// stringified. It cannot name a platform, and the schema gate
			// rejects it long before here; keeping it would only let a
			// nonsense entry admit a build.
			if s, ok := e.(string); ok {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}
