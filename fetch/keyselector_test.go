package fetch

import (
	"strings"
	"testing"
)

// ⛔⛔ THE CASE THAT MADE THIS NECESSARY, AND IT IS A REAL PROJECT.
//
// gnu.org/m4's release announcement prints `Key fingerprint = 71C2 CC22 …`, so
// the key can be named. GNU tar's prints no key at all — only "Here are the GPG
// detached signatures:" — and its maintainer publishes the key as a LONG KEY ID
// instead, verbatim in the mailutils-3.17 and cpio-2.15 announcements:
//
//	gpg --recv-keys 3602B07F55D0C732
//
// Refusing that form did not make anything safer. It made gnu.org/tar,
// gnu.org/cpio and every project documented the same way impossible to pin,
// which is worse than pinning them by the strongest identifier their author
// actually published. Measured against the real keyring after this change:
// tar's key is found after 12 primary keys and reports the full fingerprint
// 325F650C4C2B6AD58807327A3602B07F55D0C732 — whose last sixteen digits are the
// published id.
func TestNormaliseKeySelector(t *testing.T) {
	for _, tc := range []struct {
		name, in, want, wantErr string
	}{
		{"a fingerprint as gpg prints it",
			"71C2 CC22 B1C4 6029 27D2  F3AA A7A1 6B4A 2527 436A",
			"71C2CC22B1C4602927D2F3AAA7A16B4A2527436A", ""},
		{"a fingerprint with colons",
			"71:C2:CC:22:B1:C4:60:29:27:D2:F3:AA:A7:A1:6B:4A:25:27:43:6A",
			"71C2CC22B1C4602927D2F3AAA7A16B4A2527436A", ""},
		{"the long key id tar's maintainer publishes",
			"3602B07F55D0C732", "3602B07F55D0C732", ""},
		{"a long key id in lower case",
			"3602b07f55d0c732", "3602b07f55d0c732", ""},

		// ⛔ THE REFUSAL THAT IS THE SECURITY CONTENT. A 32-bit id is not an
		// identifier: colliding keys for a chosen short id have been made and
		// uploaded to the keyservers.
		{"a short key id", "55D0C732", "", "SHORT (32-bit) key id"},
		{"a short key id with 0x", "0x55D0C732", "", "SHORT (32-bit) key id"},

		// ⛔ Prose is not a selector, and EXTRACTING hex digits made it one: the
		// e's, a's and b's of ordinary English are hex. Validation requires, it
		// does not extract.
		{"prose", "the key on his website", "", "is not a hex digit"},
		{"a URL", "https://example.org/key.asc", "", "is not a hex digit"},
		{"empty", "", "", "holds no hex digits"},
		{"a truncated fingerprint", "71C2CC22B1C46029", "71C2CC22B1C46029", ""},
		{"twenty digits", "71C2CC22B1C4602927D2", "", "has 20 hex digits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormaliseKeySelector(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("NormaliseKeySelector(%q) = %q, want an error", tc.in, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormaliseKeySelector(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormaliseKeySelector(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestKeyMatches(t *testing.T) {
	const fpr = "325F650C4C2B6AD58807327A3602B07F55D0C732"
	for _, tc := range []struct {
		name, selector string
		want           bool
	}{
		{"the whole fingerprint", fpr, true},
		{"the whole fingerprint, spaced", "325F 650C 4C2B 6AD5 8807  327A 3602 B07F 55D0 C732", true},
		{"the whole fingerprint, lower case", strings.ToLower(fpr), true},
		{"the published long id", "3602B07F55D0C732", true},
		{"the published long id, lower case", "3602b07f55d0c732", true},
		// ⛔ A long id matches the LAST sixteen digits and nowhere else: the
		// leading digits of a fingerprint are not a key id, and a prefix match
		// would answer yes to a key that merely begins alike.
		{"the first sixteen digits", "325F650C4C2B6AD5", false},
		{"a different long id", "0000000000000000", false},
		{"a different fingerprint", "71C2CC22B1C4602927D2F3AAA7A16B4A2527436A", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyMatches(fpr, tc.selector); got != tc.want {
				t.Errorf("keyMatches(fpr, %q) = %v, want %v", tc.selector, got, tc.want)
			}
		})
	}
}

// ⛔ The selector is judged BEFORE the keyring is read, because a malformed one
// that merely fails to match is indistinguishable from "the key is not in this
// file" — and against the GNU keyring, whose packet stream stops at its 402nd
// key, it is indistinguishable from "the keyring is broken". That is what a
// 16-digit id reported twice on 2026-11-09, before it was accepted at all.
func TestAShortKeyIdIsRefusedBeforeTheKeyringIsTouched(t *testing.T) {
	_, err := DigestVerified("https://example.test/x.tar.xz", []string{"https://example.test/x.tar.xz.sig"},
		[]byte("not even a keyring"), "55D0C732")
	if err == nil {
		t.Fatal("a short key id was accepted")
	}
	if !strings.Contains(err.Error(), "SHORT (32-bit) key id") {
		t.Errorf("error %q is not the short-id refusal — it read the file first", err)
	}
}
