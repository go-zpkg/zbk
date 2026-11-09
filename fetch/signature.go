package fetch

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Verifying an upstream OpenPGP signature, AT THE MOMENT THE DIGEST IS
// RECORDED, which is the one design decision here worth arguing about.
//
// # Where the other distributions do this, read before it was written
//
//	Gentoo    verify-sig USE flag; keys in /usr/share/openpgp-keys, shipped by
//	          a sec-keys/openpgp-keys-* package — checked at EVERY build
//	Arch      validpgpkeys=(), full uppercase fingerprints; makepkg "will only
//	          accept signatures from the keys listed here and will ignore the
//	          trust values from the keyring" — at EVERY build
//	Debian    Pgp-Mode: in debian/watch, key in debian/upstream/signing-key.asc
//	          — at `uscan`, when the maintainer imports a release
//	Guix      NO signature field in the `origin` record at all; checked in
//	          `guix refresh`, against ~/.config/guix/upstream/trustedkeys.kbx
//	Spack, Nix, FreeBSD ports: no signature field found
//
// ⭐ GUIX HAS NO SIGNATURE FIELD BECAUSE IT DOES NOT NEED ONE, and that is the
// shape copied here. The signature's job is to justify WRITING the hash; the
// hash is then the durable pin, and the recipe's own authenticity is a separate
// mechanism. Verifying at every build instead would require the signature and
// the key to stay reachable forever, from inside a sandbox, for every consumer
// — three network dependencies for a fact settled once.
//
// # What is done DIFFERENTLY, and why
//
// ⛔⛔ NO KEYSERVER. EVER. Guix's `--key-download` defaults to `auto`, which it
// documents as `interactive` on a TTY and "else `always`" — and `always` is
// "Always download missing OpenPGP keys from the key server". In CI, where this
// would run, an unknown key is therefore fetched and accepted, so the check
// becomes "somebody signed it" rather than "this key signed it". The keyring
// here comes from a FILE the author passes, and an unknown key is a refusal.
//
// ⛔ AND THE FINGERPRINT'S PROVENANCE IS MANDATORY. Not one of the systems
// above records where a fingerprint came from. Debian's uscan(1) is the most
// explicit and it is an instruction, not a procedure: "You must verify the
// downloaded OpenPGP key using its full fingerprint value which you know is the
// trusted one." Which you know. That is unauditable, so `zbk sourcepin`
// requires the author to say, and prints it into the recipe's provenance.
//
// Fingerprints are printed as uppercase hex with no separators, which is Arch's
// documented rule and the strictest of the three.

// pgpReadKeyRing is a seam, and the measurement it stands for is the reason
// this whole fallback exists.
//
// ⛔⛔ THE BRANCH BELOW IT CANNOT BE REACHED WITH CRAFTED BYTES. The real case
// is https://ftp.gnu.org/gnu/gnu-keyring.gpg — 3 700 423 bytes, 326+ primary
// keys — which openpgp refuses WHOLE with:
//
//	openpgp: invalid data: Cannot have multiple embedded signatures
//
// Reproducing that needs an entity with two embedded signatures, not a
// truncated packet: four hand-built fixtures were tried and ReadKeyRing read
// every one of them, trailing garbage included. A seam drives the branch
// honestly; the string above is the evidence that the branch is real.
var pgpReadKeyRing = openpgp.ReadKeyRing

// maxSigBody caps a detached signature. A real one is a few hundred bytes;
// anything past this is not one, and reading it all would turn a wrong URL into
// a memory problem — the same bound DeclaredSHA256 applies for the same reason.
const maxSigBody = 1 << 16

// SourcePin is everything an author needs to pin a source, and everything a
// reader needs to know who vouched for it.
//
// Named SourcePin and not Pin because [Pin] is already this package's
// trust-on-first-use hook — a different control for a different moment, and two
// things called Pin in one package would be read as one.
type SourcePin struct {
	// SHA256 is the digest to write into the recipe, lowercase hex.
	SHA256 string
	// Size is the archive's length in bytes. Printed because 92 bytes of error
	// page is visible in a way a hex string is not.
	Size int64
	// SigURL is the candidate that actually answered, so a recipe records the
	// URL that worked rather than the one that was guessed.
	SigURL string
	// Fingerprint is the PRIMARY key's fingerprint, uppercase hex, no
	// separators. A signature made by a subkey reports the primary key, which
	// is what Arch's validpgpkeys compares and what an author can publish.
	Fingerprint string
	// Identity is the key's primary user id, for a human reading the output.
	// It is not a trust statement: anybody can put any name in a user id.
	Identity string
	// KeysRead is how many keys were used to verify: 1 when a fingerprint was
	// named, otherwise everything the file held. KeysScanned is how many
	// primary keys the file was walked past to find the named one, and is 0
	// when no fingerprint was given.
	//
	// Both are printed, because an author who passed a file holding one key and
	// an author who passed every GNU maintainer's key otherwise get the same
	// "signed by" line, and only the second needs a fingerprint.
	KeysRead, KeysScanned int
}

// DigestVerified downloads url, verifies a detached OpenPGP signature over
// those exact bytes, and returns the pin.
//
// sigURLs are tried in order and the FIRST that answers 200 is used; a 404 moves
// to the next, any other failure is reported. That mirrors Debian's
// `Pgp-Mode: auto`, which "checks possible URLs for the signature file".
//
// keyring is the author's public key file, armored or binary. It is the ONLY
// source of keys: nothing is fetched from a keyserver, so a signature by a key
// that is not in this file is a refusal and not a prompt.
//
// wantFPR, when not empty, is the fingerprint the signing key MUST have. It is
// compared on the primary key, case-insensitively, with spaces and colons
// stripped — the shapes a person copies out of `gpg --fingerprint`.
//
// ⛔ WITHOUT IT, A KEYRING IS A SET AND NOT A CHOICE. The GNU keyring holds
// every maintainer's key, so verifying against it answers "somebody in here
// signed this", which is the degradation Guix's `--key-download=always`
// produces in CI. Arch's `validpgpkeys` exists for this and `PKGBUILD(5)` is
// explicit: makepkg "will only accept signatures from the keys listed here and
// will ignore the trust values from the keyring". Empty means the caller
// accepts any key in the file, which is right only for a file holding one.
func DigestVerified(url string, sigURLs []string, keyring []byte, wantFPR string) (SourcePin, error) {
	if len(sigURLs) == 0 {
		return SourcePin{}, fmt.Errorf("fetch: %s: no signature URL to try", url)
	}
	if len(keyring) == 0 {
		return SourcePin{}, fmt.Errorf("fetch: %s: an empty keyring verifies nothing — "+
			"pass the author's public key, and never let a keyserver choose it", url)
	}
	// ⛔ THE SELECTOR IS JUDGED BEFORE THE FILE IS READ. A malformed one that
	// simply fails to match looks exactly like "the key is not in this keyring",
	// and against the GNU keyring it looks like "the keyring is broken" — which
	// is what a 16-digit long id did on 2026-11-09, twice, before this check
	// existed.
	if wantFPR != "" {
		if _, err := NormaliseKeySelector(wantFPR); err != nil {
			return SourcePin{}, err
		}
	}
	keys, scanned, err := readKeyring(keyring, wantFPR)
	if err != nil {
		return SourcePin{}, err
	}

	path, digest, size, err := digestKept(url)
	if err != nil {
		return SourcePin{}, err
	}
	defer osRemove(path)

	sigURL, sig, err := firstSignature(sigURLs)
	if err != nil {
		return SourcePin{}, err
	}

	f, err := osOpenFetched(path)
	if err != nil {
		return SourcePin{}, fmt.Errorf("fetch: %s: %w", url, err)
	}
	defer f.Close()

	// ⛔ THE SIGNATURE'S ARMOUR DECIDES WHICH CHECK TO CALL, and it is read
	// rather than guessed from the file extension: `.asc` is conventionally
	// armoured and `.sig` binary, but the convention is not enforced by anyone
	// and a mislabelled file would read as a broken signature instead of a
	// differently-encoded one.
	var signer *openpgp.Entity
	if bytes.Contains(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		signer, err = openpgp.CheckArmoredDetachedSignature(keys, f, bytes.NewReader(sig), nil)
	} else {
		signer, err = openpgp.CheckDetachedSignature(keys, f, bytes.NewReader(sig), nil)
	}
	if err != nil {
		return SourcePin{}, fmt.Errorf("fetch: %s is not vouched for by the key you passed: %w — "+
			"the bytes downloaded fine and hash to %s; what failed is WHO signed them, "+
			"so do not pin this until you know why", sigURL, err, digest)
	}

	got := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
	// ⛔ CHECKED AFTER THE SIGNATURE AND BEFORE ANYTHING IS RETURNED. A
	// fingerprint mismatch is not a lesser failure than a bad signature: the
	// bytes are correctly signed, by somebody the author did not name, which is
	// precisely the case a keyring of many keys creates.
	if wantFPR != "" && !keyMatches(got, wantFPR) {
		return SourcePin{}, fmt.Errorf("fetch: %s is signed by %s (%s), not by the %s you "+
			"named — the signature is VALID and made by a key in your keyring, which is why "+
			"this is checked separately; a keyring holding many keys answers \"somebody in "+
			"here signed it\" unless you say which", sigURL, got, primaryIdentity(signer), wantFPR)
	}

	return SourcePin{
		SHA256:      digest,
		Size:        size,
		SigURL:      sigURL,
		Fingerprint: got,
		Identity:    primaryIdentity(signer),
		KeysRead:    len(keys),
		KeysScanned: scanned,
	}, nil
}

// sameFingerprint compares two fingerprints as a person pastes them: `gpg
// --fingerprint` prints groups separated by spaces, some pages use colons, and
// case varies. Only the hex digits are compared.
func sameFingerprint(a, b string) bool {
	return strings.EqualFold(hexOnly(a), hexOnly(b))
}

// KeySelectorError says why a --fingerprint value cannot be used.
type KeySelectorError struct{ Why string }

func (e *KeySelectorError) Error() string { return e.Why }

// NormaliseKeySelector turns what an author pasted into the hex digits to
// compare, and refuses what must not be trusted.
//
// ⛔⛔ A FULL FINGERPRINT IS NOT ALWAYS PUBLISHED, AND THAT BLOCKED REAL WORK.
// gnu.org/m4's release announcement prints a `pub` block with
// `Key fingerprint = 71C2 CC22 …`, so it can be named. GNU tar's does not: it
// says only "Here are the GPG detached signatures:". Its maintainer publishes
// the key as a LONG KEY ID instead, verbatim in the mailutils-3.17 and
// cpio-2.15 announcements:
//
//	gpg --recv-keys 3602B07F55D0C732
//
// Sixteen hex digits, which are the last sixteen of the fingerprint — that is
// how GnuPG resolves it. Refusing that form does not make anything safer; it
// makes gnu.org/tar, gnu.org/cpio and every project whose maintainer documents
// a key ID unpinnable, which is strictly worse than pinning them by the
// strongest identifier their author actually published.
//
// ⛔ EIGHT DIGITS ARE REFUSED, and that refusal is the security content here. A
// 32-bit key ID is trivially collided — the demonstration is public and the
// colliding keys were uploaded to the keyservers — so a short ID identifies a
// key only until somebody wants it not to. Sixty-four bits is weaker than a
// fingerprint and is what the author published; thirty-two is not an
// identifier.
//
// ⭐ And whichever form went in, the caller reports the FULL fingerprint of the
// key it found, so a recipe records the strong form even when the source
// published the weak one. The weakness belongs in `--key-source`, which says
// where the value came from, not in the pin.
// ⛔⛔ VALIDATION NORMALISES AND THEN REQUIRES; IT DOES NOT EXTRACT. hexOnly is
// right for COMPARING a fingerprint `gpg --fingerprint` printed, where the
// groups and separators are noise. It is wrong for judging what an author
// pasted, and its own tests said so:
//
//	"0x55D0C732"             → kept the 0 and dropped the x, so nine digits,
//	                           reported as "has 9 hex digits" rather than as
//	                           the short id it plainly is
//	"the key on his website" → the e's, a's and b's of ordinary English are
//	                           hex digits, so prose became a selector
//
// So: strip the separators a person types — spaces, colons, a leading 0x — and
// then every remaining character must BE a hex digit.
func NormaliseKeySelector(s string) (string, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X")
	t = strings.NewReplacer(" ", "", ":", "", "\t", "").Replace(t)
	for _, r := range t {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return "", &KeySelectorError{Why: "fetch: " + s + " is not a key fingerprint or key " +
				"id: " + string(r) + " is not a hex digit. Spaces, colons and a leading 0x are " +
				"allowed; nothing else is"}
		}
	}
	h := t
	switch len(h) {
	case 40:
		return h, nil
	case 16:
		return h, nil
	case 8:
		return "", &KeySelectorError{Why: "fetch: " + s + " is a SHORT (32-bit) key id, and a " +
			"short id is not an identifier: colliding keys for a chosen short id have been " +
			"made and uploaded to the keyservers. Give the full fingerprint, or the 16-digit " +
			"long id the author published (`gpg --recv-keys <16 hex>`)"}
	case 0:
		return "", &KeySelectorError{Why: "fetch: " + s + " holds no hex digits — a fingerprint " +
			"or a 16-digit long key id was expected"}
	default:
		return "", &KeySelectorError{Why: fmt.Sprintf("fetch: %s has %d hex digits; a fingerprint "+
			"has 40 and a long key id has 16", s, len(h))}
	}
}

// keyMatches reports whether a key's fingerprint answers to the selector: the
// whole fingerprint, or its last sixteen digits for a long key id — which is
// what the final 64 bits of a fingerprint ARE.
func keyMatches(fingerprint, selector string) bool {
	f, s := hexOnly(fingerprint), hexOnly(selector)
	if len(s) == 16 {
		return len(f) >= 16 && strings.EqualFold(f[len(f)-16:], s)
	}
	return strings.EqualFold(f, s)
}

func hexOnly(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			out.WriteRune(r)
		}
	}
	return out.String()
}

// readKeyring parses an armored or binary public key file ENTITY BY ENTITY,
// keeping the keys that parse and counting the ones that do not.
//
// ⛔⛔ ALL-OR-NOTHING WAS UNUSABLE AGAINST THE ONE KEYRING THIS IS FOR.
// `openpgp.ReadKeyRing` stops at the first entity it cannot read and discards
// everything before it. Measured on 2026-11-08 against
// https://ftp.gnu.org/gnu/gnu-keyring.gpg — 3 700 423 bytes, every GNU
// maintainer's key, which is the keyring an author pinning a GNU tarball
// actually has:
//
//	openpgp: invalid data: Cannot have multiple embedded signatures
//
// One unreadable entity among hundreds, and not one key was returned. The error
// this package then printed was "neither an armored nor a binary OpenPGP public
// key", which is a FALSE DIAGNOSIS: it is a binary keyring, and a valid one, with
// a single entity a thirty-year-old archive is entitled to contain.
//
// ⭐ SKIPPING AN UNPARSEABLE KEY IS NOT A SECURITY HOLE, and that is the
// argument for doing it. A key that cannot be parsed is a key nothing can
// verify against, so skipping it is indistinguishable from its absence — and a
// revocation inside a packet no implementation can read was never usable
// either. What WOULD be a hole is doing it silently, which is why the count
// comes back and `sourcepin` prints it.
//
// It is also why [DigestVerified] takes a wanted fingerprint. A keyring of
// every GNU maintainer answers "somebody in here signed it", which is the same
// degradation Guix's `--key-download=always` produces in CI. Arch's
// `validpgpkeys` is the fix and it is documented as exactly that: makepkg
// "will only accept signatures from the keys listed here and will ignore the
// trust values from the keyring".
func readKeyring(b []byte, wantFPR string) (openpgp.EntityList, int, error) {
	body, ok := keyBody(b)
	if !ok {
		return nil, 0, fmt.Errorf("fetch: the key file is neither an armored nor a " +
			"binary OpenPGP public key")
	}

	// ⛔⛔ A FIRST ATTEMPT AT THIS SKIPPED UNREADABLE ENTITIES IN A LOOP, AND THE
	// LOOP DID NOT MOVE. The comment above it asserted that "ReadEntity consumes
	// up to the next key packet"; measured against the real GNU keyring, it does
	// not — the reader stays parked on the packet it refused and the same error
	// repeats, 1025 times until a cap stopped it. The cap earned its keep and
	// the premise did not.
	//
	// ⛔ THE WHOLE FILE FIRST, AND NARROWING ONLY AS A FALLBACK. An earlier
	// version narrowed to the named key whenever one was given, and that made
	// the useful diagnosis unreachable: with a one-key list, a signature by
	// another key IN THE SAME FILE comes back as "signature made by unknown
	// entity" instead of "signed by X, not by the Y you named". A test caught
	// it. Reading the ring whole and comparing afterwards is also Arch's order
	// — makepkg verifies, then compares against validpgpkeys.
	keys, err := pgpReadKeyRing(bytes.NewReader(body))
	if err == nil && len(keys) > 0 {
		return keys, 0, nil
	}
	if wantFPR == "" {
		if err == nil {
			return nil, 0, fmt.Errorf("fetch: the key file parsed and holds no key")
		}
		return nil, 0, fmt.Errorf("fetch: this key file cannot be read whole (%w) — pass "+
			"--fingerprint to name the one key you mean, which reads only that one. A "+
			"public archive's keyring spans decades and one entity it holds can be "+
			"unreadable without the rest being wrong", err)
	}

	// Naming the key is what makes such a file usable: the entities not asked
	// for are never assembled, so one unreadable key elsewhere in a
	// thirty-year-old archive cannot make the one needed unusable. Measured on
	// the real GNU keyring: 326 primary keys walked, the 327th taken.
	e, scanned, ferr := keyByFingerprint(body, wantFPR)
	if ferr != nil {
		return nil, scanned, ferr
	}
	return openpgp.EntityList{e}, scanned, nil
}

// keyByFingerprint reads only the entity whose PRIMARY key has the wanted
// fingerprint, and reports how many primary keys it walked past to get there.
//
// It compares the fingerprint from the key packet itself, before any entity is
// assembled, so a key that cannot be assembled is simply not the answer rather
// than an error.
func keyByFingerprint(body []byte, wantFPR string) (*openpgp.Entity, int, error) {
	r := packet.NewReader(bytes.NewReader(body))
	scanned := 0
	for {
		p, err := r.Next()
		if err == io.EOF {
			return nil, scanned, fmt.Errorf("fetch: no key with fingerprint %s in the key "+
				"file (%d primary key(s) walked) — check the fingerprint, and that this is "+
				"the file you meant", wantFPR, scanned)
		}
		if err != nil {
			// ⛔⛔ STOP, DO NOT CONTINUE. An earlier version of this loop
			// skipped and carried on, and that is the same defect that made the
			// first attempt at tolerant parsing spin 1025 times: a
			// packet.Reader cannot be resynchronised after a tag it refuses, so
			// `continue` either repeats the error forever or reads the rest of
			// the file as one packet's payload. A stream this cannot parse is a
			// stream it cannot search, and saying so is the honest answer.
			//
			// This is not the GNU keyring's case, which is why that one works:
			// there the PACKETS all read and one ENTITY would not assemble, and
			// entities are assembled here only for the key that matched.
			// Measured 2026-11-08: 326 primary keys walked, none refused.
			// ⛔⛔ AND IT MUST SAY BOTH THINGS. This used to report only the
			// stream break, which reads as "your keyring is broken" — and on
			// 2026-11-09 that is exactly what I concluded, twice, when the real
			// answer was "the selector you gave matched none of the keys I could
			// read". The GNU keyring breaks at its 402nd primary key, so EVERY
			// unmatched search against it ends here rather than at EOF, and the
			// message that blames the file is the one a reader always gets.
			return nil, scanned, fmt.Errorf("fetch: no key matching %s among the %d primary "+
				"key(s) that could be read, and the packet stream stops being readable after "+
				"them: %w — so either the key is beyond that point in this file, or the "+
				"selector is wrong", wantFPR, scanned, err)
		}
		pk, isKey := p.(*packet.PublicKey)
		if !isKey || pk.IsSubkey {
			continue
		}
		scanned++
		if !keyMatches(fmt.Sprintf("%X", pk.Fingerprint), wantFPR) {
			continue
		}
		// Found it. Hand the key packet back so ReadEntity sees the entity from
		// its start, with its user ids, self-signatures and subkeys.
		r.Unread(p)
		e, err := openpgp.ReadEntity(r)
		if err != nil {
			return nil, scanned, fmt.Errorf("fetch: the key %s is in the file and cannot be "+
				"read: %w", wantFPR, err)
		}
		return e, scanned, nil
	}
}

// keyBody strips OpenPGP armour if present and returns the binary packet
// stream, so everything downstream reads one shape.
//
// ⛔ THE FIRST OCTET IS THE TEST FOR "IS THIS A PACKET STREAM AT ALL", and it
// is why a README does not reach the keyring reader. RFC 9580 §4.2: a packet's
// first octet has bit 7 set, always. Without this check a text file was
// accepted as "binary" and the refusal then advised passing --fingerprint,
// which is useless advice for a file that holds no keys at all — a test caught
// exactly that.
func keyBody(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	if block, err := armor.Decode(bytes.NewReader(b)); err == nil {
		body, err := io.ReadAll(block.Body)
		if err != nil || len(body) == 0 {
			return nil, false
		}
		return body, body[0]&0x80 != 0
	}
	return b, b[0]&0x80 != 0
}

// firstSignature fetches the first candidate URL that answers 200.
//
// A 404 is "not published at that name" and moves on; anything else stops,
// because a 503 on the first candidate must not be reported as "the project
// publishes no signature".
func firstSignature(urls []string) (string, []byte, error) {
	var missing []string
	for _, u := range urls {
		resp, err := httpGet(u)
		if err != nil {
			return "", nil, fmt.Errorf("fetch: get signature %s: %w", u, err)
		}
		if resp.StatusCode == 404 {
			resp.Body.Close()
			missing = append(missing, u)
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return "", nil, fmt.Errorf("fetch: get signature %s: %s", u, resp.Status)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxSigBody))
		resp.Body.Close()
		if err != nil {
			return "", nil, fmt.Errorf("fetch: read signature %s: %w", u, err)
		}
		if len(body) == 0 {
			return "", nil, fmt.Errorf("fetch: signature %s is empty", u)
		}
		return u, body, nil
	}
	return "", nil, fmt.Errorf("fetch: no signature at %s — all answered 404. "+
		"That is a fact about the project, not about you: most publish none, and "+
		"a recipe without one is pinned by digest alone", strings.Join(missing, ", "))
}

// primaryIdentity names the key's owner, DETERMINISTICALLY.
//
// ⛔ openpgp.Entity.Identities is a MAP, so ranging it once gives a different
// answer per run and two `sourcepin` invocations would print different lines for
// the same key. The identity marked primary wins; otherwise the
// lexicographically smallest, so the choice is stable rather than merely
// arbitrary. A key with no identity at all is possible and says so.
func primaryIdentity(e *openpgp.Entity) string {
	var names []string
	for name, id := range e.Identities {
		if id.SelfSignature != nil && id.SelfSignature.IsPrimaryId != nil && *id.SelfSignature.IsPrimaryId {
			return name
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return "(the key carries no user id)"
	}
	sort.Strings(names)
	return names[0]
}

// osOpenFetched is a seam, matching osStatFetched beside it, so the open error
// of a file this package just wrote stays reachable from a test.
var osOpenFetched = func(path string) (*os.File, error) { return os.Open(path) }
