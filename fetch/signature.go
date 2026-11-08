package fetch

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
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
func DigestVerified(url string, sigURLs []string, keyring []byte) (SourcePin, error) {
	if len(sigURLs) == 0 {
		return SourcePin{}, fmt.Errorf("fetch: %s: no signature URL to try", url)
	}
	if len(keyring) == 0 {
		return SourcePin{}, fmt.Errorf("fetch: %s: an empty keyring verifies nothing — "+
			"pass the author's public key, and never let a keyserver choose it", url)
	}
	keys, err := readKeyring(keyring)
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

	return SourcePin{
		SHA256:      digest,
		Size:        size,
		SigURL:      sigURL,
		Fingerprint: fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint),
		Identity:    primaryIdentity(signer),
	}, nil
}

// readKeyring parses an armored or binary public key file.
func readKeyring(b []byte) (openpgp.EntityList, error) {
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	if err != nil {
		// Not armoured, or not a key at all: try the binary form before
		// reporting, and report the BINARY error, which is the one that saw the
		// bytes as they are.
		keys, err = openpgp.ReadKeyRing(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("fetch: the key file is neither an armored nor a "+
				"binary OpenPGP public key: %w", err)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("fetch: the key file parsed but holds no keys")
	}
	return keys, nil
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
