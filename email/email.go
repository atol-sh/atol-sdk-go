// Package email provides the canonical-email normalization that atol applies
// everywhere an address becomes a principal or a Zanzibar subject (signup,
// login lookup, social/passwordless federation, and grant/revoke).
//
// Consumers that key or hash on an email - for example deriving a stable
// pre-login subject like "user:em_<sha256(email)>" - MUST normalize with
// CanonicalEmail before keying, on both the write side (grant/invite) and the
// read side (login). atol stores and verifies the canonical form, so any
// divergent normalization produces a different key (and, when hashed, a
// completely different digest) and silently fails to match. This package is the
// single source of truth: the control plane delegates to it, so calling it
// guarantees byte-for-byte agreement with atol's verified-identity form.
package email

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// ErrInvalidEmail is returned by CanonicalEmail when an address is empty, too
// long, contains a null byte, has anything other than exactly one "@", has an
// empty local or domain part, or has a domain that IDNA rejects. It is a
// sentinel for errors.Is. The email is PII; the returned error never embeds the
// offending address.
var ErrInvalidEmail = errors.New("invalid email address")

// maxEmailLen is the RFC 5321 maximum total length of an email address.
const maxEmailLen = 254

// CanonicalEmail returns the canonical form of an email address: the local part
// is ASCII-trimmed, lowercased, and NFC-normalized (preserving dots and
// "+tags"); the domain is normalized via IDNA (idna.Lookup.ToASCII lowercases,
// validates, and punycodes internationalized domains). Internationalized
// addresses canonicalize consistently rather than being rejected.
//
// It rejects structurally invalid input: empty, longer than 254 bytes,
// containing a null byte, not having exactly one "@", an empty local or domain
// part, or a domain IDNA cannot encode.
//
// The email is PII; the returned error never embeds the address.
func CanonicalEmail(raw string) (string, error) {
	s := trimASCIISpace(raw)
	if s == "" {
		return "", ErrInvalidEmail
	}
	if len(s) > maxEmailLen {
		return "", ErrInvalidEmail
	}
	if strings.IndexByte(s, 0) >= 0 {
		return "", ErrInvalidEmail
	}
	if strings.Count(s, "@") != 1 {
		return "", ErrInvalidEmail
	}
	at := strings.IndexByte(s, '@')
	local, domain := s[:at], s[at+1:]
	if local == "" || domain == "" {
		return "", ErrInvalidEmail
	}

	canonLocal := norm.NFC.String(strings.ToLower(local))

	// idna.Lookup.ToASCII lowercases, validates, and punycodes the domain. Any
	// IDNA violation (disallowed rune, malformed label) is a typed rejection.
	canonDomain, err := idna.Lookup.ToASCII(domain)
	if err != nil || canonDomain == "" {
		return "", ErrInvalidEmail
	}

	return canonLocal + "@" + canonDomain, nil
}

// trimASCIISpace trims leading and trailing ASCII whitespace (space, tab, CR,
// LF, vertical tab, form feed) without touching non-ASCII runes such as a
// no-break space inside an internationalized local part.
func trimASCIISpace(s string) string {
	return strings.Trim(s, " \t\r\n\v\f")
}
