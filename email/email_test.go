package email

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalEmail(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"lowercases whole address", "Client@Example.COM", "client@example.com", false},
		{"trims ascii whitespace", "  client@example.com\t\n", "client@example.com", false},
		{"preserves dots", "first.last@example.com", "first.last@example.com", false},
		{"preserves plus tag", "user+tag@example.com", "user+tag@example.com", false},
		{"mixed case normalizes", "Jose@Bucher.de", "jose@bucher.de", false},
		{"non-ascii local lowercases", "RÉMI@Example.com", "rémi@example.com", false},
		{"idn domain punycodes", "user@Müller.de", "user@xn--mller-kva.de", false},
		{"uppercase idn domain punycodes", "user@MÜLLER.DE", "user@xn--mller-kva.de", false},
		{"already-punycode domain passthrough", "user@xn--mller-kva.de", "user@xn--mller-kva.de", false},
		{"empty rejected", "", "", true},
		{"whitespace-only rejected", "   ", "", true},
		{"null byte rejected", "a\x00b@example.com", "", true},
		{"multi-at rejected", "a@b@example.com", "", true},
		{"no-at rejected", "noatsign.example.com", "", true},
		{"empty local rejected", "@example.com", "", true},
		{"empty domain rejected", "user@", "", true},
		{"domain with space rejected", "user@exam ple.com", "", true},
		// A 256-byte all-ASCII address: isolates the maxEmailLen guard (no null
		// byte, single "@", valid domain) so a regression that raised the limit
		// wouldn't be masked by an earlier rejection.
		{"too long rejected", strings.Repeat("a", 250) + "@x.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalEmail(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidEmail) {
					t.Fatalf("CanonicalEmail(%q) err = %v, want ErrInvalidEmail", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalEmail(%q) unexpected err = %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("CanonicalEmail(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestCanonicalEmailNFC is the case a naive ToLower-only normalizer misses: a
// local part typed in decomposed form (base letter + a combining mark) must
// NFC-normalize to the precomposed code point, so it keys/hashes byte-for-byte
// identically to atol's verified-identity form. The strings are built from rune
// values rather than source literals so the byte sequences are unambiguous
// regardless of how an editor normalizes the file.
func TestCanonicalEmailNFC(t *testing.T) {
	const combiningAcute = rune(0x0301) // U+0301 COMBINING ACUTE ACCENT
	const precomposedE = rune(0x00E9)   // U+00E9 LATIN SMALL LETTER E WITH ACUTE

	decomposed := "jose" + string(combiningAcute) + "@x.com" // j o s e ◌́ @ ...
	wantPrecomposed := "jos" + string(precomposedE) + "@x.com"

	got, err := CanonicalEmail(decomposed)
	if err != nil {
		t.Fatalf("CanonicalEmail(decomposed) unexpected err = %v", err)
	}
	if got != wantPrecomposed {
		t.Errorf("CanonicalEmail(decomposed) = %q (% x), want %q (% x)", got, got, wantPrecomposed, wantPrecomposed)
	}
	// Re-canonicalizing the precomposed result is a no-op (fixed point), so the
	// write side (invite) and read side (login JWT) converge on one digest.
	again, err := CanonicalEmail(got)
	if err != nil {
		t.Fatalf("CanonicalEmail(precomposed) unexpected err = %v", err)
	}
	if again != got {
		t.Errorf("not idempotent: CanonicalEmail(%q) = %q", got, again)
	}
}
