package utils

import "testing"

func TestParseIdentifier(t *testing.T) {
	tests := []struct {
		in, name, domain string
		ok               bool
	}{
		{"bob@example.com", "bob", "example.com", true},
		// TLDs longer than 4 letters were rejected by the old regex.
		{"x@nostrplebs.social", "x", "nostrplebs.social", true},
		{"x@nostr.directory", "x", "nostr.directory", true},
		{"x@flokicoin.network", "x", "flokicoin.network", true},
		{"_@primal.net", "_", "primal.net", true},
		{"  Bob@Example.COM ", "bob", "example.com", true},
		{"bob.smith-1@sub.example.co.uk", "bob.smith-1", "sub.example.co.uk", true},
		{"tips+nostr@getalby.com", "tips+nostr", "getalby.com", true},
		{"x@xn--bcher-kva.example", "x", "xn--bcher-kva.example", true},
		{"", "", "", false},
		{"bob", "", "", false},
		{"@example.com", "", "", false},
		{"bob@", "", "", false},
		{"bob@localhost", "", "", false},
		{"bob@example.c", "", "", false},
		{"bob@example.123", "", "", false},
		{"bob@-example.com", "", "", false},
		{"bob@exa_mple.com", "", "", false},
		{"bob@example.com:8080", "", "", false},
		{"b ob@example.com", "", "", false},
		{"bøb@example.com", "", "", false},
	}
	for _, tt := range tests {
		name, domain, ok := ParseIdentifier(tt.in)
		if ok != tt.ok || name != tt.name || domain != tt.domain {
			t.Errorf("ParseIdentifier(%q) = %q, %q, %v; want %q, %q, %v", tt.in, name, domain, ok, tt.name, tt.domain, tt.ok)
		}
	}
}
