package transport

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NormalizeNodeIdentity converts a hub's node pubkey into the x-only form a Nostr
// event author is always in.
//
// This exists because the two ends of the discovery path disagree about shape, and
// the disagreement is invisible until a real relay is involved.
//
// A client is told to anchor trust in the identity recovered from a bill's mint
// signature (§The Hub Announcement). That recovery is ECDSA-recoverable over the
// node's Lightning key and yields a 33-byte COMPRESSED pubkey — 66 hex characters,
// parity byte included. A Nostr event's author is always the 32-byte x-only form —
// 64 hex characters. So the announcement is published under one spelling of the
// same key and looked up under another, and the filter {kinds:[11190],
// authors:[...]} simply returns nothing: the hub looks like it does not offer the
// transport at all, which is exactly what a hub that genuinely does not offer it
// looks like.
//
// Every in-process test passed the x-only key straight in as hubXOnly, so both
// halves were self-consistent and neither could see it. The first live run against
// a real hub and a real relay found it immediately.
//
// A 64-character value is accepted unchanged, so a caller that already holds the
// x-only key is unaffected.
func NormalizeNodeIdentity(pubkeyHex string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(pubkeyHex))
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("nipcash/transport: hub identity %q is not hex: %w", pubkeyHex, err)
	}
	switch len(s) {
	case 64:
		return s, nil
	case 66:
		// The parity byte is what distinguishes a compressed pubkey. Dropping it
		// is the x-only form, which is what BIP340 and Nostr use; the parity is
		// recovered from the curve when verifying, so nothing is lost.
		if s[:2] != "02" && s[:2] != "03" {
			return "", fmt.Errorf("nipcash/transport: hub identity %q is 33 bytes but does not begin 02/03, so it is not a compressed pubkey", pubkeyHex)
		}
		return s[2:], nil
	default:
		return "", fmt.Errorf("nipcash/transport: hub identity must be 64 hex chars (x-only) or 66 (compressed), got %d", len(s))
	}
}
