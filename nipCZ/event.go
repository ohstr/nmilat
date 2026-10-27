package nipCZ

import (
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
)

// Identity is a p or P tag's identity (NIP-CZ §Identity Tags): a Nostr pubkey
// when Platform is "", else a ConnectionKey on that platform. Value is 64
// lowercase hex either way.
type Identity struct{ Value, Platform string }

// IsConnectionKey reports an identity on a platform, not a Nostr pubkey.
func (i Identity) IsConnectionKey() bool { return i.Platform != "" }

func (i Identity) tag(name string) []string {
	if i.Platform == "" {
		return []string{name, i.Value}
	}
	return []string{name, i.Value, i.Platform}
}

// valid reports a 64-lowercase-hex value and either no platform or a valid
// platform name other than "nostr" (a pubkey is written with Platform "").
func (i Identity) valid() bool {
	return isLowerHex(i.Value, 64) && (i.Platform == "" ||
		(i.Platform != "nostr" && nipIC.ValidPlatformName(nipIC.WebIdentity(i.Platform))))
}

// PubkeyIdentity is a Nostr pubkey recipient, 64 lowercase hex, never
// lowercased for the caller.
func PubkeyIdentity(pubkey string) (Identity, error) {
	if !isLowerHex(pubkey, 64) {
		return Identity{}, ErrIdentity
	}
	return Identity{Value: pubkey}, nil
}

// IdentityFromTyped derives a ConnectionKey from typed input, only for a
// platform with a canonical form in NIP-IC (nipIC.ErrTypedInputNotCanonical
// otherwise: that key comes from the recipient's attestation or nconnection).
func IdentityFromTyped(platform nipIC.WebIdentity, typed string) (Identity, error) {
	key, err := nipIC.NewConnectionKey(platform, typed)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Value: string(key), Platform: string(platform)}, nil
}

// IdentityFromAttestation is the ConnectionKey a recipient's 35522 attests,
// byte for byte, and the IA that attested it (the ia to name).
func IdentityFromAttestation(att *nipIC.Attestation) (id Identity, ia string, err error) {
	if att == nil || att.Event == nil {
		return Identity{}, "", ErrIdentity
	}
	id = Identity{Value: string(att.ConnectionKey), Platform: string(att.Platform)}
	if !id.valid() {
		return Identity{}, "", ErrIdentity
	}
	return id, att.PubKey, nil
}

// IdentityFromNConnection is the ConnectionKey an nconnection carries, byte for
// byte, and its relays (TLV 1), where the recipient reads.
func IdentityFromNConnection(s string) (id Identity, relays []string, err error) {
	key, relays, platform, err := nipIC.DecodeNConnection(s)
	if err != nil {
		return Identity{}, nil, err
	}
	id = Identity{Value: string(key), Platform: string(platform)}
	if !id.valid() || platform == "" {
		return Identity{}, nil, ErrIdentity
	}
	return id, relays, nil
}

// parseIdentity reads a p or P tag: [1] 64 lowercase hex, never lowercased;
// [2] missing, empty or "nostr" is a pubkey, else a platform name.
func parseIdentity(tag []string) (Identity, bool) {
	if len(tag) < 2 || !isLowerHex(tag[1], 64) {
		return Identity{}, false
	}
	id := Identity{Value: tag[1]}
	if len(tag) > 2 && tag[2] != "" && tag[2] != "nostr" {
		if !nipIC.ValidPlatformName(nipIC.WebIdentity(tag[2])) {
			return Identity{}, false
		}
		id.Platform = tag[2]
	}
	return id, true
}

// CashZap is a parsed kind 9522 (NIP-CZ §Kind 9522). Fields are the tags as
// written; IssuedAt and ExpiresAt are nil when absent (ExpiresAt 0 = never).
type CashZap struct {
	Event     *nip01.Event
	Recipient Identity
	// Sender is the P tag, always a ConnectionKey; nil without one.
	Sender      *Identity
	Amount      uint64
	Chain, Cash string
	Token       nipcash.Token
	// IA is the Identity Authority named for a ConnectionKey recipient.
	W, IA, E, A, K      string
	IssuedAt, ExpiresAt *uint64
	// HasExpirationTag is a NIP-40 expiration tag, which a 9522 MUST NOT carry:
	// the zap is listed, never counted.
	HasExpirationTag bool
}

// decodeToken is nipcash.Decode, replaceable by tests that count decodes.
var decodeToken = nipcash.Decode

// ParseCashZap verifies a 9522's signature (rule 1) before reading any tag,
// then applies rules 2 and 3: tag cardinality and forms, the token decoding,
// and w equal to the token's TLV 0. A failure is a *RuleError.
func ParseCashZap(ev *nip01.Event) (*CashZap, error) {
	if ev == nil || ev.Kind != KindCashZap {
		return nil, ErrWrongKind
	}
	if err := ev.Verify(); err != nil {
		return nil, ruleErr(1, "signature: %v", err)
	}
	z, rerr := parseCashZap(ev)
	if rerr != nil {
		return nil, rerr
	}
	return z, nil
}

// singleValued are the tags whose count rule 2 checks.
var singleValued = map[string]bool{
	"p": true, "P": true, "amount": true, "chain": true, "cash": true, "w": true, "ia": true,
	"e": true, "a": true, "k": true, "issued_at": true, "expires_at": true,
}

// parseCashZap is rules 2 and 3 on an event whose signature already verified.
func parseCashZap(ev *nip01.Event) (*CashZap, *RuleError) {
	z := &CashZap{Event: ev}
	vals := map[string][]string{}
	tags := map[string][]string{}
	for _, t := range ev.Tags {
		if len(t) == 0 {
			continue
		}
		if t[0] == "expiration" {
			z.HasExpirationTag = true
			continue
		}
		if !singleValued[t[0]] {
			continue
		}
		if len(t) < 2 {
			return nil, ruleErr(2, "%s tag has no value", t[0])
		}
		vals[t[0]] = append(vals[t[0]], t[1])
		tags[t[0]] = t
	}
	for _, name := range []string{"p", "amount", "chain", "cash", "w"} {
		if len(vals[name]) != 1 {
			return nil, ruleErr(2, "%d %s tags, want exactly one", len(vals[name]), name)
		}
	}
	for _, name := range []string{"P", "e", "a", "k", "issued_at", "expires_at", "ia"} {
		if len(vals[name]) > 1 {
			return nil, ruleErr(2, "%d %s tags, want at most one", len(vals[name]), name)
		}
	}
	p, ok := parseIdentity(tags["p"])
	if !ok {
		return nil, ruleErr(2, "p is not 64 lowercase hex with a valid platform")
	}
	z.Recipient = p
	if p.IsConnectionKey() != (len(vals["ia"]) == 1) {
		return nil, ruleErr(2, "ia is present exactly when p is a ConnectionKey")
	}
	if len(vals["ia"]) == 1 {
		if vals["ia"][0] == "" {
			return nil, ruleErr(2, "ia is empty")
		}
		z.IA = vals["ia"][0]
	}
	if t, ok := tags["P"]; ok {
		s, ok := parseIdentity(t)
		if !ok {
			return nil, ruleErr(2, "P is not 64 lowercase hex with a valid platform")
		}
		if !s.IsConnectionKey() {
			return nil, ruleErr(2, "P is a ConnectionKey, never a Nostr pubkey")
		}
		z.Sender = &s
	}
	amount, ok := parseDecimal(vals["amount"][0])
	if !ok || amount == 0 {
		return nil, ruleErr(2, "amount is not a positive integer without leading zeros")
	}
	z.Amount = amount
	z.Chain, z.Cash, z.W = vals["chain"][0], vals["cash"][0], vals["w"][0]
	if z.Chain == "" {
		return nil, ruleErr(2, "chain is empty")
	}
	if !isLowerHex(z.W, 64) {
		return nil, ruleErr(2, "w is not 64 lowercase hex")
	}
	for _, name := range []string{"issued_at", "expires_at"} {
		if len(vals[name]) == 0 {
			continue
		}
		n, ok := parseDecimal(vals[name][0])
		if !ok {
			return nil, ruleErr(2, "%s is not unsigned decimal without leading zeros", name)
		}
		if name == "issued_at" {
			z.IssuedAt = &n
		} else {
			z.ExpiresAt = &n
		}
	}
	if len(vals["e"]) == 1 {
		if z.E = vals["e"][0]; z.E == "" {
			return nil, ruleErr(2, "e is empty")
		}
	}
	if len(vals["a"]) == 1 {
		if z.A = vals["a"][0]; z.A == "" {
			return nil, ruleErr(2, "a is empty")
		}
	}
	if len(vals["k"]) == 1 {
		z.K = vals["k"][0]
	}
	if z.E != "" && z.A != "" {
		_, author, _, ok := parseCoordinate(z.A)
		if !ok || author != z.Recipient.Value {
			return nil, ruleErr(2, "e and a do not name the same event")
		}
	}

	tok, err := decodeToken(z.Cash)
	if err != nil {
		return nil, ruleErr(3, "cash does not decode: %v", err)
	}
	z.Token = tok
	if tok.WalletPubkey != z.W {
		return nil, ruleErr(2, "w is not the token's wallet pubkey (TLV 0)")
	}
	if tok.Scheme == nipcash.SchemeZapV1 && (z.IssuedAt == nil || z.ExpiresAt == nil) {
		return nil, ruleErr(2, "a token with TLV 8 = 2 needs issued_at and expires_at")
	}
	return z, nil
}

// parseCoordinate splits "<kind>:<pubkey>:<d>"; d is the whole rest and may
// itself contain ':'.
func parseCoordinate(a string) (kind int, pubkey, d string, ok bool) {
	parts := strings.SplitN(a, ":", 3)
	if len(parts) != 3 || !isLowerHex(parts[1], 64) {
		return 0, "", "", false
	}
	k, okk := parseDecimal(parts[0])
	if !okk || k > 65535 {
		return 0, "", "", false
	}
	return int(k), parts[1], parts[2], true
}

// ZapTargetFor is the zap_target of a target event: an addressable event's
// coordinate "<kind>:<pubkey>:<d>" (its first d tag, byte for byte, "" when it
// has none), else its id.
func ZapTargetFor(target *nip01.Event) (string, error) {
	if target == nil {
		return "", ErrNoTarget
	}
	if target.Kind >= 30000 && target.Kind < 40000 {
		d := ""
		for _, t := range target.Tags {
			if len(t) >= 2 && t[0] == "d" {
				d = t[1]
				break
			}
		}
		return strconv.Itoa(target.Kind) + ":" + target.PubKey + ":" + d, nil
	}
	if !isLowerHex(target.ID, 64) {
		return "", ErrNoTarget
	}
	return target.ID, nil
}

// ZapContextFromEvent rebuilds the cash-zap:v1 context of a Cash Zap: its p as
// recipient, its signer as sender, its a tag (else its e tag) as target, and
// its issued_at and expires_at.
func ZapContextFromEvent(z *CashZap) (nipcash.ZapContext, error) {
	if z == nil || z.Event == nil {
		return nipcash.ZapContext{}, ErrNoTarget
	}
	if z.Recipient.IsConnectionKey() {
		return nipcash.ZapContext{}, ErrNotPubkeyZap
	}
	target := z.A
	if target == "" {
		target = z.E
	}
	if target == "" {
		return nipcash.ZapContext{}, ErrNoTarget
	}
	if z.IssuedAt == nil || z.ExpiresAt == nil {
		return nipcash.ZapContext{}, ErrZapNotSigned
	}
	return nipcash.ZapContext{
		Recipient: z.Recipient.Value, Sender: z.Event.PubKey, ZapTarget: target,
		IssuedAt: *z.IssuedAt, ExpiresAt: *z.ExpiresAt,
	}, nil
}
