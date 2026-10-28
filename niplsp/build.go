package niplsp

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
)

// NodeSigner signs with the node key. It is handed SigningPayload's bytes,
// the event's NIP-01 serialization, hashes them with SHA-256 itself and
// returns the 64-byte BIP-340 signature over that hash, which is the event id.
// A Lightning node's Schnorr signing RPC works this way.
type NodeSigner func(ctx context.Context, payload []byte) (sig []byte, err error)

// normalize checks every field an announcement carries, except the
// expiration's distance from created_at, and returns them with the node key in
// x-only form and an empty status as open.
func normalize(f Fields) (Fields, error) {
	key, ok := xOnlyNodeKey(f.NodeKey)
	if !ok {
		return f, ErrNodeKey
	}
	f.NodeKey = key
	if f.Status == "" {
		f.Status = StatusOpen
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidFields}, a...)...)
	}

	if len(f.Addrs) == 0 {
		return f, fmt.Errorf("%w: at least one addr", ErrBadAddr)
	}
	for _, a := range f.Addrs {
		if !ValidAddr(a) {
			return f, fmt.Errorf("%w: %q", ErrBadAddr, a)
		}
	}
	if !validChain(f.Chain) {
		return f, bad("chain %q", f.Chain)
	}
	if !validNetwork(f.Network) {
		return f, bad("network %q", f.Network)
	}
	if !f.Status.Valid() {
		return f, bad("status %q", f.Status)
	}
	if f.Expiration < 0 {
		return f, ErrExpiryTooFar
	}

	if len(f.Protocols) == 0 {
		return f, bad("at least one protocol")
	}
	seenProto := map[int]bool{}
	for _, p := range f.Protocols {
		if p < 1 {
			return f, bad("protocol %d", p)
		}
		if seenProto[p] {
			return f, bad("protocol %d twice", p)
		}
		seenProto[p] = true
	}
	if err := checkOptions(f.LSPS1, lsps1Options, seenProto[ProtocolLSPS1], "lsps1"); err != nil {
		return f, err
	}
	if err := checkOptions(f.LSPS5, lsps5Fields, seenProto[ProtocolLSPS5], "lsps5"); err != nil {
		return f, err
	}
	switch {
	case seenProto[ProtocolLSPS2] && len(f.LSPS2) == 0:
		return f, ErrNoFeeRow
	case !seenProto[ProtocolLSPS2] && len(f.LSPS2) > 0:
		return f, fmt.Errorf("%w: lsps2_fee without protocol 2", ErrProtocolGating)
	}

	d := f.Display
	if n := countChars(f.Display.Content); n > MaxContent {
		return f, fmt.Errorf("%w: %d characters", ErrContentTooLong, n)
	}
	if d.Website != "" && !validHTTPS(d.Website) {
		return f, fmt.Errorf("%w: website %q", ErrNotHTTPS, d.Website)
	}
	if d.Image != "" && !validHTTPS(d.Image) {
		return f, fmt.Errorf("%w: image %q", ErrNotHTTPS, d.Image)
	}
	if op := d.Operator; op != nil {
		if !validLowerHex64(op.Pubkey) {
			return f, bad("operator pubkey %q", op.Pubkey)
		}
		if op.Relay != "" && !validRelay(op.Relay) {
			return f, bad("operator relay %q", op.Relay)
		}
	}
	seenLang := map[string]bool{}
	for _, l := range d.Languages {
		if !validLanguage(l) || seenLang[l] {
			return f, bad("language %q", l)
		}
		seenLang[l] = true
	}
	for _, r := range f.Relays {
		if !validRelay(r) {
			return f, bad("relay %q", r)
		}
	}
	return f, nil
}

// checkOptions checks lsps1 options or lsps5 fields: present only with their
// protocol, each named once, known ones in their form and unknown ones with a
// plain name and a number or boolean.
func checkOptions(opts []Option, table []knownOption, protocol bool, tag string) error {
	if len(opts) > 0 && !protocol {
		return fmt.Errorf("%w: %s without its protocol", ErrProtocolGating, tag)
	}
	seen := map[string]bool{}
	for _, o := range opts {
		if seen[o.Name] {
			return fmt.Errorf("%w: %s %q", ErrDuplicateOption, tag, o.Name)
		}
		seen[o.Name] = true
		k, known := lookupOption(table, o.Name)
		if !validOptionName(o.Name) || !validValue(k, known, o.Value) {
			return fmt.Errorf("%w: %s %q = %q", ErrInvalidFields, tag, o.Name, o.Value)
		}
	}
	return nil
}

// buildTags writes the tags in the NIP-LSP example's order.
func buildTags(f Fields) [][]string {
	var tags [][]string
	add := func(t ...string) { tags = append(tags, t) }
	for _, a := range f.Addrs {
		add(TagAddr, a)
	}
	add(TagChain, f.Chain)
	add(TagNetwork, f.Network)
	add(TagStatus, string(f.Status))
	add(TagExpiration, strconv.FormatInt(f.Expiration, 10))
	for _, p := range f.Protocols {
		add(TagProtocol, strconv.Itoa(p))
	}
	for _, o := range f.LSPS1 {
		add(TagLSPS1, o.Name, o.Value)
	}
	for _, r := range f.LSPS2 {
		t := []string{TagLSPS2Fee}
		for _, v := range r.values() {
			t = append(t, strconv.FormatUint(v, 10))
		}
		add(t...)
	}
	for _, o := range f.LSPS5 {
		add(TagLSPS5, o.Name, o.Value)
	}
	d := f.Display
	if d.Title != "" {
		add(TagTitle, d.Title)
	}
	if d.Website != "" {
		add(TagWebsite, d.Website)
	}
	if d.Image != "" {
		add(TagImage, d.Image)
	}
	if op := d.Operator; op != nil {
		if op.Relay != "" {
			add(TagOperator, op.Pubkey, op.Relay)
		} else {
			add(TagOperator, op.Pubkey)
		}
	}
	if len(d.Languages) > 0 {
		add(TagLabelNS, LanguageNamespace)
		for _, l := range d.Languages {
			add(TagLabel, l, LanguageNamespace)
		}
	}
	if d.Title != "" {
		add(TagAlt, AltPrefix+": "+d.Title)
	} else {
		add(TagAlt, AltPrefix)
	}
	for _, r := range f.Relays {
		add(TagRelay, r)
	}
	return tags
}

// NewAnnouncement builds the unsigned kind 10735 event for f, created at
// createdAt (unix seconds), with its id set and its tags in the NIP's order:
// addr, n, network, status, expiration, protocol, lsps1, lsps2_fee, lsps5,
// title, website, image, p, L and l, alt (AltPrefix, then ": " and the title
// when there is one) and r. The node key signs it (SigningPayload, Sign).
//
// It refuses an expiration not after createdAt or more than MaxExpirySecs
// after it (ErrExpiryTooFar; 0 means exactly MaxExpirySecs), protocol 2
// without a fee row (ErrNoFeeRow), step data without its protocol
// (ErrProtocolGating), an option or field given twice (ErrDuplicateOption), a
// website or image that is not https (ErrNotHTTPS), a malformed addr
// (ErrBadAddr), content over MaxContent characters (ErrContentTooLong) and any
// other malformed value (ErrInvalidFields, ErrNodeKey).
func NewAnnouncement(f Fields, createdAt int64) (*nip01.Event, error) {
	if createdAt < 0 {
		return nil, fmt.Errorf("%w: created_at %d", ErrInvalidFields, createdAt)
	}
	f, err := normalize(f)
	if err != nil {
		return nil, err
	}
	if f.Expiration == 0 {
		f.Expiration = createdAt + MaxExpirySecs
	}
	if f.Expiration <= createdAt || f.Expiration-createdAt > MaxExpirySecs {
		return nil, fmt.Errorf("%w: expiration %d, created_at %d", ErrExpiryTooFar, f.Expiration, createdAt)
	}

	ev := nip01.NewUnsignedEvent(Kind, f.NodeKey, f.Display.Content, buildTags(f)...)
	ev.CreatedAt = uint64(createdAt)
	id, err := ev.HashID()
	if err != nil {
		return nil, fmt.Errorf("niplsp: compute the event id: %w", err)
	}
	ev.ID = hex.EncodeToString(id)
	if err := checkBuilt(ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// SigningPayload is what the node signer is handed: the event's NIP-01
// serialization, whose SHA-256 is the event id. It refuses any kind but 10735
// (ErrWrongKind), so that the node key signs no other Nostr event (NIP-LSP
// §Security Considerations), a pubkey that is not 64 lowercase hex, and an id
// that is set but is not the event's own hash.
func SigningPayload(ev *nip01.Event) ([]byte, error) {
	if ev == nil {
		return nil, fmt.Errorf("%w: no event", ErrInvalidFields)
	}
	if ev.Kind != Kind {
		return nil, fmt.Errorf("%w: kind %d", ErrWrongKind, ev.Kind)
	}
	if !validLowerHex64(ev.PubKey) {
		return nil, fmt.Errorf("%w: pubkey %q", ErrNodeKey, ev.PubKey)
	}
	payload, err := ev.Serialize()
	if err != nil {
		return nil, fmt.Errorf("niplsp: serialize the event: %w", err)
	}
	if ev.ID != "" {
		id, err := ev.HashID()
		if err != nil || hex.EncodeToString(id) != ev.ID {
			return nil, fmt.Errorf("%w: the id is not the event's hash", ErrInvalidFields)
		}
	}
	return payload, nil
}

// Sign has signer sign ev with the node key: it hands it SigningPayload(ev),
// sets ev's id and signature, and verifies the signature against ev's pubkey
// (ErrSignature when it does not verify; ev is then left unsigned).
func Sign(ctx context.Context, ev *nip01.Event, signer NodeSigner) error {
	payload, err := SigningPayload(ev)
	if err != nil {
		return err
	}
	if signer == nil {
		return fmt.Errorf("%w: no signer", ErrSignature)
	}
	sig, err := signer(ctx, payload)
	if err != nil {
		return fmt.Errorf("niplsp: node signer: %w", err)
	}
	id, err := ev.HashID()
	if err != nil {
		return fmt.Errorf("niplsp: compute the event id: %w", err)
	}
	ev.ID = hex.EncodeToString(id)
	ev.Sig = hex.EncodeToString(sig)
	if len(sig) != 64 || ev.Verify(nip01.WithoutPowCheck()) != nil {
		ev.Sig = ""
		return ErrSignature
	}
	return nil
}
