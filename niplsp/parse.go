package niplsp

import (
	"fmt"
	"slices"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// CheckOptions are the client's side of the checks.
type CheckOptions struct {
	// Chains are the chain names (n) the client uses; empty accepts none.
	Chains []string
	// Networks are the networks the client uses; empty accepts none.
	Networks []string
	// Now is the time to check expiration against, unix seconds; 0 means the
	// clock.
	Now int64
}

func (o CheckOptions) now() int64 {
	if o.Now != 0 {
		return o.Now
	}
	return time.Now().Unix()
}

// AnnouncementError is the first check an announcement failed: Step is the
// NIP-LSP §Client Behavior step, 1 to 5. The client ignores the announcement.
type AnnouncementError struct {
	Step   int
	Reason string
}

func (e *AnnouncementError) Error() string {
	return fmt.Sprintf("niplsp: announcement fails step %d: %s", e.Step, e.Reason)
}

func stepErr(step int, format string, a ...any) *AnnouncementError {
	return &AnnouncementError{Step: step, Reason: fmt.Sprintf(format, a...)}
}

// Announcement is an announcement that passed every check. Its Fields hold
// what a client reads: unknown tags, unknown lsps1 options and lsps5 fields,
// and step data whose protocol is missing are not in them. Display text is
// the LSP's claim, raw; show it through DisplayTitle and DisplayContent.
type Announcement struct {
	Event     *nip01.Event
	CreatedAt int64
	Fields
}

// NodeIDs are the two node ids the announcement's key can stand for.
func (a *Announcement) NodeIDs() [2]string { return NodeIDs(a.NodeKey) }

// Shown reports whether a client shows the announcement: not when closed.
func (a *Announcement) Shown() bool { return a.Status != StatusClosed }

// Selling reports whether a client offers anything new through it: only when
// open, never when paused or closed.
func (a *Announcement) Selling() bool { return a.Status == StatusOpen }

// Expired reports whether the expiration has passed at now (unix seconds).
func (a *Announcement) Expired(now int64) bool { return now > a.Expiration }

// DisplayTitle is the title as a client may show it: control, zero-width and
// bidirectional characters and check-mark look-alikes stripped, on one line,
// at most MaxTitle characters. It is the LSP's claim, never a verified fact;
// show the node id next to it.
func (a *Announcement) DisplayTitle() string { return sanitizeText(a.Display.Title, MaxTitle, true) }

// DisplayContent is the content as a client may show it: stripped like
// DisplayTitle, line breaks kept, at most MaxContent characters. Render no
// links in it.
func (a *Announcement) DisplayContent() string {
	return sanitizeText(a.Display.Content, MaxContent, false)
}

// counts are NIP-LSP's tag counts: exactly one, at least one, at most one.
var (
	exactlyOne = []string{TagChain, TagNetwork, TagStatus, TagExpiration}
	atLeastOne = []string{TagAddr, TagProtocol}
	atMostOne  = []string{TagTitle, TagWebsite, TagImage, TagOperator, TagAlt}
)

// ParseAnnouncement checks ev as NIP-LSP §Client Behavior orders, and returns
// the first failure as an *AnnouncementError:
//
//  1. the kind is 10735 and the signature verifies against pubkey (the id is
//     the event's hash, the pubkey 64 lowercase hex);
//  2. n, network, status and expiration are present once, addr and protocol
//     at least once, title, website, image, p and alt at most once, and an
//     announcement with protocol 2 has an lsps2_fee tag;
//  3. every value has its form (addr, chain name, network, status, unsigned
//     decimals and booleans, six lsps2_fee positions, https website and image,
//     p, ISO-639-1 labels, ws or wss relays), and no lsps1 option or lsps5
//     field appears twice;
//  4. expiration has not passed at o.Now and is at most MaxExpirySecs after
//     created_at;
//  5. n is in o.Chains and network in o.Networks.
//
// It ignores tags NIP-LSP does not define, L and l tags of another namespace,
// lsps1 options and lsps5 fields it does not know, and every lsps1, lsps2_fee
// or lsps5 tag whose protocol is missing. Content longer than MaxContent is
// not refused; DisplayContent cuts it.
//
// A closed or paused announcement parses; see Shown and Selling. Use Seen to
// keep only the newest announcement of each node.
func ParseAnnouncement(ev *nip01.Event, o CheckOptions) (*Announcement, error) {
	if err := checkSignature(ev); err != nil {
		return nil, err
	}
	f, err := readTags(ev)
	if err != nil {
		return nil, err
	}
	created := int64(ev.CreatedAt) //nolint:gosec // event timestamps are seconds
	if now := o.now(); now > f.Expiration {
		return nil, stepErr(4, "expired at %d, now %d", f.Expiration, now)
	}
	if f.Expiration-created > MaxExpirySecs {
		return nil, stepErr(4, "expiration %d is more than 30 days after created_at %d", f.Expiration, created)
	}
	if !slices.Contains(o.Chains, f.Chain) {
		return nil, stepErr(5, "chain %q is not one the client uses", f.Chain)
	}
	if !slices.Contains(o.Networks, f.Network) {
		return nil, stepErr(5, "network %q is not one the client uses", f.Network)
	}
	return &Announcement{Event: ev, CreatedAt: created, Fields: f}, nil
}

// checkSignature is step 1.
func checkSignature(ev *nip01.Event) error {
	switch {
	case ev == nil:
		return stepErr(1, "no event")
	case ev.Kind != Kind:
		return stepErr(1, "kind %d", ev.Kind)
	case !validLowerHex64(ev.PubKey):
		return stepErr(1, "pubkey is not 64 lowercase hex")
	}
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return stepErr(1, "signature: %v", err)
	}
	return nil
}

// readTags runs steps 2 and 3 and returns what the tags hold.
func readTags(ev *nip01.Event) (Fields, error) {
	var f Fields
	f.NodeKey = ev.PubKey
	f.Display.Content = ev.Content

	// Step 2: counts.
	count := map[string]int{}
	protocol2 := false
	for _, tag := range ev.Tags {
		if len(tag) == 0 {
			continue
		}
		count[tag[0]]++
		if tag[0] == TagProtocol && len(tag) >= 2 && tag[1] == "2" {
			protocol2 = true
		}
	}
	for _, name := range exactlyOne {
		if count[name] != 1 {
			return f, stepErr(2, "%d %s tags, want exactly 1", count[name], name)
		}
	}
	for _, name := range atLeastOne {
		if count[name] == 0 {
			return f, stepErr(2, "no %s tag", name)
		}
	}
	for _, name := range atMostOne {
		if count[name] > 1 {
			return f, stepErr(2, "%d %s tags, want at most 1", count[name], name)
		}
	}
	if protocol2 && count[TagLSPS2Fee] == 0 {
		return f, stepErr(2, "protocol 2 without an lsps2_fee tag")
	}

	// Step 3: forms. The protocols come first: they decide which step data
	// is read at all.
	protocols := map[int]bool{}
	for _, tag := range ev.Tags {
		if len(tag) == 0 || tag[0] != TagProtocol {
			continue
		}
		v, ok := uintValue(tag)
		if !ok || v > uint64(^uint32(0)) {
			return f, stepErr(3, "protocol %q", tag)
		}
		if p := int(v); !protocols[p] {
			protocols[p] = true
			f.Protocols = append(f.Protocols, p)
		}
	}
	seen1, seen5 := map[string]bool{}, map[string]bool{}
	for _, tag := range ev.Tags {
		if len(tag) == 0 {
			continue
		}
		if err := readTag(&f, tag, protocols, seen1, seen5); err != nil {
			return f, err
		}
	}
	return f, nil
}

// readTag checks one tag's form (step 3) and records what it holds.
func readTag(f *Fields, tag []string, protocols map[int]bool, seen1, seen5 map[string]bool) error {
	value := ""
	if len(tag) >= 2 {
		value = tag[1]
	}
	bad := func() error { return stepErr(3, "malformed %s tag %q", tag[0], tag) }
	switch tag[0] {
	case TagAddr:
		if !ValidAddr(value) {
			return bad()
		}
		f.Addrs = append(f.Addrs, value)
	case TagChain:
		if !validChain(value) {
			return bad()
		}
		f.Chain = value
	case TagNetwork:
		if !validNetwork(value) {
			return bad()
		}
		f.Network = value
	case TagStatus:
		if !Status(value).Valid() {
			return bad()
		}
		f.Status = Status(value)
	case TagExpiration:
		v, ok := uintValue(tag)
		if !ok || v > 1<<62 {
			return bad()
		}
		f.Expiration = int64(v)
	case TagLSPS1:
		if !protocols[ProtocolLSPS1] {
			return nil
		}
		o, keep, err := readOption(tag, lsps1Options, seen1)
		if err != nil {
			return err
		}
		if keep {
			f.LSPS1 = append(f.LSPS1, o)
		}
	case TagLSPS5:
		if !protocols[ProtocolLSPS5] {
			return nil
		}
		o, keep, err := readOption(tag, lsps5Fields, seen5)
		if err != nil {
			return err
		}
		if keep {
			f.LSPS5 = append(f.LSPS5, o)
		}
	case TagLSPS2Fee:
		if !protocols[ProtocolLSPS2] {
			return nil
		}
		if len(tag) < 7 {
			return bad()
		}
		var v [6]uint64
		for i := range v {
			n, ok := canonicalUint(tag[1+i])
			if !ok {
				return bad()
			}
			v[i] = n
		}
		f.LSPS2 = append(f.LSPS2, FeeRow{v[0], v[1], v[2], v[3], v[4], v[5]})
	case TagTitle:
		if len(tag) < 2 {
			return bad()
		}
		f.Display.Title = value
	case TagWebsite:
		if !validHTTPS(value) {
			return bad()
		}
		f.Display.Website = value
	case TagImage:
		if !validHTTPS(value) {
			return bad()
		}
		f.Display.Image = value
	case TagOperator:
		op := &Operator{Pubkey: value}
		if len(tag) >= 3 {
			op.Relay = tag[2]
		}
		if !validLowerHex64(op.Pubkey) || (op.Relay != "" && !validRelay(op.Relay)) {
			return bad()
		}
		f.Display.Operator = op
	case TagLabel:
		if len(tag) < 3 || tag[2] != LanguageNamespace {
			return nil // a label of another namespace
		}
		if !validLanguage(value) {
			return bad()
		}
		if !slices.Contains(f.Display.Languages, value) {
			f.Display.Languages = append(f.Display.Languages, value)
		}
	case TagRelay:
		if !validRelay(value) {
			return bad()
		}
		f.Relays = append(f.Relays, value)
	}
	// L, alt and every tag NIP-LSP does not define: nothing to read.
	return nil
}

// readOption reads an lsps1 or lsps5 tag: a name and a value, each name once;
// a known one of its form, an unknown one skipped (keep false).
func readOption(tag []string, table []knownOption, seen map[string]bool) (Option, bool, error) {
	if len(tag) < 3 || tag[1] == "" {
		return Option{}, false, stepErr(3, "malformed %s tag %q", tag[0], tag)
	}
	o := Option{Name: tag[1], Value: tag[2]}
	if seen[o.Name] {
		return o, false, stepErr(3, "%s %q appears twice", tag[0], o.Name)
	}
	seen[o.Name] = true
	k, known := lookupOption(table, o.Name)
	if !known {
		return o, false, nil
	}
	if !validValue(k, true, o.Value) {
		return o, false, stepErr(3, "malformed %s tag %q", tag[0], tag)
	}
	return o, true, nil
}

func uintValue(tag []string) (uint64, bool) {
	if len(tag) < 2 {
		return 0, false
	}
	return canonicalUint(tag[1])
}

// checkBuilt runs steps 2 and 3 on an event NewAnnouncement built, so that it
// never hands out one a client would ignore.
func checkBuilt(ev *nip01.Event) error {
	if _, err := readTags(ev); err != nil {
		return fmt.Errorf("niplsp: built an announcement a client would ignore: %w", err)
	}
	return nil
}
