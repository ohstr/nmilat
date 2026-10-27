// Package niplsp implements NIP-LSP, the Lightning Service Provider
// Announcement: one replaceable kind 10735 event, signed by a Lightning node's
// key, that advertises the LSPS services the node sells and their parameters.
//
// A publisher builds its Fields from its own live LSPS answers
// (FromLSPSInfo), turns them into an unsigned event (NewAnnouncement) and has
// its node sign the event's serialization (SigningPayload, or Sign with an
// injected NodeSigner). This package never holds a node key.
//
// A client checks an announcement with ParseAnnouncement, which runs NIP-LSP
// §Client Behavior steps 1-5 in order and reports the first failure as an
// *AnnouncementError. Seen and Newest keep only the newest announcement of each
// node and never fall back to an older one. NodeIDs gives the two node id
// candidates, and CheckLive compares an announcement with the node's live LSPS
// answers, which always decide.
//
// The announcement only advertises: title, content and website are the LSP's
// claims, never verified facts. DisplayTitle and DisplayContent give the
// stripped, capped text a client may show.
//
// Spec: https://github.com/ohstr/nips/blob/main/NIP-LSP.md
package niplsp

import "errors"

// Kind is the Lightning Service Provider Announcement (replaceable).
const Kind = 10735

const (
	// MaxExpirySecs is how far after created_at an announcement's expiration
	// may lie: 30 days (NIP-LSP §The Announcement, §Client Behavior step 4).
	MaxExpirySecs = 30 * 24 * 60 * 60
	// MaxTitle is the display cap of title, in user-perceived characters, on
	// one line (NIP-LSP §Client Behavior).
	MaxTitle = 40
	// MaxContent is the cap of content, in user-perceived characters: a
	// publisher refuses more, a client cuts what it shows there.
	MaxContent = 280
	// LanguageNamespace is the NIP-32 namespace of the language labels.
	LanguageNamespace = "ISO-639-1"
	// AltPrefix starts the NIP-31 alt text; the title, when there is one,
	// follows after ": ".
	AltPrefix = "Lightning service provider"
)

// Status is an announcement's status tag.
type Status string

// The three statuses (NIP-LSP §The Announcement).
const (
	// StatusOpen sells as announced.
	StatusOpen Status = "open"
	// StatusPaused takes no new orders for now.
	StatusPaused Status = "paused"
	// StatusClosed has stopped selling; a client does not show it.
	StatusClosed Status = "closed"
)

// Valid reports one of the three statuses.
func (s Status) Valid() bool {
	return s == StatusOpen || s == StatusPaused || s == StatusClosed
}

// The LSPS protocol numbers that carry step data in an announcement.
const (
	ProtocolLSPS1 = 1
	ProtocolLSPS2 = 2
	ProtocolLSPS5 = 5
)

// Tag names (NIP-LSP §The Announcement).
const (
	TagAddr       = "addr"
	TagChain      = "n"
	TagNetwork    = "network"
	TagStatus     = "status"
	TagExpiration = "expiration"
	TagProtocol   = "protocol"
	TagLSPS1      = "lsps1"
	TagLSPS2Fee   = "lsps2_fee"
	TagLSPS5      = "lsps5"
	TagTitle      = "title"
	TagWebsite    = "website"
	TagImage      = "image"
	TagOperator   = "p"
	TagLabelNS    = "L"
	TagLabel      = "l"
	TagAlt        = "alt"
	TagRelay      = "r"
)

var (
	// ErrNodeKey is a node key that is neither 64 hex characters (x-only)
	// nor 66 starting 02 or 03 (a node id).
	ErrNodeKey = errors.New("niplsp: the node key is 64 hex characters, or a 66-character node id starting 02 or 03")
	// ErrExpiryTooFar is an expiration more than MaxExpirySecs after
	// created_at, or not after it.
	ErrExpiryTooFar = errors.New("niplsp: expiration must be after created_at and at most 30 days after it")
	// ErrNoFeeRow is protocol 2 announced without an lsps2_fee row.
	ErrNoFeeRow = errors.New("niplsp: protocol 2 needs at least one lsps2_fee row")
	// ErrDuplicateOption is an lsps1 option or lsps5 field given twice.
	ErrDuplicateOption = errors.New("niplsp: an lsps1 option or lsps5 field appears twice")
	// ErrProtocolGating is lsps1, lsps2_fee or lsps5 data without its
	// protocol (1, 2 or 5).
	ErrProtocolGating = errors.New("niplsp: LSPS step data without its protocol")
	// ErrNotHTTPS is a website or image that is not an https URL.
	ErrNotHTTPS = errors.New("niplsp: website and image must be https URLs")
	// ErrBadAddr is an addr that is not host:port with an IPv4 address, a
	// bracketed IPv6 address or an onion address as the host.
	ErrBadAddr = errors.New("niplsp: addr must be host:port with an IPv4, bracketed IPv6 or onion host")
	// ErrContentTooLong is content over MaxContent characters.
	ErrContentTooLong = errors.New("niplsp: content is at most 280 characters")
	// ErrInvalidFields is any other value an announcement cannot carry.
	ErrInvalidFields = errors.New("niplsp: invalid announcement fields")
	// ErrWrongKind is an event of another kind handed to the signing path:
	// the node key signs only kind 10735 (NIP-LSP §Security Considerations).
	ErrWrongKind = errors.New("niplsp: the node key signs only kind 10735")
	// ErrSignature is a signature from a NodeSigner that does not verify
	// against the event's pubkey.
	ErrSignature = errors.New("niplsp: the node signer's signature does not verify")
	// ErrLSPSAnswer is an LSPS answer FromLSPSInfo or a Parse* helper cannot
	// read.
	ErrLSPSAnswer = errors.New("niplsp: malformed LSPS answer")
	// ErrMissingLSPSAnswer is a protocol listed without the LSPS answer its
	// step data comes from (LSPS1 get_info for 1, LSPS2 get_info for 2).
	ErrMissingLSPSAnswer = errors.New("niplsp: a listed protocol's LSPS answer is missing")
	// ErrNotNewer is an announcement no newer than the newest seen for its
	// node (NIP-LSP §Client Behavior, newest only).
	ErrNotNewer = errors.New("niplsp: not newer than the newest announcement seen for this node")
	// ErrNoUsable is a node whose newest announcement failed a check, has
	// expired, or is unknown: there is no fallback to an older one.
	ErrNoUsable = errors.New("niplsp: no usable announcement for this node")
)
