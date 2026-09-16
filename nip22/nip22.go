// Package nip22 implements NIP-22: Comment, a generic threading note
// (kind:1111) scoped to a root event, addressable event, or NIP-73
// external identifier, with a separate pointer to the specific parent item
// being replied to.
//
// This package is a pure protocol library: event/type construction,
// parsing, and validation, with no relay or network dependency of its own.
// For declaring NIP-22 support to nmilat's relay engine, see the
// nip22/relayreg subpackage. See the nip34 package for a git-specific
// convenience layer built on top of this one (replies to issues, patches,
// and pull requests).
package nip22

import (
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const KindComment = 1111

// Failure modes for the Parse*/Validate*/New* functions below, for callers
// that need to distinguish them (e.g. via errors.Is) rather than match on
// message text.
var (
	ErrWrongKind            = errors.New("nip22: wrong kind")
	ErrInvalidSignature     = errors.New("nip22: invalid signature")
	ErrMissingRootScope     = errors.New("nip22: missing root scope (A/E/I) tag")
	ErrMissingRootKind      = errors.New("nip22: missing K tag")
	ErrMissingParentScope   = errors.New("nip22: missing parent scope (a/e/i) tag")
	ErrMissingParentKind    = errors.New("nip22: missing k tag")
	ErrInvalidPointerTag    = errors.New("nip22: invalid scope pointer tag")
	ErrInvalidPubkeyTag     = errors.New("nip22: invalid pubkey tag")
	ErrMultipleRootScopes   = errors.New("nip22: more than one root scope (A/E/I) tag")
	ErrMultipleParentScopes = errors.New("nip22: more than one parent scope (a/e/i) tag")
)

// PointerType identifies which kind of value a Pointer holds: a
// parameterized-replaceable event address (nip33-style "a"/"A" tags), a
// regular event id ("e"/"E" tags), or a NIP-73 external identifier
// ("i"/"I" tags).
type PointerType int

const (
	PointerEvent PointerType = iota
	PointerAddress
	PointerExternal
)

func (t PointerType) lowerTag() string {
	switch t {
	case PointerAddress:
		return "a"
	case PointerExternal:
		return "i"
	default:
		return "e"
	}
}

func (t PointerType) upperTag() string {
	switch t {
	case PointerAddress:
		return "A"
	case PointerExternal:
		return "I"
	default:
		return "E"
	}
}

// Pointer is a NIP-22 scope reference: an event id, an addressable-event
// address, or a NIP-73 external identifier, plus an optional relay/webpage
// hint. AuthorPubkey is only meaningful for PointerEvent ("e"/"E") tags,
// which the spec permits to carry the referenced event's author as a 4th
// element -- PointerAddress values already embed a pubkey, and
// PointerExternal values have no author.
type Pointer struct {
	Type         PointerType
	Value        string
	RelayHint    string
	AuthorPubkey string
}

// Scope is one side (root or parent) of a Comment: what item it targets,
// that item's kind, and (when known) that item's author. Kind is a plain
// string rather than an int because NIP-73 external items use non-numeric
// kinds (e.g. "web", "podcast:item:guid").
type Scope struct {
	Pointer      Pointer
	Kind         string
	AuthorPubkey string
	AuthorRelay  string
}

// Comment is a parsed kind:1111 comment event.
type Comment struct {
	*nip01.Event
	Root   Scope
	Parent Scope
}

// ParseComment parses and structurally validates a kind:1111 comment
// event.
func ParseComment(event *nip01.Event) (*Comment, error) {
	if event.Kind != KindComment {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindComment)
	}

	c := &Comment{Event: event}
	var haveRootPointer, haveParentPointer bool

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "A", "E", "I":
			if haveRootPointer {
				return nil, ErrMultipleRootScopes
			}
			p, err := parsePointerTag(tag)
			if err != nil {
				return nil, err
			}
			c.Root.Pointer = p
			haveRootPointer = true
		case "a", "e", "i":
			if haveParentPointer {
				return nil, ErrMultipleParentScopes
			}
			p, err := parsePointerTag(tag)
			if err != nil {
				return nil, err
			}
			c.Parent.Pointer = p
			haveParentPointer = true
		case "K":
			c.Root.Kind = tag[1]
		case "k":
			c.Parent.Kind = tag[1]
		case "P":
			c.Root.AuthorPubkey = tag[1]
			if len(tag) > 2 {
				c.Root.AuthorRelay = tag[2]
			}
		case "p":
			c.Parent.AuthorPubkey = tag[1]
			if len(tag) > 2 {
				c.Parent.AuthorRelay = tag[2]
			}
		}
	}

	if !haveRootPointer {
		return nil, ErrMissingRootScope
	}
	if !haveParentPointer {
		return nil, ErrMissingParentScope
	}
	if c.Root.Kind == "" {
		return nil, ErrMissingRootKind
	}
	if c.Parent.Kind == "" {
		return nil, ErrMissingParentKind
	}
	if c.Root.AuthorPubkey != "" {
		if err := utils.Validate32Key(c.Root.AuthorPubkey); err != nil {
			return nil, fmt.Errorf("%w: root author %q: %w", ErrInvalidPubkeyTag, c.Root.AuthorPubkey, err)
		}
	}
	if c.Parent.AuthorPubkey != "" {
		if err := utils.Validate32Key(c.Parent.AuthorPubkey); err != nil {
			return nil, fmt.Errorf("%w: parent author %q: %w", ErrInvalidPubkeyTag, c.Parent.AuthorPubkey, err)
		}
	}

	return c, nil
}

func parsePointerTag(tag []string) (Pointer, error) {
	var t PointerType
	switch tag[0] {
	case "A", "a":
		t = PointerAddress
	case "I", "i":
		t = PointerExternal
	default: // "E", "e"
		t = PointerEvent
	}

	p := Pointer{Type: t, Value: tag[1]}
	if len(tag) > 2 {
		p.RelayHint = tag[2]
	}

	switch t {
	case PointerEvent:
		if err := utils.Validate32Key(p.Value); err != nil {
			return Pointer{}, fmt.Errorf("%w: %q %q: %w", ErrInvalidPointerTag, tag[0], p.Value, err)
		}
		if len(tag) > 3 {
			p.AuthorPubkey = tag[3]
			if err := utils.Validate32Key(p.AuthorPubkey); err != nil {
				return Pointer{}, fmt.Errorf("%w: %q author %q: %w", ErrInvalidPointerTag, tag[0], p.AuthorPubkey, err)
			}
		}
	case PointerAddress:
		if _, _, _, err := utils.ParseATag(p.Value); err != nil {
			return Pointer{}, fmt.Errorf("%w: %q %q: %w", ErrInvalidPointerTag, tag[0], p.Value, err)
		}
	}

	return p, nil
}

// ValidateComment checks the signature and structure of a comment event.
func ValidateComment(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseComment(event)
	return err
}

// PointerParams describes a Pointer to build. Type and Value are required;
// RelayHint and AuthorPubkey (meaningful only for PointerEvent) are
// optional.
type PointerParams struct {
	Type         PointerType
	Value        string
	RelayHint    string
	AuthorPubkey string
}

// ScopeParams describes a Scope to build. Kind is required; Pointer.Value
// is required (root or parent, per which ScopeParams this is).
// AuthorPubkey/AuthorRelay are optional.
type ScopeParams struct {
	Pointer      PointerParams
	Kind         string
	AuthorPubkey string
	AuthorRelay  string
}

// CommentParams describes a comment event to build. Pubkey, Root, and
// Parent are required (pass Parent equal to Root for a top-level comment);
// Content is optional.
type CommentParams struct {
	Pubkey  string
	Content string
	Root    ScopeParams
	Parent  ScopeParams
}

// NewComment builds an unsigned kind:1111 comment event. Caller must sign
// it.
func NewComment(p CommentParams) (*nip01.Event, error) {
	if p.Root.Kind == "" {
		return nil, ErrMissingRootKind
	}
	if p.Parent.Kind == "" {
		return nil, ErrMissingParentKind
	}

	rootTag, err := buildPointerTag(p.Root.Pointer, true)
	if err != nil {
		return nil, err
	}
	parentTag, err := buildPointerTag(p.Parent.Pointer, false)
	if err != nil {
		return nil, err
	}

	tags := [][]string{rootTag, {"K", p.Root.Kind}}
	if p.Root.AuthorPubkey != "" {
		if err := utils.Validate32Key(p.Root.AuthorPubkey); err != nil {
			return nil, fmt.Errorf("%w: root author %q: %w", ErrInvalidPubkeyTag, p.Root.AuthorPubkey, err)
		}
		pt := []string{"P", p.Root.AuthorPubkey}
		if p.Root.AuthorRelay != "" {
			pt = append(pt, p.Root.AuthorRelay)
		}
		tags = append(tags, pt)
	}

	tags = append(tags, parentTag, []string{"k", p.Parent.Kind})
	if p.Parent.AuthorPubkey != "" {
		if err := utils.Validate32Key(p.Parent.AuthorPubkey); err != nil {
			return nil, fmt.Errorf("%w: parent author %q: %w", ErrInvalidPubkeyTag, p.Parent.AuthorPubkey, err)
		}
		pt := []string{"p", p.Parent.AuthorPubkey}
		if p.Parent.AuthorRelay != "" {
			pt = append(pt, p.Parent.AuthorRelay)
		}
		tags = append(tags, pt)
	}

	return nip01.NewUnsignedEvent(KindComment, p.Pubkey, p.Content, tags...), nil
}

func buildPointerTag(p PointerParams, root bool) ([]string, error) {
	if p.Value == "" {
		if root {
			return nil, ErrMissingRootScope
		}
		return nil, ErrMissingParentScope
	}

	switch p.Type {
	case PointerAddress:
		if _, _, _, err := utils.ParseATag(p.Value); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPointerTag, p.Value, err)
		}
	case PointerEvent:
		if err := utils.Validate32Key(p.Value); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPointerTag, p.Value, err)
		}
	}

	var name string
	if root {
		name = p.Type.upperTag()
	} else {
		name = p.Type.lowerTag()
	}
	tag := []string{name, p.Value}

	hasAuthor := p.Type == PointerEvent && p.AuthorPubkey != ""
	if p.RelayHint != "" || hasAuthor {
		tag = append(tag, p.RelayHint)
	}
	if hasAuthor {
		if err := utils.Validate32Key(p.AuthorPubkey); err != nil {
			return nil, fmt.Errorf("%w: author %q: %w", ErrInvalidPointerTag, p.AuthorPubkey, err)
		}
		tag = append(tag, p.AuthorPubkey)
	}
	return tag, nil
}

// QuoteTag builds a ["q", ...] tag for citing an event or address in
// Content via NIP-21, per NIP-22's "q tags MAY be used when citing events"
// note. pubkey is only meaningful when idOrAddress is a regular event id;
// pass "" for an addressable-event address.
func QuoteTag(idOrAddress, relayURL, pubkey string) []string {
	tag := []string{"q", idOrAddress}
	if relayURL != "" || pubkey != "" {
		tag = append(tag, relayURL)
	}
	if pubkey != "" {
		tag = append(tag, pubkey)
	}
	return tag
}
