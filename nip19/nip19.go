// Package nip19 implements NIP-19: bech32-Encoded Entities, converting
// between raw hex keys/IDs and their human-friendly bech32 form (npub,
// nsec, note, nprofile, nevent, naddr).
package nip19

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// TLV (type-length-value) types used by the "shareable identifiers with
// extra metadata" entities: nprofile, nevent, naddr.
const (
	tlvSpecial = 0
	tlvRelay   = 1
	tlvAuthor  = 2
	tlvKind    = 3
)

type tlvEntry struct {
	typ   byte
	value []byte
}

// encodeTLVEntries serializes an ordered list of TLV entries into their wire form.
func encodeTLVEntries(entries []tlvEntry) ([]byte, error) {
	var buf []byte
	for _, e := range entries {
		if len(e.value) > 255 {
			return nil, fmt.Errorf("tlv value for type %d exceeds 255 bytes (%d)", e.typ, len(e.value))
		}
		buf = append(buf, e.typ, byte(len(e.value)))
		buf = append(buf, e.value...)
	}
	return buf, nil
}

// decodeTLVEntries parses a TLV byte string into its entries, grouped by type.
func decodeTLVEntries(data []byte) map[byte][][]byte {
	result := make(map[byte][][]byte)
	curr := 0
	for curr+2 <= len(data) {
		t := data[curr]
		l := int(data[curr+1])
		curr += 2
		if curr+l > len(data) {
			break
		}
		result[t] = append(result[t], data[curr:curr+l])
		curr += l
	}
	return result
}

func encodeBech32Bytes(prefix string, data []byte) (string, error) {
	bits5, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(prefix, bits5)
}

func decodeBech32Bytes(bech32string, wantPrefix string) ([]byte, error) {
	prefix, bits5, err := bech32.DecodeNoLimit(bech32string)
	if err != nil {
		return nil, err
	}
	if prefix != wantPrefix {
		return nil, fmt.Errorf("expected %s, got %s", wantPrefix, prefix)
	}
	return bech32.ConvertBits(bits5, 5, 8, false)
}

func CheckPublicKey(publicKeyHex string) error {
	_, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode public key hex: %w", err)
	}
	return nil
}

func Decode(bech32string string) (prefix string, value any, err error) {
	prefix, bits5, err := bech32.DecodeNoLimit(bech32string)
	if err != nil {
		return "", nil, err
	}

	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return prefix, nil, fmt.Errorf("failed translating data into 8 bits: %w", err)
	}

	switch prefix {
	case "npub", "nsec", "note":
		if len(data) < 32 {
			return prefix, nil, fmt.Errorf("data is less than 32 bytes (%d)", len(data))
		}

		return prefix, hex.EncodeToString(data[0:32]), nil

	case "nprofile", "nevent", "naddr":
		// TLV encoded; see DecodeProfile, DecodeEvent, and DecodeAddr for
		// parsed access to the individual fields.
		return prefix, data, nil
	}

	return prefix, data, fmt.Errorf("unknown tag %s", prefix)
}

// decodeSimple is the shared implementation behind DecodePublicKey,
// DecodePrivateKey, and DecodeNote: each is a thin, type-safe wrapper around
// the generic Decode that also checks the prefix matches what was asked for.
func decodeSimple(wantPrefix, bech32string string) (string, error) {
	prefix, value, err := Decode(bech32string)
	if err != nil {
		return "", err
	}
	if prefix != wantPrefix {
		return "", fmt.Errorf("expected %s, got %s", wantPrefix, prefix)
	}
	hexValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("could not cast %s decoded data to a hex string", wantPrefix)
	}
	return hexValue, nil
}

// DecodePublicKey decodes an npub string to its hex-encoded public key.
func DecodePublicKey(npub string) (string, error) {
	return decodeSimple("npub", npub)
}

// DecodePrivateKey decodes an nsec string to its hex-encoded private key.
func DecodePrivateKey(nsec string) (string, error) {
	return decodeSimple("nsec", nsec)
}

// DecodeNote decodes a note string to its hex-encoded event ID.
func DecodeNote(note string) (string, error) {
	return decodeSimple("note", note)
}

// ProfilePointer holds the data encoded in an nprofile: a public key plus
// optional relay hints where that pubkey's events can be found.
type ProfilePointer struct {
	PublicKey string
	Relays    []string
}

// EncodeProfile encodes a public key and optional relay hints as an
// nprofile string.
func EncodeProfile(publicKeyHex string, relays []string) (string, error) {
	pk, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key hex: %w", err)
	}
	if len(pk) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes, got %d", len(pk))
	}

	entries := []tlvEntry{{tlvSpecial, pk}}
	for _, r := range relays {
		entries = append(entries, tlvEntry{tlvRelay, []byte(r)})
	}

	data, err := encodeTLVEntries(entries)
	if err != nil {
		return "", err
	}
	return encodeBech32Bytes("nprofile", data)
}

// DecodeProfile decodes an nprofile string into its public key and relay hints.
func DecodeProfile(bech32string string) (*ProfilePointer, error) {
	data, err := decodeBech32Bytes(bech32string, "nprofile")
	if err != nil {
		return nil, err
	}

	tlv := decodeTLVEntries(data)
	pubkeys := tlv[tlvSpecial]
	if len(pubkeys) != 1 || len(pubkeys[0]) != 32 {
		return nil, fmt.Errorf("nprofile public key missing or not 32 bytes")
	}

	pointer := &ProfilePointer{PublicKey: hex.EncodeToString(pubkeys[0])}
	for _, r := range tlv[tlvRelay] {
		pointer.Relays = append(pointer.Relays, string(r))
	}
	return pointer, nil
}

// DecodeNprofile extracts the 32-byte public key hex from an nprofile string.
// An nprofile encodes TLV (type-length-value) data where type 0 is the public key.
func DecodeNprofile(bech32string string) (string, error) {
	pointer, err := DecodeProfile(bech32string)
	if err != nil {
		return "", err
	}
	return pointer.PublicKey, nil
}

// EventPointer holds the data encoded in an nevent: an event ID plus
// optional relay hints, author pubkey, and kind.
type EventPointer struct {
	ID     string
	Relays []string
	Author string // optional, "" if absent
	Kind   int    // optional, 0 if absent
}

// EncodeEvent encodes an EventPointer as an nevent string. ID is required;
// Relays, Author, and Kind are optional.
func EncodeEvent(p EventPointer) (string, error) {
	id, err := hex.DecodeString(p.ID)
	if err != nil {
		return "", fmt.Errorf("failed to decode event id hex: %w", err)
	}
	if len(id) != 32 {
		return "", fmt.Errorf("event id must be 32 bytes, got %d", len(id))
	}

	entries := []tlvEntry{{tlvSpecial, id}}
	for _, r := range p.Relays {
		entries = append(entries, tlvEntry{tlvRelay, []byte(r)})
	}
	if p.Author != "" {
		author, err := hex.DecodeString(p.Author)
		if err != nil {
			return "", fmt.Errorf("failed to decode author pubkey hex: %w", err)
		}
		if len(author) != 32 {
			return "", fmt.Errorf("author pubkey must be 32 bytes, got %d", len(author))
		}
		entries = append(entries, tlvEntry{tlvAuthor, author})
	}
	if p.Kind != 0 {
		kindBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(kindBytes, uint32(p.Kind))
		entries = append(entries, tlvEntry{tlvKind, kindBytes})
	}

	data, err := encodeTLVEntries(entries)
	if err != nil {
		return "", err
	}
	return encodeBech32Bytes("nevent", data)
}

// DecodeEvent decodes an nevent string into its event id, relay hints,
// optional author, and optional kind.
func DecodeEvent(bech32string string) (*EventPointer, error) {
	data, err := decodeBech32Bytes(bech32string, "nevent")
	if err != nil {
		return nil, err
	}

	tlv := decodeTLVEntries(data)
	ids := tlv[tlvSpecial]
	if len(ids) != 1 || len(ids[0]) != 32 {
		return nil, fmt.Errorf("nevent event id missing or not 32 bytes")
	}

	pointer := &EventPointer{ID: hex.EncodeToString(ids[0])}
	for _, r := range tlv[tlvRelay] {
		pointer.Relays = append(pointer.Relays, string(r))
	}
	if authors := tlv[tlvAuthor]; len(authors) == 1 && len(authors[0]) == 32 {
		pointer.Author = hex.EncodeToString(authors[0])
	}
	if kinds := tlv[tlvKind]; len(kinds) == 1 && len(kinds[0]) == 4 {
		pointer.Kind = int(binary.BigEndian.Uint32(kinds[0]))
	}
	return pointer, nil
}

// EntityPointer holds the data encoded in an naddr: the coordinate of an
// addressable (parameterized replaceable) event.
type EntityPointer struct {
	Identifier string
	PublicKey  string
	Kind       int
	Relays     []string
}

// EncodeAddr encodes an EntityPointer as an naddr string. Identifier (which
// may be empty), PublicKey, and Kind are required; Relays is optional.
func EncodeAddr(p EntityPointer) (string, error) {
	pk, err := hex.DecodeString(p.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key hex: %w", err)
	}
	if len(pk) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes, got %d", len(pk))
	}

	entries := []tlvEntry{{tlvSpecial, []byte(p.Identifier)}}
	for _, r := range p.Relays {
		entries = append(entries, tlvEntry{tlvRelay, []byte(r)})
	}
	entries = append(entries, tlvEntry{tlvAuthor, pk})

	kindBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(kindBytes, uint32(p.Kind))
	entries = append(entries, tlvEntry{tlvKind, kindBytes})

	data, err := encodeTLVEntries(entries)
	if err != nil {
		return "", err
	}
	return encodeBech32Bytes("naddr", data)
}

// DecodeAddr decodes an naddr string into its identifier, author public
// key, kind, and relay hints.
func DecodeAddr(bech32string string) (*EntityPointer, error) {
	data, err := decodeBech32Bytes(bech32string, "naddr")
	if err != nil {
		return nil, err
	}

	tlv := decodeTLVEntries(data)
	idents := tlv[tlvSpecial]
	if len(idents) != 1 {
		return nil, fmt.Errorf("naddr identifier missing")
	}
	authors := tlv[tlvAuthor]
	if len(authors) != 1 || len(authors[0]) != 32 {
		return nil, fmt.Errorf("naddr author pubkey missing or not 32 bytes")
	}
	kinds := tlv[tlvKind]
	if len(kinds) != 1 || len(kinds[0]) != 4 {
		return nil, fmt.Errorf("naddr kind missing or not 4 bytes")
	}

	pointer := &EntityPointer{
		Identifier: string(idents[0]),
		PublicKey:  hex.EncodeToString(authors[0]),
		Kind:       int(binary.BigEndian.Uint32(kinds[0])),
	}
	for _, r := range tlv[tlvRelay] {
		pointer.Relays = append(pointer.Relays, string(r))
	}
	return pointer, nil
}

func EncodePrivateKey(privateKeyHex string) (string, error) {
	b, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key hex: %w", err)
	}

	bits5, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode("nsec", bits5)
}

func EncodePublicKey(publicKeyHex string) (string, error) {
	b, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key hex: %w", err)
	}

	bits5, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode("npub", bits5)
}

func EncodeNote(eventIDHex string) (string, error) {
	b, err := hex.DecodeString(eventIDHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode event id hex: %w", err)
	}

	bits5, err := bech32.ConvertBits(b, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode("note", bits5)
}

// NormalizeToHex attempt to decode a string as bech32 (nsec/npub/note/nprofile/nevent)
// or returns it as is if it's already hex.
func NormalizeToHex(input string) string {
	input = strings.TrimSpace(input)
	switch {
	case strings.HasPrefix(input, "nsec"), strings.HasPrefix(input, "npub"), strings.HasPrefix(input, "note"):
		_, val, err := Decode(input)
		if err == nil {
			if s, ok := val.(string); ok {
				return s
			}
		}
	case strings.HasPrefix(input, "nprofile"):
		if pk, err := DecodeNprofile(input); err == nil {
			return pk
		}
	case strings.HasPrefix(input, "nevent"):
		if ev, err := DecodeEvent(input); err == nil {
			return ev.ID
		}
	}
	return input
}
