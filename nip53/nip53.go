// Package nip53 implements NIP-53: Live Streaming and Spaces -- live
// streaming events, the persistent meeting spaces that host audio/video
// rooms, the individual meetings held in them, listener presence, and live
// chat. This package is a pure protocol library (parsing, structural
// validation, and event construction); it has no dependency on relay/.
package nip53

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	// KindLiveChatMessage is a chat message scoped to a live activity by
	// its "a" tag.
	KindLiveChatMessage = 1311
	// KindRoomPresence signals that a listener is present in a room. It is
	// a regular replaceable kind, which is exactly why presence can only
	// be indicated in one room at a time.
	KindRoomPresence = 10312
	// KindLiveStreamingEvent advertises the content and participants of a
	// live stream.
	KindLiveStreamingEvent = 30311
	// KindMeetingSpace ("Space Host") defines a virtual interactive space:
	// one or more audio/video rooms users can join. A space MAY persist
	// when not in use.
	KindMeetingSpace = 30312
	// KindMeetingRoomEvent is a scheduled or ongoing meeting inside a
	// space, referencing its parent space by "a" tag.
	KindMeetingRoomEvent = 30313
)

// Activity statuses, shared by kind:30311 and kind:30313.
const (
	StatusPlanned = "planned"
	StatusLive    = "live"
	StatusEnded   = "ended"
)

// Space accessibility statuses (kind:30312). Closed means the room is not
// in operation.
const (
	SpaceStatusOpen    = "open"
	SpaceStatusPrivate = "private"
	SpaceStatusClosed  = "closed"
)

// Participant and provider roles. The spec calls these "displayable"
// markers rather than a closed enum, so these are the conventional values
// it names -- not an exhaustive list, and parsing never rejects an unknown
// role.
const (
	RoleHost        = "Host"
	RoleModerator   = "Moderator"
	RoleSpeaker     = "Speaker"
	RoleParticipant = "Participant"
)

// DefaultStaleWindow is the spec's own suggestion that clients MAY treat a
// status=live activity with no update for an hour as ended. It is a client
// heuristic, not a protocol rule -- IsStale takes the window explicitly so
// callers can tighten it.
const DefaultStaleWindow = time.Hour

// DefaultPresenceWindow is this package's default tolerance for "clients
// SHOULD filter presence events older than a given time window". The spec
// deliberately names no number, so this is a reasonable default for
// presence refreshed on the order of minutes, not a normative value.
const DefaultPresenceWindow = 10 * time.Minute

// Failure modes, for callers that need to distinguish them (e.g. via
// errors.Is) rather than match on message text.
var (
	ErrWrongKind          = errors.New("nip53: wrong kind")
	ErrMissingDTag        = errors.New("nip53: missing d tag (identifier)")
	ErrMissingRoomTag     = errors.New("nip53: missing room tag (display name)")
	ErrMissingServiceTag  = errors.New("nip53: missing service tag (room access url)")
	ErrMissingTitleTag    = errors.New("nip53: missing title tag")
	ErrMissingStatusTag   = errors.New("nip53: missing status tag")
	ErrInvalidStatus      = errors.New("nip53: status must be planned, live or ended")
	ErrInvalidSpaceStatus = errors.New("nip53: status must be open, private or closed")
	ErrMissingStartsTag   = errors.New("nip53: missing starts tag")
	ErrInvalidTimestamp   = errors.New("nip53: invalid unix timestamp")
	ErrInvalidCount       = errors.New("nip53: participant count must be a non-negative integer")
	ErrMissingATag        = errors.New("nip53: missing a tag")
	ErrMultipleATags      = errors.New("nip53: multiple a tags (presence is one room at a time)")
	ErrInvalidATag        = errors.New("nip53: invalid a tag")
	ErrWrongATagKind      = errors.New("nip53: a tag references the wrong kind")
	ErrMissingHost        = errors.New("nip53: space needs at least one provider with the Host role")
	ErrInvalidPubkey      = errors.New("nip53: invalid participant pubkey")
	ErrInvalidProof       = errors.New("nip53: invalid participation proof")
	ErrMissingProof       = errors.New("nip53: participant carries no participation proof")
	ErrInvalidSignature   = errors.New("nip53: invalid signature")
)

/////////////////////////////////////////////////////////////////////
// Shared helpers
/////////////////////////////////////////////////////////////////////

// IsValidStatus reports whether s is one of the three activity statuses
// kind:30311 and kind:30313 allow.
func IsValidStatus(s string) bool {
	switch s {
	case StatusPlanned, StatusLive, StatusEnded:
		return true
	default:
		return false
	}
}

// IsValidSpaceStatus reports whether s is one of the three accessibility
// statuses kind:30312 allows.
func IsValidSpaceStatus(s string) bool {
	switch s {
	case SpaceStatusOpen, SpaceStatusPrivate, SpaceStatusClosed:
		return true
	default:
		return false
	}
}

// IsStale reports whether a live activity looks abandoned: status is live
// and createdAt is older than window. Any other status is never stale --
// an ended activity is finished, not abandoned, and a planned one has not
// started. Implements the spec's "clients MAY consider status=live events
// after 1hr without any update as ended".
func IsStale(status string, createdAt uint64, now time.Time, window time.Duration) bool {
	if status != StatusLive {
		return false
	}
	return now.Unix()-int64(createdAt) > int64(window.Seconds())
}

// IsPresenceFresh reports whether a kind:10312 presence event is recent
// enough to still count, per the spec's instruction that clients SHOULD
// filter presence older than some window. A presence timestamped in the
// future is treated as fresh: clock skew should not silently hide a
// participant.
func IsPresenceFresh(createdAt uint64, now time.Time, window time.Duration) bool {
	age := now.Unix() - int64(createdAt)
	if age < 0 {
		return true
	}
	return age <= int64(window.Seconds())
}

// parseUnixTag parses a tag value holding a unix timestamp in seconds.
func parseUnixTag(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrInvalidTimestamp, value)
	}
	return n, nil
}

// parseCountTag parses a participant-count tag value.
func parseCountTag(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: %q", ErrInvalidCount, value)
	}
	return n, nil
}

// appendIfSet appends a two-element tag only when value is non-empty,
// keeping the New* builders free of repeated emptiness checks.
func appendIfSet(tags [][]string, name, value string) [][]string {
	if value == "" {
		return tags
	}
	return append(tags, []string{name, value})
}

/////////////////////////////////////////////////////////////////////
// Participants
/////////////////////////////////////////////////////////////////////

// Participant is one "p" tag: a pubkey, an optional relay hint, a
// displayable role, and an optional participation proof. The relay URL MAY
// be empty, which the spec states explicitly.
type Participant struct {
	Pubkey   string
	RelayURL string
	Role     string
	Proof    string
}

// HasProof reports whether this participant carries a participation proof.
// Clients MAY display participants without one as merely "invited".
func (p Participant) HasProof() bool { return p.Proof != "" }

// parseParticipants collects every "p" tag into a Participant. A "p" tag
// with an unparseable pubkey is an error rather than a skip: silently
// dropping a participant would understate who is in a room.
func parseParticipants(tags [][]string) ([]Participant, error) {
	var out []Participant
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != "p" {
			continue
		}
		if err := utils.Validate32Key(tag[1]); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkey, tag[1], err)
		}
		p := Participant{Pubkey: tag[1]}
		if len(tag) >= 3 {
			p.RelayURL = tag[2]
		}
		if len(tag) >= 4 {
			p.Role = tag[3]
		}
		if len(tag) >= 5 {
			p.Proof = tag[4]
		}
		out = append(out, p)
	}
	return out, nil
}

// participantTag renders a Participant back to its "p" tag form, padding
// earlier positions so a proof is never mistaken for a role.
func participantTag(p Participant) []string {
	tag := []string{"p", p.Pubkey}
	switch {
	case p.Proof != "":
		tag = append(tag, p.RelayURL, p.Role, p.Proof)
	case p.Role != "":
		tag = append(tag, p.RelayURL, p.Role)
	case p.RelayURL != "":
		tag = append(tag, p.RelayURL)
	}
	return tag
}

/////////////////////////////////////////////////////////////////////
// Proof of agreement to participate
/////////////////////////////////////////////////////////////////////

// ParticipationProofDigest returns the SHA256 of an activity's complete
// "a" tag ("<kind>:<pubkey>:<d-tag>"), which is what a participant signs
// to prove they agreed to join.
func ParticipationProofDigest(aTag string) []byte {
	sum := sha256.Sum256([]byte(aTag))
	return sum[:]
}

// SignParticipationProof signs an activity's "a" tag with a participant's
// private key and returns the hex proof for the 5th term of their "p" tag.
func SignParticipationProof(privateKey, aTag string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("nip53: invalid private key: %w", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	sig, err := schnorr.Sign(privKey, ParticipationProofDigest(aTag))
	if err != nil {
		return "", fmt.Errorf("nip53: failed to sign participation proof: %w", err)
	}
	return hex.EncodeToString(sig.Serialize()), nil
}

// VerifyParticipationProof checks that proofHex is pubkey's signature over
// aTag's digest. This is the check that stops a malicious activity owner
// from listing large accounts who never agreed to take part.
func VerifyParticipationProof(pubkey, aTag, proofHex string) error {
	if proofHex == "" {
		return ErrMissingProof
	}
	sigBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return fmt.Errorf("%w: not hex: %w", ErrInvalidProof, err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPubkey, err)
	}
	parsed, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPubkey, err)
	}
	if !sig.Verify(ParticipationProofDigest(aTag), parsed) {
		return ErrInvalidProof
	}
	return nil
}

/////////////////////////////////////////////////////////////////////
// Live Streaming Events (kind 30311)
/////////////////////////////////////////////////////////////////////

// LiveStream is a parsed kind:30311 event. Per spec a distinct "d" tag
// identifies each activity and every other tag is optional, so all the
// nil-able fields here really can be absent on an otherwise valid event.
type LiveStream struct {
	Identifier          string
	Title               string
	Summary             string
	Image               string
	Hashtags            []string
	Streaming           []string
	Recording           []string
	Starts              *uint64
	Ends                *uint64
	Status              string
	CurrentParticipants *int
	TotalParticipants   *int
	Participants        []Participant
	Relays              []string
	Pinned              []string
}

// ParseLiveStream parses and structurally validates a kind:30311 event.
func ParseLiveStream(event *nip01.Event) (*LiveStream, error) {
	if event.Kind != KindLiveStreamingEvent {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindLiveStreamingEvent)
	}

	ls := &LiveStream{}
	haveD := false
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "d":
			ls.Identifier = tag[1]
			haveD = true
		case "title":
			ls.Title = tag[1]
		case "summary":
			ls.Summary = tag[1]
		case "image":
			ls.Image = tag[1]
		case "t":
			ls.Hashtags = append(ls.Hashtags, tag[1])
		case "streaming":
			ls.Streaming = append(ls.Streaming, tag[1])
		case "recording":
			ls.Recording = append(ls.Recording, tag[1])
		case "starts":
			n, err := parseUnixTag(tag[1])
			if err != nil {
				return nil, err
			}
			ls.Starts = &n
		case "ends":
			n, err := parseUnixTag(tag[1])
			if err != nil {
				return nil, err
			}
			ls.Ends = &n
		case "status":
			if !IsValidStatus(tag[1]) {
				return nil, fmt.Errorf("%w: %q", ErrInvalidStatus, tag[1])
			}
			ls.Status = tag[1]
		case "current_participants":
			n, err := parseCountTag(tag[1])
			if err != nil {
				return nil, err
			}
			ls.CurrentParticipants = &n
		case "total_participants":
			n, err := parseCountTag(tag[1])
			if err != nil {
				return nil, err
			}
			ls.TotalParticipants = &n
		case "relays":
			ls.Relays = append(ls.Relays, tag[1:]...)
		case "pinned":
			ls.Pinned = append(ls.Pinned, tag[1])
		}
	}
	if !haveD {
		return nil, ErrMissingDTag
	}

	participants, err := parseParticipants(event.Tags)
	if err != nil {
		return nil, err
	}
	ls.Participants = participants
	return ls, nil
}

// ValidateLiveStream checks the signature and structure of a kind:30311
// event.
func ValidateLiveStream(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseLiveStream(event)
	return err
}

// LiveStreamParams describes a kind:30311 live streaming event. Pubkey and
// Identifier are required; everything else is optional per spec.
type LiveStreamParams struct {
	Pubkey              string
	Identifier          string
	Title               string
	Summary             string
	Image               string
	Hashtags            []string
	Streaming           []string
	Recording           []string
	Starts              *uint64
	Ends                *uint64
	Status              string
	CurrentParticipants *int
	TotalParticipants   *int
	Participants        []Participant
	Relays              []string
	Pinned              []string
	Content             string
}

// NewLiveStream builds an unsigned kind:30311 event.
func NewLiveStream(p LiveStreamParams) *nip01.Event {
	tags := [][]string{{"d", p.Identifier}}
	tags = appendIfSet(tags, "title", p.Title)
	tags = appendIfSet(tags, "summary", p.Summary)
	tags = appendIfSet(tags, "image", p.Image)
	for _, t := range p.Hashtags {
		tags = append(tags, []string{"t", t})
	}
	for _, s := range p.Streaming {
		tags = append(tags, []string{"streaming", s})
	}
	for _, r := range p.Recording {
		tags = append(tags, []string{"recording", r})
	}
	if p.Starts != nil {
		tags = append(tags, []string{"starts", strconv.FormatUint(*p.Starts, 10)})
	}
	if p.Ends != nil {
		tags = append(tags, []string{"ends", strconv.FormatUint(*p.Ends, 10)})
	}
	tags = appendIfSet(tags, "status", p.Status)
	if p.CurrentParticipants != nil {
		tags = append(tags, []string{"current_participants", strconv.Itoa(*p.CurrentParticipants)})
	}
	if p.TotalParticipants != nil {
		tags = append(tags, []string{"total_participants", strconv.Itoa(*p.TotalParticipants)})
	}
	for _, participant := range p.Participants {
		tags = append(tags, participantTag(participant))
	}
	if len(p.Relays) > 0 {
		tags = append(tags, append([]string{"relays"}, p.Relays...))
	}
	for _, id := range p.Pinned {
		tags = append(tags, []string{"pinned", id})
	}
	return nip01.NewUnsignedEvent(KindLiveStreamingEvent, p.Pubkey, p.Content, tags...)
}

// StreamATag renders the "a" tag value addressing a live streaming event,
// which kind:1311 chat messages and participation proofs reference.
func StreamATag(pubkey, identifier string) (string, error) {
	return utils.FormatATag(KindLiveStreamingEvent, pubkey, identifier)
}

/////////////////////////////////////////////////////////////////////
// Meeting Spaces (kind 30312)
/////////////////////////////////////////////////////////////////////

// MeetingSpace is a parsed kind:30312 event: the room itself, which MAY
// persist when not in use. Service is the URL clients use to reach the
// room's media transport; the spec deliberately leaves that transport
// unspecified, which is what makes this kind usable with any of them.
type MeetingSpace struct {
	Identifier string
	Room       string
	Summary    string
	Image      string
	Status     string
	Service    string
	Endpoint   string
	Hashtags   []string
	Providers  []Participant
	Relays     []string
}

// Hosts returns the providers carrying the Host role.
func (s *MeetingSpace) Hosts() []Participant {
	var out []Participant
	for _, p := range s.Providers {
		if p.Role == RoleHost {
			out = append(out, p)
		}
	}
	return out
}

// ParseMeetingSpace parses and structurally validates a kind:30312 event,
// enforcing the spec's MUSTs: a d tag, a room name, a valid status, a
// service URL, and at least one provider with the Host role.
func ParseMeetingSpace(event *nip01.Event) (*MeetingSpace, error) {
	if event.Kind != KindMeetingSpace {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindMeetingSpace)
	}

	space := &MeetingSpace{}
	haveD := false
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "d":
			space.Identifier = tag[1]
			haveD = true
		case "room":
			space.Room = tag[1]
		case "summary":
			space.Summary = tag[1]
		case "image":
			space.Image = tag[1]
		case "status":
			if !IsValidSpaceStatus(tag[1]) {
				return nil, fmt.Errorf("%w: %q", ErrInvalidSpaceStatus, tag[1])
			}
			space.Status = tag[1]
		case "service":
			space.Service = tag[1]
		case "endpoint":
			space.Endpoint = tag[1]
		case "t":
			space.Hashtags = append(space.Hashtags, tag[1])
		case "relays":
			space.Relays = append(space.Relays, tag[1:]...)
		}
	}
	if !haveD {
		return nil, ErrMissingDTag
	}
	if space.Room == "" {
		return nil, ErrMissingRoomTag
	}
	if space.Status == "" {
		return nil, ErrMissingStatusTag
	}
	if space.Service == "" {
		return nil, ErrMissingServiceTag
	}

	providers, err := parseParticipants(event.Tags)
	if err != nil {
		return nil, err
	}
	space.Providers = providers
	if len(space.Hosts()) == 0 {
		return nil, ErrMissingHost
	}
	return space, nil
}

// ValidateMeetingSpace checks the signature and structure of a kind:30312
// event.
func ValidateMeetingSpace(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseMeetingSpace(event)
	return err
}

// MeetingSpaceParams describes a kind:30312 meeting space. Pubkey,
// Identifier, Room, Status, Service and at least one Host provider are
// required.
type MeetingSpaceParams struct {
	Pubkey     string
	Identifier string
	Room       string
	Summary    string
	Image      string
	Status     string
	Service    string
	Endpoint   string
	Hashtags   []string
	Providers  []Participant
	Relays     []string
	Content    string
}

// NewMeetingSpace builds an unsigned kind:30312 event. It does not enforce
// the required fields; build it and then ParseMeetingSpace if you want
// them checked.
func NewMeetingSpace(p MeetingSpaceParams) *nip01.Event {
	tags := [][]string{{"d", p.Identifier}, {"room", p.Room}}
	tags = appendIfSet(tags, "summary", p.Summary)
	tags = appendIfSet(tags, "image", p.Image)
	tags = appendIfSet(tags, "status", p.Status)
	tags = appendIfSet(tags, "service", p.Service)
	tags = appendIfSet(tags, "endpoint", p.Endpoint)
	for _, t := range p.Hashtags {
		tags = append(tags, []string{"t", t})
	}
	for _, provider := range p.Providers {
		tags = append(tags, participantTag(provider))
	}
	if len(p.Relays) > 0 {
		tags = append(tags, append([]string{"relays"}, p.Relays...))
	}
	return nip01.NewUnsignedEvent(KindMeetingSpace, p.Pubkey, p.Content, tags...)
}

// SpaceATag renders the "a" tag value that addresses a meeting space,
// which kind:30313 meetings and kind:10312 presence reference.
func SpaceATag(pubkey, identifier string) (string, error) {
	return utils.FormatATag(KindMeetingSpace, pubkey, identifier)
}

/////////////////////////////////////////////////////////////////////
// Meeting Room Events (kind 30313)
/////////////////////////////////////////////////////////////////////

// MeetingRoomEvent is a parsed kind:30313 event: one scheduled or ongoing
// meeting inside a space. Space holds the raw parent "a" tag, with its
// components broken out alongside for convenience.
type MeetingRoomEvent struct {
	Identifier          string
	Space               string
	SpaceRelay          string
	SpacePubkey         string
	SpaceIdentifier     string
	Title               string
	Summary             string
	Image               string
	Starts              uint64
	Ends                *uint64
	Status              string
	CurrentParticipants *int
	TotalParticipants   *int
	Participants        []Participant
}

// ParseMeetingRoomEvent parses and structurally validates a kind:30313
// event, enforcing the spec's MUSTs: a d tag, an "a" tag referencing a
// kind:30312 parent, a title, a start time, and a valid status.
func ParseMeetingRoomEvent(event *nip01.Event) (*MeetingRoomEvent, error) {
	if event.Kind != KindMeetingRoomEvent {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindMeetingRoomEvent)
	}

	meeting := &MeetingRoomEvent{}
	haveD := false
	haveStarts := false
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "d":
			meeting.Identifier = tag[1]
			haveD = true
		case "a":
			kind, pubkey, identifier, err := utils.ParseATag(tag[1])
			if err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidATag, tag[1], err)
			}
			if kind != KindMeetingSpace {
				return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongATagKind, kind, KindMeetingSpace)
			}
			meeting.Space = tag[1]
			meeting.SpacePubkey = pubkey
			meeting.SpaceIdentifier = identifier
			if len(tag) >= 3 {
				meeting.SpaceRelay = tag[2]
			}
		case "title":
			meeting.Title = tag[1]
		case "summary":
			meeting.Summary = tag[1]
		case "image":
			meeting.Image = tag[1]
		case "starts":
			n, err := parseUnixTag(tag[1])
			if err != nil {
				return nil, err
			}
			meeting.Starts = n
			haveStarts = true
		case "ends":
			n, err := parseUnixTag(tag[1])
			if err != nil {
				return nil, err
			}
			meeting.Ends = &n
		case "status":
			if !IsValidStatus(tag[1]) {
				return nil, fmt.Errorf("%w: %q", ErrInvalidStatus, tag[1])
			}
			meeting.Status = tag[1]
		case "current_participants":
			n, err := parseCountTag(tag[1])
			if err != nil {
				return nil, err
			}
			meeting.CurrentParticipants = &n
		case "total_participants":
			n, err := parseCountTag(tag[1])
			if err != nil {
				return nil, err
			}
			meeting.TotalParticipants = &n
		}
	}
	if !haveD {
		return nil, ErrMissingDTag
	}
	if meeting.Space == "" {
		return nil, ErrMissingATag
	}
	if meeting.Title == "" {
		return nil, ErrMissingTitleTag
	}
	if !haveStarts {
		return nil, ErrMissingStartsTag
	}
	if meeting.Status == "" {
		return nil, ErrMissingStatusTag
	}

	participants, err := parseParticipants(event.Tags)
	if err != nil {
		return nil, err
	}
	meeting.Participants = participants
	return meeting, nil
}

// ValidateMeetingRoomEvent checks the signature and structure of a
// kind:30313 event.
func ValidateMeetingRoomEvent(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseMeetingRoomEvent(event)
	return err
}

// MeetingRoomEventParams describes a kind:30313 meeting. Pubkey,
// Identifier, Space, Title, Starts and Status are required.
type MeetingRoomEventParams struct {
	Pubkey              string
	Identifier          string
	Space               string
	SpaceRelay          string
	Title               string
	Summary             string
	Image               string
	Starts              uint64
	Ends                *uint64
	Status              string
	CurrentParticipants *int
	TotalParticipants   *int
	Participants        []Participant
	Content             string
}

// NewMeetingRoomEvent builds an unsigned kind:30313 event.
func NewMeetingRoomEvent(p MeetingRoomEventParams) *nip01.Event {
	aTag := []string{"a", p.Space}
	if p.SpaceRelay != "" {
		aTag = append(aTag, p.SpaceRelay)
	}
	tags := [][]string{
		{"d", p.Identifier},
		aTag,
		{"title", p.Title},
		{"starts", strconv.FormatUint(p.Starts, 10)},
	}
	tags = appendIfSet(tags, "summary", p.Summary)
	tags = appendIfSet(tags, "image", p.Image)
	if p.Ends != nil {
		tags = append(tags, []string{"ends", strconv.FormatUint(*p.Ends, 10)})
	}
	tags = appendIfSet(tags, "status", p.Status)
	if p.CurrentParticipants != nil {
		tags = append(tags, []string{"current_participants", strconv.Itoa(*p.CurrentParticipants)})
	}
	if p.TotalParticipants != nil {
		tags = append(tags, []string{"total_participants", strconv.Itoa(*p.TotalParticipants)})
	}
	for _, participant := range p.Participants {
		tags = append(tags, participantTag(participant))
	}
	return nip01.NewUnsignedEvent(KindMeetingRoomEvent, p.Pubkey, p.Content, tags...)
}

// MeetingATag renders the "a" tag value addressing a meeting, which
// kind:1311 chat messages and kind:10312 presence reference.
func MeetingATag(pubkey, identifier string) (string, error) {
	return utils.FormatATag(KindMeetingRoomEvent, pubkey, identifier)
}

/////////////////////////////////////////////////////////////////////
// Room Presence (kind 10312)
/////////////////////////////////////////////////////////////////////

// RoomPresence is a parsed kind:10312 event signalling that a listener is
// in a room. Because the kind is replaceable, exactly one room may be
// referenced -- ParseRoomPresence rejects a second "a" tag rather than
// silently picking one.
type RoomPresence struct {
	Room       string
	RelayHint  string
	Marker     string
	HandRaised bool
}

// ParseRoomPresence parses and structurally validates a kind:10312 event.
func ParseRoomPresence(event *nip01.Event) (*RoomPresence, error) {
	if event.Kind != KindRoomPresence {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindRoomPresence)
	}

	presence := &RoomPresence{}
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "a":
			if presence.Room != "" {
				return nil, ErrMultipleATags
			}
			if _, _, _, err := utils.ParseATag(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidATag, tag[1], err)
			}
			presence.Room = tag[1]
			if len(tag) >= 3 {
				presence.RelayHint = tag[2]
			}
			if len(tag) >= 4 {
				presence.Marker = tag[3]
			}
		case "hand":
			presence.HandRaised = tag[1] == "1"
		}
	}
	if presence.Room == "" {
		return nil, ErrMissingATag
	}
	return presence, nil
}

// ValidateRoomPresence checks the signature and structure of a kind:10312
// event.
func ValidateRoomPresence(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseRoomPresence(event)
	return err
}

// RoomPresenceParams describes a kind:10312 presence event. Pubkey and
// Room are required.
type RoomPresenceParams struct {
	Pubkey     string
	Room       string
	RelayHint  string
	Marker     string
	HandRaised bool
}

// NewRoomPresence builds an unsigned kind:10312 event. Marker defaults to
// "root", the value the spec's own example carries.
func NewRoomPresence(p RoomPresenceParams) *nip01.Event {
	marker := p.Marker
	if marker == "" {
		marker = "root"
	}
	tags := [][]string{{"a", p.Room, p.RelayHint, marker}}
	if p.HandRaised {
		tags = append(tags, []string{"hand", "1"})
	}
	return nip01.NewUnsignedEvent(KindRoomPresence, p.Pubkey, "", tags...)
}

/////////////////////////////////////////////////////////////////////
// Live Chat Messages (kind 1311)
/////////////////////////////////////////////////////////////////////

// LiveChatMessage is a parsed kind:1311 event. Activity is the "a" tag of
// the activity the message belongs to, which clients MUST include; Parent
// is the optional "e" tag naming the message being replied to.
type LiveChatMessage struct {
	Activity      string
	ActivityRelay string
	Parent        string
	Quotes        []string
	Content       string
}

// ParseLiveChatMessage parses and structurally validates a kind:1311
// event. A second "a" tag is ignored rather than rejected: unlike
// presence, a chat message is not replaceable, so a stray extra reference
// is malformed metadata, not an ambiguous room claim.
func ParseLiveChatMessage(event *nip01.Event) (*LiveChatMessage, error) {
	if event.Kind != KindLiveChatMessage {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindLiveChatMessage)
	}

	msg := &LiveChatMessage{Content: event.Content}
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "a":
			if msg.Activity != "" {
				continue
			}
			if _, _, _, err := utils.ParseATag(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidATag, tag[1], err)
			}
			msg.Activity = tag[1]
			if len(tag) >= 3 {
				msg.ActivityRelay = tag[2]
			}
		case "e":
			if msg.Parent == "" {
				msg.Parent = tag[1]
			}
		case "q":
			msg.Quotes = append(msg.Quotes, tag[1])
		}
	}
	if msg.Activity == "" {
		return nil, ErrMissingATag
	}
	return msg, nil
}

// ValidateLiveChatMessage checks the signature and structure of a
// kind:1311 event.
func ValidateLiveChatMessage(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseLiveChatMessage(event)
	return err
}

// LiveChatMessageParams describes a kind:1311 message. Pubkey, Activity
// and Content are required.
type LiveChatMessageParams struct {
	Pubkey        string
	Activity      string
	ActivityRelay string
	Parent        string
	Quotes        []string
	Content       string
}

// NewLiveChatMessage builds an unsigned kind:1311 event.
func NewLiveChatMessage(p LiveChatMessageParams) *nip01.Event {
	aTag := []string{"a", p.Activity}
	if p.ActivityRelay != "" {
		aTag = append(aTag, p.ActivityRelay)
	}
	tags := [][]string{aTag}
	if p.Parent != "" {
		tags = append(tags, []string{"e", p.Parent})
	}
	for _, q := range p.Quotes {
		tags = append(tags, []string{"q", q})
	}
	return nip01.NewUnsignedEvent(KindLiveChatMessage, p.Pubkey, p.Content, tags...)
}
