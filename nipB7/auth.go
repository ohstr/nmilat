package nipB7

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip40"
	"github.com/ohstr/nmilat/utils"
)

// KindAuthorization is the kind of a BUD-11 Authorization token: a
// short-lived, scoped credential proving control of a pubkey to a Blossom
// server, carried in an HTTP "Authorization: Nostr <token>" header rather
// than published to a relay.
const KindAuthorization = 24242

// Verbs a BUD-11 Authorization token's "t" tag can carry, one per endpoint
// action it authorizes. BUD-04 (mirror) does not pin its own verb; servers
// conventionally require VerbUpload for PUT /mirror since mirroring is a
// form of upload.
const (
	VerbGet    = "get"
	VerbUpload = "upload"
	VerbList   = "list"
	VerbDelete = "delete"
	VerbMedia  = "media"
)

// ClockSkewTolerance bounds how far in the future an Authorization event's
// created_at may be and still be accepted, to absorb ordinary clock drift
// between client and server. The spec only says created_at "is in the
// past"; a zero-tolerance check would be flaky for clients whose clock runs
// even a little ahead of the server's.
const ClockSkewTolerance = 60 * time.Second

const authHeaderScheme = "Nostr "

// Failure modes for NewAuthorization/ParseAuthorization/VerifyAuthorization,
// for callers that need to distinguish them (e.g. via errors.Is) rather than
// match on message text.
var (
	ErrWrongAuthKind        = errors.New("nipB7: wrong kind for authorization event")
	ErrMissingVerbTag       = errors.New("nipB7: authorization missing t (verb) tag")
	ErrMissingExpiration    = errors.New("nipB7: authorization missing expiration tag")
	ErrAuthNotYetValid      = errors.New("nipB7: authorization created_at is in the future")
	ErrAuthExpired          = errors.New("nipB7: authorization has expired")
	ErrAuthInvalidSignature = errors.New("nipB7: authorization has an invalid signature")
	ErrVerbMismatch         = errors.New("nipB7: authorization verb does not match requested action")
	ErrServerMismatch       = errors.New("nipB7: authorization is not scoped to this server")
	ErrHashNotAuthorized    = errors.New("nipB7: authorization does not cover this blob hash")
	ErrMissingAuthHeader    = errors.New("nipB7: missing or malformed Authorization header")
)

// Authorization is a parsed kind:24242 BUD-11 token.
type Authorization struct {
	*nip01.Event
	Verb       string
	Expiration uint64
	Servers    []string
	Hashes     []string
}

// HasServer reports whether host is among the token's "server" tags
// (case-insensitive), or true if the token carries no server tags at all —
// per spec, an absent server tag means the token is valid on any server.
func (a *Authorization) HasServer(host string) bool {
	if len(a.Servers) == 0 {
		return true
	}
	for _, s := range a.Servers {
		if strings.EqualFold(normalizeHost(s), normalizeHost(host)) {
			return true
		}
	}
	return false
}

// HasHash reports whether hash is among the token's "x" tags
// (case-insensitive hex comparison).
func (a *Authorization) HasHash(hash string) bool {
	for _, h := range a.Hashes {
		if strings.EqualFold(h, hash) {
			return true
		}
	}
	return false
}

func normalizeHost(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	return strings.TrimSuffix(s, "/")
}

// ParseAuthorization parses and structurally validates a kind:24242 event:
// wrong kind, missing "t" tag, or missing/malformed expiration tag are all
// rejected. It does not check the signature (see ValidateAuthorization) or
// timing/verb/server/hash constraints (see VerifyAuthorization) — this is
// the pure structural layer, mirroring ParseBlossomServerList.
func ParseAuthorization(event *nip01.Event) (*Authorization, error) {
	if event.Kind != KindAuthorization {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongAuthKind, event.Kind, KindAuthorization)
	}

	verb, err := utils.FindUniqueEventTagValue(event.Tags, "t")
	if err != nil || verb == "" {
		return nil, ErrMissingVerbTag
	}

	expiration, err := nip40.GetExpiration(event.Tags)
	if err != nil || expiration == 0 {
		return nil, ErrMissingExpiration
	}

	auth := &Authorization{Event: event, Verb: verb, Expiration: expiration}
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "server":
			auth.Servers = append(auth.Servers, tag[1])
		case "x":
			auth.Hashes = append(auth.Hashes, tag[1])
		}
	}
	return auth, nil
}

// ValidateAuthorization checks the signature and structure of an
// authorization event. It does not check timing, verb, server, or hash
// constraints against a specific request — use VerifyAuthorization for the
// full server-side check against an incoming HTTP request.
func ValidateAuthorization(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthInvalidSignature, err)
	}
	_, err := ParseAuthorization(event)
	return err
}

// checkTiming enforces the BUD-11 timing rules: created_at must not be in
// the future (beyond ClockSkewTolerance), and expiration must not have
// passed yet.
func checkTiming(auth *Authorization, now time.Time) error {
	createdAt := time.Unix(int64(auth.CreatedAt), 0)
	if createdAt.After(now.Add(ClockSkewTolerance)) {
		return ErrAuthNotYetValid
	}
	if !time.Unix(int64(auth.Expiration), 0).After(now) {
		return ErrAuthExpired
	}
	return nil
}

// AuthorizationParams describes a BUD-11 Authorization token to build.
// Pubkey, Verb, Content, and Expiration are required; Servers and Hashes are
// optional scoping restrictions (absent Servers means "valid on any
// server"; absent Hashes means "not scoped to specific blobs", appropriate
// for e.g. a list or a fresh upload whose hash isn't known yet).
type AuthorizationParams struct {
	Pubkey     string
	Verb       string
	Content    string // human-readable reason shown to the user, e.g. "Upload blob"
	Expiration time.Time
	Servers    []string
	Hashes     []string
}

// NewAuthorization builds an unsigned kind:24242 event per p. Caller must
// sign it before use.
func NewAuthorization(p AuthorizationParams) *nip01.Event {
	tags := make([][]string, 0, 2+len(p.Servers)+len(p.Hashes))
	tags = append(tags, []string{"t", p.Verb})
	tags = append(tags, []string{nip40.TagName, strconv.FormatInt(p.Expiration.Unix(), 10)})
	for _, s := range p.Servers {
		tags = append(tags, []string{"server", s})
	}
	for _, h := range p.Hashes {
		tags = append(tags, []string{"x", h})
	}
	return nip01.NewUnsignedEvent(KindAuthorization, p.Pubkey, p.Content, tags...)
}

// EncodeAuthHeader base64url-encodes a signed authorization event into the
// "Authorization: Nostr <token>" header value BUD-11 specifies (the same
// encoding as a JWT payload segment: RawURLEncoding, no padding).
func EncodeAuthHeader(event *nip01.Event) (string, error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return authHeaderScheme + base64.RawURLEncoding.EncodeToString(payload), nil
}

// DecodeAuthHeader parses a raw "Authorization" header value (as returned by
// http.Header.Get) into an event, without verifying its signature or
// structure — pair with ValidateAuthorization/VerifyAuthorization for that.
func DecodeAuthHeader(header string) (*nip01.Event, error) {
	if !strings.HasPrefix(header, authHeaderScheme) {
		return nil, ErrMissingAuthHeader
	}
	payload, err := base64.RawURLEncoding.DecodeString(header[len(authHeaderScheme):])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMissingAuthHeader, err)
	}
	var event nip01.Event
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMissingAuthHeader, err)
	}
	return &event, nil
}

// VerifyParams constrains VerifyAuthorization's check of an incoming
// request's Authorization token beyond signature/structure. Verb is
// required. ServerHost, when set, is enforced only if the token itself
// carries "server" tags (an absent tag means the token isn't scoped to a
// server). Hash works the same way unless RequireHash is set: pass
// RequireHash for endpoints where the spec expects the token to name
// exactly which blob it authorizes (e.g. BUD-12 delete, where a token
// without a matching "x" tag must be rejected rather than treated as
// unscoped). Now defaults to time.Now() when zero.
type VerifyParams struct {
	Verb        string
	ServerHost  string
	Hash        string
	RequireHash bool
	Now         time.Time
}

// VerifyAuthorization performs the complete BUD-11 server-side check on an
// incoming HTTP request: extracts and decodes the Authorization header,
// verifies the event's signature and structure, then checks timing, verb,
// server scope, and (if p.Hash is set) that the token authorizes that exact
// blob hash. It is the Blossom analogue of nip98.VerifyAuthHeader.
func VerifyAuthorization(r *http.Request, p VerifyParams) (*Authorization, error) {
	event, err := DecodeAuthHeader(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	if err := event.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthInvalidSignature, err)
	}
	auth, err := ParseAuthorization(event)
	if err != nil {
		return nil, err
	}
	if auth.Verb != p.Verb {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrVerbMismatch, auth.Verb, p.Verb)
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	if err := checkTiming(auth, now); err != nil {
		return nil, err
	}
	if p.ServerHost != "" && !auth.HasServer(p.ServerHost) {
		return nil, ErrServerMismatch
	}
	if p.Hash != "" && (p.RequireHash || len(auth.Hashes) > 0) && !auth.HasHash(p.Hash) {
		return nil, ErrHashNotAuthorized
	}
	return auth, nil
}
