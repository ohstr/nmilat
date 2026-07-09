// Package nip90 implements NIP-90: Data Vending Machines, a marketplace
// flow where customers announce compute jobs and service providers compete
// to fulfill them. NIP-90 reserves kinds 5000-5999 for job requests,
// 6000-6999 for job results, and 7000 for job feedback; job-kind-specific
// input/output schemas are defined by separate, per-job-type specs and are
// intentionally out of scope here — only the common envelope (tags shared
// by every job type) is modeled.
package nip90

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Failure modes for the Parse*/Validate*/New* functions below, for callers
// that need to distinguish them (e.g. via errors.Is) rather than match on
// message text.
var (
	ErrWrongKind          = errors.New("nip90: wrong kind")
	ErrInvalidInputTag    = errors.New("nip90: invalid i tag")
	ErrInvalidInputType   = errors.New("nip90: invalid i tag input-type")
	ErrInvalidBid         = errors.New("nip90: invalid bid amount")
	ErrInvalidRelayURL    = errors.New("nip90: invalid relay url")
	ErrInvalidRelayScheme = errors.New("nip90: relay url must use ws or wss scheme")
	ErrInvalidProviderTag = errors.New("nip90: invalid p tag")
	ErrInvalidParamTag    = errors.New("nip90: invalid param tag")
	ErrInvalidSignature   = errors.New("nip90: invalid signature")
	ErrInvalidEventTag    = errors.New("nip90: invalid e tag")
	ErrMissingEventTag    = errors.New("nip90: missing e tag referencing the job request")
	ErrInvalidAmount      = errors.New("nip90: invalid amount")
	ErrInvalidStatus      = errors.New("nip90: invalid status")
	ErrMissingStatus      = errors.New("nip90: job feedback must have a status tag")
)

const (
	KindJobRequest  = 5000 // lower bound of the 5000-5999 job request range
	KindJobResult   = 6000 // lower bound of the 6000-6999 job result range
	KindJobFeedback = 7000
)

// IsJobRequestKind reports whether kind falls in the 5000-5999 job request range.
func IsJobRequestKind(kind int) bool {
	return kind >= 5000 && kind <= 5999
}

// IsJobResultKind reports whether kind falls in the 6000-6999 job result range.
func IsJobResultKind(kind int) bool {
	return kind >= 6000 && kind <= 6999
}

// JobResultKindFor returns the job-result kind for a given job-request kind:
// results always use a kind 1000 higher than the request they answer.
func JobResultKindFor(requestKind int) int {
	return requestKind + 1000
}

// Input types for the "i" tag's second element.
const (
	InputTypeURL   = "url"
	InputTypeEvent = "event"
	InputTypeJob   = "job"
	InputTypeText  = "text"
)

// Job feedback status values for the "status" tag.
const (
	StatusPaymentRequired = "payment-required"
	StatusProcessing      = "processing"
	StatusError           = "error"
	StatusSuccess         = "success"
	StatusPartial         = "partial"
)

// JobInput is one ["i", data, type, relay, marker] tag.
type JobInput struct {
	Data   string
	Type   string
	Relay  string
	Marker string
}

// JobRequest is a parsed kind 5000-5999 job request event.
type JobRequest struct {
	*nip01.Event
	Inputs          []JobInput
	Output          string
	BidMloki        int64
	Relays          []string
	TargetProviders []string
	Params          map[string][]string
	// Encrypted is true if the request carries an "encrypted" tag, meaning
	// its i/param tags were moved into an encrypted Content payload (see
	// NIP-90's "Encrypted Params" section). Decrypting that payload is the
	// caller's responsibility (NIP-04, using the customer's private key and
	// the target provider's public key).
	Encrypted bool
}

// ParseJobRequest parses and structurally validates a job request event.
func ParseJobRequest(event *nip01.Event) (*JobRequest, error) {
	if !IsJobRequestKind(event.Kind) {
		return nil, fmt.Errorf("%w: got %d, want 5000-5999", ErrWrongKind, event.Kind)
	}

	jr := &JobRequest{Event: event, Params: make(map[string][]string)}

	for _, tag := range event.Tags {
		if len(tag) < 1 {
			continue
		}
		switch tag[0] {
		case "i":
			if len(tag) < 3 {
				return nil, fmt.Errorf("%w: expected [\"i\", data, type, ...], got %v", ErrInvalidInputTag, tag)
			}
			input := JobInput{Data: tag[1], Type: tag[2]}
			switch input.Type {
			case InputTypeURL, InputTypeEvent, InputTypeJob, InputTypeText:
			default:
				return nil, fmt.Errorf("%w: %q", ErrInvalidInputType, input.Type)
			}
			if len(tag) > 3 {
				input.Relay = tag[3]
			}
			if len(tag) > 4 {
				input.Marker = tag[4]
			}
			jr.Inputs = append(jr.Inputs, input)
		case "output":
			if len(tag) < 2 {
				continue
			}
			jr.Output = tag[1]
		case "bid":
			if len(tag) < 2 {
				continue
			}
			bid, err := strconv.ParseInt(tag[1], 10, 64)
			if err != nil || bid < 0 {
				return nil, fmt.Errorf("%w: %q", ErrInvalidBid, tag[1])
			}
			jr.BidMloki = bid
		case "relays":
			for _, r := range tag[1:] {
				u, err := url.ParseRequestURI(r)
				if err != nil {
					return nil, fmt.Errorf("%w %q: %w", ErrInvalidRelayURL, r, err)
				}
				if u.Scheme != "wss" && u.Scheme != "ws" {
					return nil, fmt.Errorf("%w: %q has scheme %q", ErrInvalidRelayScheme, r, u.Scheme)
				}
				jr.Relays = append(jr.Relays, r)
			}
		case "p":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidProviderTag, tag[1], err)
			}
			jr.TargetProviders = append(jr.TargetProviders, tag[1])
		case "param":
			if len(tag) < 3 {
				return nil, fmt.Errorf("%w: expected [\"param\", key, value], got %v", ErrInvalidParamTag, tag)
			}
			jr.Params[tag[1]] = append(jr.Params[tag[1]], tag[2])
		case "encrypted":
			jr.Encrypted = true
		}
	}

	return jr, nil
}

// ValidateJobRequest checks the signature and structure of a job request event.
func ValidateJobRequest(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseJobRequest(event)
	return err
}

// JobRequestParams describes a NIP-90 job request. Pubkey, JobKind, and
// Inputs are required; Output, BidMloki, Relays, TargetProviders, and
// Params are optional.
type JobRequestParams struct {
	Pubkey          string
	JobKind         int
	Inputs          []JobInput
	Output          string
	BidMloki        int64
	Relays          []string
	TargetProviders []string
	Params          map[string]string
}

// NewJobRequest builds an unsigned job request event. JobKind must be in
// the 5000-5999 range. Caller must sign it.
func NewJobRequest(p JobRequestParams) (*nip01.Event, error) {
	if !IsJobRequestKind(p.JobKind) {
		return nil, fmt.Errorf("%w: got %d, want 5000-5999", ErrWrongKind, p.JobKind)
	}

	var tags [][]string
	for _, in := range p.Inputs {
		tag := []string{"i", in.Data, in.Type}
		if in.Relay != "" || in.Marker != "" {
			tag = append(tag, in.Relay)
		}
		if in.Marker != "" {
			tag = append(tag, in.Marker)
		}
		tags = append(tags, tag)
	}
	if p.Output != "" {
		tags = append(tags, []string{"output", p.Output})
	}
	if p.BidMloki > 0 {
		tags = append(tags, []string{"bid", strconv.FormatInt(p.BidMloki, 10)})
	}
	if len(p.Relays) > 0 {
		tags = append(tags, append([]string{"relays"}, p.Relays...))
	}
	for _, provider := range p.TargetProviders {
		tags = append(tags, []string{"p", provider})
	}
	for k, v := range p.Params {
		tags = append(tags, []string{"param", k, v})
	}

	return nip01.NewUnsignedEvent(p.JobKind, p.Pubkey, "", tags...), nil
}

// JobResult is a parsed kind 6000-6999 job result event.
type JobResult struct {
	*nip01.Event
	RequestEventID   string
	RequestRelayHint string
	RequestJSON      string
	CustomerPubkey   string
	AmountMloki      int64
	Bolt11           string
	// Encrypted is true if the result carries an "encrypted" tag; Content is
	// then a NIP-04 encrypted payload the caller must decrypt.
	Encrypted bool
}

// ParseJobResult parses and structurally validates a job result event.
func ParseJobResult(event *nip01.Event) (*JobResult, error) {
	if !IsJobResultKind(event.Kind) {
		return nil, fmt.Errorf("%w: got %d, want 6000-6999", ErrWrongKind, event.Kind)
	}

	jr := &JobResult{Event: event}

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			if len(tag) == 1 && tag[0] == "encrypted" {
				jr.Encrypted = true
			}
			continue
		}
		switch tag[0] {
		case "request":
			jr.RequestJSON = tag[1]
		case "e":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, tag[1], err)
			}
			jr.RequestEventID = tag[1]
			if len(tag) > 2 {
				jr.RequestRelayHint = tag[2]
			}
		case "p":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidProviderTag, tag[1], err)
			}
			jr.CustomerPubkey = tag[1]
		case "amount":
			amt, err := strconv.ParseInt(tag[1], 10, 64)
			if err != nil || amt < 0 {
				return nil, fmt.Errorf("%w: %q", ErrInvalidAmount, tag[1])
			}
			jr.AmountMloki = amt
			if len(tag) > 2 {
				jr.Bolt11 = tag[2]
			}
		case "encrypted":
			jr.Encrypted = true
		}
	}

	if jr.RequestEventID == "" {
		return nil, ErrMissingEventTag
	}

	return jr, nil
}

// ValidateJobResult checks the signature and structure of a job result event.
func ValidateJobResult(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseJobResult(event)
	return err
}

// JobResultParams describes a NIP-90 job result. ProviderPubkey,
// ResultKind, and RequestEvent are required; Content, AmountMloki, and
// Bolt11 are optional.
type JobResultParams struct {
	ProviderPubkey string
	// ResultKind should normally be JobResultKindFor(RequestEvent.Kind).
	ResultKind   int
	RequestEvent *nip01.Event
	Content      string
	AmountMloki  int64
	Bolt11       string
}

// NewJobResult builds an unsigned job result event answering
// p.RequestEvent.
func NewJobResult(p JobResultParams) (*nip01.Event, error) {
	if !IsJobResultKind(p.ResultKind) {
		return nil, fmt.Errorf("%w: got %d, want 6000-6999", ErrWrongKind, p.ResultKind)
	}

	tags := [][]string{
		{"e", p.RequestEvent.ID},
		{"p", p.RequestEvent.PubKey},
	}
	if p.AmountMloki > 0 {
		amountTag := []string{"amount", strconv.FormatInt(p.AmountMloki, 10)}
		if p.Bolt11 != "" {
			amountTag = append(amountTag, p.Bolt11)
		}
		tags = append(tags, amountTag)
	}

	return nip01.NewUnsignedEvent(p.ResultKind, p.ProviderPubkey, p.Content, tags...), nil
}

// JobFeedback is a parsed kind 7000 job feedback event.
type JobFeedback struct {
	*nip01.Event
	Status           string
	StatusExtra      string
	RequestEventID   string
	RequestRelayHint string
	CustomerPubkey   string
	AmountMloki      int64
	Bolt11           string
}

// ParseJobFeedback parses and structurally validates a job feedback event.
func ParseJobFeedback(event *nip01.Event) (*JobFeedback, error) {
	if event.Kind != KindJobFeedback {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindJobFeedback)
	}

	jf := &JobFeedback{Event: event}

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "status":
			switch tag[1] {
			case StatusPaymentRequired, StatusProcessing, StatusError, StatusSuccess, StatusPartial:
			default:
				return nil, fmt.Errorf("%w: %q", ErrInvalidStatus, tag[1])
			}
			jf.Status = tag[1]
			if len(tag) > 2 {
				jf.StatusExtra = tag[2]
			}
		case "e":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, tag[1], err)
			}
			jf.RequestEventID = tag[1]
			if len(tag) > 2 {
				jf.RequestRelayHint = tag[2]
			}
		case "p":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidProviderTag, tag[1], err)
			}
			jf.CustomerPubkey = tag[1]
		case "amount":
			amt, err := strconv.ParseInt(tag[1], 10, 64)
			if err != nil || amt < 0 {
				return nil, fmt.Errorf("%w: %q", ErrInvalidAmount, tag[1])
			}
			jf.AmountMloki = amt
			if len(tag) > 2 {
				jf.Bolt11 = tag[2]
			}
		}
	}

	if jf.Status == "" {
		return nil, ErrMissingStatus
	}
	if jf.RequestEventID == "" {
		return nil, ErrMissingEventTag
	}

	return jf, nil
}

// ValidateJobFeedback checks the signature and structure of a feedback event.
func ValidateJobFeedback(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseJobFeedback(event)
	return err
}

// JobFeedbackParams describes a NIP-90 job feedback event. ProviderPubkey,
// RequestEvent, and Status are required; StatusExtra, Content, and
// AmountMloki are optional.
type JobFeedbackParams struct {
	ProviderPubkey string
	RequestEvent   *nip01.Event
	Status         string
	StatusExtra    string
	Content        string
	AmountMloki    int64
}

// NewJobFeedback builds an unsigned kind 7000 feedback event about
// p.RequestEvent.
func NewJobFeedback(p JobFeedbackParams) *nip01.Event {
	statusTag := []string{"status", p.Status}
	if p.StatusExtra != "" {
		statusTag = append(statusTag, p.StatusExtra)
	}

	tags := [][]string{
		statusTag,
		{"e", p.RequestEvent.ID},
		{"p", p.RequestEvent.PubKey},
	}
	if p.AmountMloki > 0 {
		tags = append(tags, []string{"amount", strconv.FormatInt(p.AmountMloki, 10)})
	}

	return nip01.NewUnsignedEvent(KindJobFeedback, p.ProviderPubkey, p.Content, tags...)
}
