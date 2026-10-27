package relay

import (
	"strings"
	"time"
)

// Observer receives relay activity for metrics. Its methods are called on
// the hot path, so they must be cheap, non-blocking and safe for concurrent
// use. Every argument is a small value type, so a call never allocates.
type Observer interface {
	SessionOpened()
	SessionClosed()
	// Message counts one client message by type; MsgMalformed is one that
	// could not be parsed.
	Message(MessageType)
	// EventHandled reports one EVENT's outcome and how long it took from
	// receipt to the OK reply.
	EventHandled(EventResult, RejectReason, KindClass, time.Duration)
	// ReqServed reports a REQ's stored-events pass: time to EOSE and events
	// delivered before it.
	ReqServed(d time.Duration, events int)
	// ReadRefused counts a REQ or COUNT the relay refused.
	ReadRefused(RejectReason)
	CountServed(time.Duration)
	// SubscriptionsChanged moves the relay-wide open subscription count.
	SubscriptionsChanged(delta int)
	SubscriptionLimitHit()
	// Auth reports a NIP-42 AUTH; reason is ReasonNone when accepted.
	Auth(accepted bool, reason RejectReason)
	// Sent reports one websocket write.
	Sent(d time.Duration, failed bool)
}

// StoreObserver receives event store activity. Same rules as Observer.
type StoreObserver interface {
	// BatchCommitted reports one write transaction of n tasks.
	BatchCommitted(n int, d time.Duration, failed bool)
	// ScanBusy counts a read refused for want of a scan slot.
	ScanBusy()
	// IndexBatchCommitted reports one write transaction of a derived index
	// operation (rebuild, catch-up, rescore, reap); index is constant.
	IndexBatchCommitted(index string, d time.Duration)
}

// NopObserver discards everything. Embed it to implement only some methods.
type NopObserver struct{}

func (NopObserver) SessionOpened()                                                   {}
func (NopObserver) SessionClosed()                                                   {}
func (NopObserver) Message(MessageType)                                              {}
func (NopObserver) EventHandled(EventResult, RejectReason, KindClass, time.Duration) {}
func (NopObserver) ReqServed(time.Duration, int)                                     {}
func (NopObserver) ReadRefused(RejectReason)                                         {}
func (NopObserver) CountServed(time.Duration)                                        {}
func (NopObserver) SubscriptionsChanged(int)                                         {}
func (NopObserver) SubscriptionLimitHit()                                            {}
func (NopObserver) Auth(bool, RejectReason)                                          {}
func (NopObserver) Sent(time.Duration, bool)                                         {}
func (NopObserver) BatchCommitted(int, time.Duration, bool)                          {}
func (NopObserver) ScanBusy()                                                        {}
func (NopObserver) IndexBatchCommitted(string, time.Duration)                        {}

// MessageType is a client message's type.
type MessageType uint8

const (
	MsgEvent MessageType = iota
	MsgReq
	MsgClose
	MsgAuth
	MsgCount
	MsgNeg
	MsgMalformed
	numMessageTypes
)

var messageTypeNames = [numMessageTypes]string{"EVENT", "REQ", "CLOSE", "AUTH", "COUNT", "NEG", "malformed"}

func (m MessageType) String() string {
	if m < numMessageTypes {
		return messageTypeNames[m]
	}
	return "unknown"
}

// MessageTypes lists every MessageType, for pre-registering metric labels.
func MessageTypes() []MessageType {
	out := make([]MessageType, numMessageTypes)
	for i := range out {
		out[i] = MessageType(i)
	}
	return out
}

// EventResult is how an EVENT ended.
type EventResult uint8

const (
	EventAccepted EventResult = iota
	EventDuplicate
	EventRejected
	// EventCommand is a NIP-43 or NIP-29 request the relay acted on rather
	// than stored; its handler sends its own OK.
	EventCommand
	numEventResults
)

var eventResultNames = [numEventResults]string{"accepted", "duplicate", "rejected", "command"}

func (r EventResult) String() string {
	if r < numEventResults {
		return eventResultNames[r]
	}
	return "unknown"
}

// EventResults lists every EventResult.
func EventResults() []EventResult {
	out := make([]EventResult, numEventResults)
	for i := range out {
		out[i] = EventResult(i)
	}
	return out
}

// RejectReason is the NIP-01 machine-readable prefix of a refusal.
type RejectReason uint8

const (
	ReasonNone RejectReason = iota
	ReasonInvalid
	ReasonPow
	ReasonAuthRequired
	ReasonRestricted
	ReasonBlocked
	ReasonRateLimited
	ReasonMute
	ReasonError
	// ReasonBusy is "error: relay busy": the store or a scan slot did not
	// answer in time.
	ReasonBusy
	ReasonOther
	numRejectReasons
)

var rejectReasonNames = [numRejectReasons]string{"none", "invalid", "pow", "auth-required", "restricted", "blocked", "rate-limited", "mute", "error", "busy", "other"}

func (r RejectReason) String() string {
	if r < numRejectReasons {
		return rejectReasonNames[r]
	}
	return "unknown"
}

// RejectReasons lists every RejectReason.
func RejectReasons() []RejectReason {
	out := make([]RejectReason, numRejectReasons)
	for i := range out {
		out[i] = RejectReason(i)
	}
	return out
}

const relayBusyPrefix = "error: relay busy"

// ParseRejectReason maps a NIP-01 OK/CLOSED message to its reason by prefix.
// It does not allocate.
func ParseRejectReason(msg string) RejectReason {
	if msg == "" {
		return ReasonNone
	}
	if strings.HasPrefix(msg, relayBusyPrefix) {
		return ReasonBusy
	}
	prefix, _, found := strings.Cut(msg, ":")
	if !found {
		return ReasonOther
	}
	switch prefix {
	case "invalid", "auth-error":
		return ReasonInvalid
	case "pow":
		return ReasonPow
	case "auth-required":
		return ReasonAuthRequired
	case "restricted":
		return ReasonRestricted
	case "blocked":
		return ReasonBlocked
	case "rate-limited":
		return ReasonRateLimited
	case "mute":
		return ReasonMute
	case "error":
		return ReasonError
	}
	return ReasonOther
}

// KindClass groups event kinds into a small fixed set, so a metric label
// stays bounded whatever kinds clients send.
type KindClass uint8

const (
	KindMetadata KindClass = iota
	KindNote
	KindContacts
	KindDM
	KindDeletion
	KindRepost
	KindReaction
	KindGiftWrap
	KindChannel
	KindGroup
	KindZap
	KindList
	KindLongForm
	KindReplaceable
	KindEphemeral
	KindAddressable
	KindOther
	numKindClasses
)

var kindClassNames = [numKindClasses]string{"metadata", "note", "contacts", "dm", "deletion", "repost", "reaction", "giftwrap", "channel", "group", "zap", "list", "long-form", "replaceable", "ephemeral", "addressable", "other"}

func (k KindClass) String() string {
	if k < numKindClasses {
		return kindClassNames[k]
	}
	return "unknown"
}

// KindClasses lists every KindClass.
func KindClasses() []KindClass {
	out := make([]KindClass, numKindClasses)
	for i := range out {
		out[i] = KindClass(i)
	}
	return out
}

// ClassifyKind returns kind's KindClass.
func ClassifyKind(kind int) KindClass {
	switch kind {
	case 0:
		return KindMetadata
	case 1, 1111:
		return KindNote
	case 3:
		return KindContacts
	case 4, 14, 15:
		return KindDM
	case 5:
		return KindDeletion
	case 6, 16:
		return KindRepost
	case 7:
		return KindReaction
	case 1059, 1060:
		return KindGiftWrap
	case 40, 41, 42, 43, 44:
		return KindChannel
	case 9734, 9735, 9520, 9521, 9522, 9523:
		return KindZap
	case 30023, 30024:
		return KindLongForm
	}
	switch {
	case kind >= 9000 && kind <= 9030, kind >= 39000 && kind <= 39009:
		return KindGroup
	case kind >= 10000 && kind < 20000:
		if kind >= 10000 && kind <= 10102 {
			return KindList
		}
		return KindReplaceable
	case kind >= 20000 && kind < 30000:
		return KindEphemeral
	case kind >= 30000 && kind <= 30030:
		return KindList
	case kind >= 30000 && kind < 40000:
		return KindAddressable
	}
	return KindOther
}

// WithObserver sets SessionConfig.Observer.
func WithObserver(o Observer) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.Observer = o
	}
}

// WithEventStoreObserver sets EventStoreConfig.Observer.
func WithEventStoreObserver(o StoreObserver) EventStoreOption {
	return func(cfg *EventStoreConfig) {
		cfg.Observer = o
	}
}

// observer returns c.Observer, or a NopObserver when it is unset, so call
// sites never nil-check and a hand-built Session or SessionConfig still
// works.
func (c *SessionConfig) observer() Observer {
	if c == nil || c.Observer == nil {
		return NopObserver{}
	}
	return c.Observer
}

func (s *EventStore) observer() StoreObserver {
	if s.obs == nil {
		return NopObserver{}
	}
	return s.obs
}
