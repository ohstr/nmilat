// Package nip17 implements NIP-17: Private Direct Messages, unencrypted
// kind-14 chat rumors meant to be sealed and gift-wrapped (see nip59)
// before publishing.
package nip17

import (
	"github.com/ohstr/nmilat/nip01"
)

const KindChatMessage = 14

// ChatMessageOption configures thread references on a chat message event.
type ChatMessageOption func(*nip01.Event)

// WithRoot marks id as the root event of the thread this message belongs to.
func WithRoot(id string) ChatMessageOption {
	return func(event *nip01.Event) {
		event.Tags = append(event.Tags, []string{"e", id, "", "root"})
	}
}

// WithReplyTo marks id as the event this message is directly replying to.
func WithReplyTo(id string) ChatMessageOption {
	return func(event *nip01.Event) {
		event.Tags = append(event.Tags, []string{"e", id, "", "reply"})
	}
}

// NewChatMessage builds a kind-14 chat message. A plain call with no
// options produces a standalone message; pass WithRoot and/or WithReplyTo to
// thread it into a conversation.
func NewChatMessage(content string, opts ...ChatMessageOption) *nip01.Event {
	event := nip01.NewEvent(KindChatMessage, content)
	for _, opt := range opts {
		opt(event)
	}
	return event
}
