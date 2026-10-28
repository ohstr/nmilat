package nip17

import (
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

// KindDMRelays is a user's list of relays to receive DMs on.
const KindDMRelays = 10050

// WithRecipients tags each pubkey as a recipient ("p"). NIP-17 requires one
// per receiver.
func WithRecipients(pubkeys ...string) ChatMessageOption {
	return func(event *nip01.Event) {
		for _, p := range pubkeys {
			event.Tags = append(event.Tags, []string{"p", strings.ToLower(p)})
		}
	}
}

// WithSubject sets the conversation's subject.
func WithSubject(subject string) ChatMessageOption {
	return func(event *nip01.Event) {
		event.Tags = append(event.Tags, []string{"subject", subject})
	}
}

// WithReply marks id as the message this one answers, the way NIP-17 does:
// an "e" tag with an optional relay hint and no marker.
func WithReply(id, relay string) ChatMessageOption {
	return func(event *nip01.Event) {
		tag := []string{"e", strings.ToLower(id)}
		if relay != "" {
			tag = append(tag, relay)
		}
		event.Tags = append(event.Tags, tag)
	}
}

// ChatMessage is a parsed kind 14.
type ChatMessage struct {
	Recipients []string
	Subject    string
	// ReplyTo is the message this one answers: an "e" with marker "reply",
	// else the first unmarked "e".
	ReplyTo string
	// Root is the "e" marked "root", if any.
	Root    string
	Content string
}

// ParseChatMessage reads a kind 14 rumor's tags.
func ParseChatMessage(ev *nip01.Event) (*ChatMessage, error) {
	if ev.Kind != KindChatMessage {
		return nil, fmt.Errorf("nip17: kind %d is not a chat message (14)", ev.Kind)
	}
	m := &ChatMessage{Recipients: []string{}, Content: ev.Content}
	var unmarked string
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "p":
			m.Recipients = append(m.Recipients, strings.ToLower(t[1]))
		case "subject":
			m.Subject = t[1]
		case "e":
			marker := ""
			if len(t) >= 4 {
				marker = t[3]
			}
			switch marker {
			case "reply":
				m.ReplyTo = t[1]
			case "root":
				m.Root = t[1]
			case "":
				if unmarked == "" {
					unmarked = t[1]
				}
			}
		}
	}
	if m.ReplyTo == "" {
		m.ReplyTo = unmarked
	}
	return m, nil
}

// NewDMRelayList builds a kind 10050 naming relays.
func NewDMRelayList(relays []string) *nip01.Event {
	ev := nip01.NewEvent(KindDMRelays, "")
	ev.Tags = [][]string{}
	for _, r := range relays {
		ev.Tags = append(ev.Tags, []string{"relay", r})
	}
	return ev
}

// ParseDMRelayList returns a kind 10050's relays, in order.
func ParseDMRelayList(ev *nip01.Event) ([]string, error) {
	if ev.Kind != KindDMRelays {
		return nil, fmt.Errorf("nip17: kind %d is not a DM relay list (10050)", ev.Kind)
	}
	relays := []string{}
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == "relay" && t[1] != "" {
			relays = append(relays, t[1])
		}
	}
	return relays, nil
}
