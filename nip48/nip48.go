// Package nip48 implements NIP-48: Proxy tags, which let an event declare
// that it originated on another protocol (ActivityPub, AT Protocol, RSS, or
// the web) and reference its source object there.
package nip48

import (
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	TagNameProxy = "proxy"
)

// Known protocol identifiers for the proxy tag's third element.
const (
	ProtocolActivityPub = "activitypub"
	ProtocolATProto     = "atproto"
	ProtocolRSS         = "rss"
	ProtocolWeb         = "web"
)

// ProxyTag is a parsed ["proxy", <id>, <protocol>] tag.
type ProxyTag struct {
	ID       string
	Protocol string
}

// ParseProxyTag extracts the proxy tag from event, if present.
func ParseProxyTag(event *nip01.Event) (*ProxyTag, error) {
	tag, err := utils.FindUniqueEventTag(event.Tags, TagNameProxy)
	if err != nil {
		return nil, fmt.Errorf("proxy tag: %w", err)
	}
	if len(tag) < 3 {
		return nil, fmt.Errorf("invalid proxy tag, expected [\"proxy\", id, protocol], got %v", tag)
	}
	if tag[1] == "" {
		return nil, fmt.Errorf("invalid proxy tag: empty id")
	}
	if tag[2] == "" {
		return nil, fmt.Errorf("invalid proxy tag: empty protocol")
	}
	return &ProxyTag{ID: tag[1], Protocol: tag[2]}, nil
}

// ValidateProxyTag checks the structural shape of event's proxy tag, if any.
// An event without a proxy tag is valid — NIP-48 is opt-in per event.
func ValidateProxyTag(event *nip01.Event) error {
	if _, ok := utils.LookupEventTag(event.Tags, TagNameProxy); !ok {
		return nil
	}
	_, err := ParseProxyTag(event)
	return err
}

// AddProxyTag appends a ["proxy", id, protocol] tag to ev.
func AddProxyTag(ev *nip01.Event, id, protocol string) {
	ev.AddTag([]string{TagNameProxy, id, protocol})
}
