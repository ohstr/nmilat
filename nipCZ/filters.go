package nipCZ

import (
	"net/url"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

// IncomingFilter is the query for Cash Zaps to a user (NIP-CZ §Receiving): #p
// with the user's pubkey and every ConnectionKey linked to them through NIP-IC.
// The relays to send it to are IncomingRelays'.
func IncomingFilter(recipient string, linkedCKs []string) nip01.SubscriptionFilter {
	p := append([]string{recipient}, dedup(linkedCKs, recipient)...)
	return nip01.SubscriptionFilter{Kinds: []int{KindCashZap}, Tags: map[string][]string{"p": p}}
}

// SentFilters are the queries for Cash Zaps a user sent: authors = the user,
// and #P with the ConnectionKeys linked to them (never a Nostr pubkey; the
// user's own pubkey is dropped). The second filter is omitted without one.
func SentFilters(user string, linkedCKs []string) []nip01.SubscriptionFilter {
	out := []nip01.SubscriptionFilter{{Kinds: []int{KindCashZap}, Authors: []string{user}}}
	if cks := dedup(linkedCKs, user); len(cks) > 0 {
		out = append(out, nip01.SubscriptionFilter{Kinds: []int{KindCashZap}, Tags: map[string][]string{"P": cks}})
	}
	return out
}

func dedup(list []string, drop string) []string {
	var out []string
	for _, s := range list {
		if s != "" && s != drop && !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// PublishRelays are where a sender publishes a 9522 (NIP-CZ §Sending 3): the
// recipient's 10522 relays, else their NIP-65 read relays; the sender's write
// relays; and, for a ConnectionKey recipient, its identity connection's relays
// (an nconnection's TLV 1). Normalised and deduplicated, in that order.
func PublishRelays(info *CashZapInfo, recipientNIP65Read, senderWrite, icRelays []string) []string {
	return normalizeRelays(readRelays(info, recipientNIP65Read), senderWrite, icRelays)
}

// IncomingRelays are where a wallet reads Cash Zaps to its user: the user's own
// 10522 relays, else their NIP-65 read relays (the sender's fallback), plus every
// linked ConnectionKey's identity connection relays. For the same 10522 and
// NIP-65 list, PublishRelays(info, read, nil, ic) is a subset of it.
func IncomingRelays(own *CashZapInfo, ownNIP65Read, icRelays []string) []string {
	return normalizeRelays(readRelays(own, ownNIP65Read), icRelays)
}

func readRelays(info *CashZapInfo, nip65Read []string) []string {
	if info != nil && len(info.Relays) > 0 {
		return info.Relays
	}
	return nip65Read
}

// normalizeRelays lowercases scheme and host, drops a default port, a trailing
// slash, a query and a fragment, refuses anything but ws:// and wss://, and
// keeps the first of each.
func normalizeRelays(lists ...[]string) []string {
	var out []string
	for _, list := range lists {
		for _, r := range list {
			n, ok := normalizeRelay(r)
			if ok && !contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

func normalizeRelay(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", false
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "wss" && port == "443") || (u.Scheme == "ws" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	if port != "" {
		u.Host += ":" + port
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath, u.RawQuery, u.Fragment, u.User = "", "", "", nil
	return u.String(), true
}
