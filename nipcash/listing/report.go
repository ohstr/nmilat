package listing

import (
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
)

// ReportReason is why a user reports a node (§Reports).
type ReportReason string

// The four reasons of §Reports.
const (
	// ReasonNoPayout: took a payment and minted nothing (NIP-56 other, label
	// no_payout).
	ReasonNoPayout ReportReason = "no_payout"
	// ReasonImpersonation: pretends to be someone else (NIP-56 impersonation).
	ReasonImpersonation ReportReason = "impersonation"
	// ReasonSpam: spam or a fake listing (NIP-56 spam).
	ReasonSpam ReportReason = "spam"
	// ReasonTermsMismatch: terms differ from the listing (NIP-56 other, label
	// terms_mismatch).
	ReasonTermsMismatch ReportReason = "terms_mismatch"
)

// nip56Type is the NIP-56 type put on p and e, and labelled reports their label.
func (r ReportReason) nip56Type() (typ string, labelled bool, ok bool) {
	switch r {
	case ReasonNoPayout, ReasonTermsMismatch:
		return "other", true, true
	case ReasonImpersonation, ReasonSpam:
		return string(r), false, true
	}
	return "", false, false
}

// ErrReport is a kind-1984 event ParseReport refuses.
var ErrReport = errors.New("listing: not a valid report")

// Report is a parsed kind 1984 about a node identity. Addr and ListingID are
// optional; when Addr names another offer than the one shown, a wallet says so.
// Reason is the cash.report label when present, else the NIP-56 type on p as
// written (which may be one outside ReportReason's four).
type Report struct {
	Event     *nip01.Event
	Author    string
	Node      string
	Addr      string
	ListingID string
	Content   string
	Reason    ReportReason
}

// NewReport builds an unsigned report on node (§Reports): p with the reason's
// NIP-56 type; a when addr is set; e with the type when listingID is set; the
// cash.report label for no_payout and terms_mismatch. content is the user's own
// text, never pre-filled.
func NewReport(node, addr, listingID string, r ReportReason, content string) *nip01.Event {
	typ, labelled, ok := r.nip56Type()
	if !ok {
		typ = "other"
	}
	tags := [][]string{{"p", node, typ}}
	if addr != "" {
		tags = append(tags, []string{"a", addr})
	}
	if listingID != "" {
		tags = append(tags, []string{"e", listingID, typ})
	}
	if labelled {
		tags = append(tags, []string{"L", ReportNamespace}, []string{"l", string(r), ReportNamespace})
	}
	return nip01.NewEvent(KindReport, content, tags...)
}

// ParseReport reads a signed report. p is required.
func ParseReport(ev *nip01.Event) (*Report, error) {
	if ev == nil || ev.Kind != KindReport {
		return nil, fmt.Errorf("%w: kind", ErrReport)
	}
	if err := ev.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReport, err)
	}
	r := &Report{Event: ev, Author: ev.PubKey, Content: ev.Content}
	var typ, label string
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "p":
			if r.Node == "" && isHex64(t[1]) {
				r.Node = t[1]
				if len(t) > 2 {
					typ = t[2]
				}
			}
		case "a":
			if r.Addr == "" {
				r.Addr = t[1]
			}
		case "e":
			if r.ListingID == "" {
				r.ListingID = t[1]
			}
		case "l":
			if label == "" && len(t) > 2 && t[2] == ReportNamespace {
				label = t[1]
			}
		}
	}
	if r.Node == "" {
		return nil, fmt.Errorf("%w: no p", ErrReport)
	}
	r.Reason = ReportReason(typ)
	if label != "" {
		r.Reason = ReportReason(label)
	}
	return r, nil
}
