package nipB7

import (
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
)

// KindReport is the kind of a BUD-09 blob report: a NIP-56-shaped report
// event submitted to a server's PUT /report endpoint (not published to a
// relay — it's carried directly in the HTTP request body, self-authenticated
// by its own signature).
const KindReport = 1984

// Failure modes for NewReport/ParseReport/ValidateReport, for callers that
// need to distinguish them (e.g. via errors.Is) rather than match on
// message text.
var (
	ErrWrongReportKind = errors.New("nipB7: wrong kind for report event")
	ErrEmptyReport     = errors.New("nipB7: report must reference at least one blob")
)

// ReportedBlob is one blob a Report flags, with the NIP-56 report type
// (e.g. "nudity", "malware", "illegal", "spam") describing why.
type ReportedBlob struct {
	Hash string
	Type string
}

// Report is a parsed kind:1984 BUD-09 blob report.
type Report struct {
	*nip01.Event
	Blobs []ReportedBlob
}

// ParseReport parses and structurally validates a kind:1984 event: wrong
// kind, no "x" tags, or an "x" tag whose hash isn't sha256-shaped are all
// rejected.
func ParseReport(event *nip01.Event) (*Report, error) {
	if event.Kind != KindReport {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongReportKind, event.Kind, KindReport)
	}

	var blobs []ReportedBlob
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "x" {
			continue
		}
		if !IsSHA256Hex(tag[1]) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidHash, tag[1])
		}
		blob := ReportedBlob{Hash: tag[1]}
		if len(tag) >= 3 {
			blob.Type = tag[2]
		}
		blobs = append(blobs, blob)
	}
	if len(blobs) == 0 {
		return nil, ErrEmptyReport
	}
	return &Report{Event: event, Blobs: blobs}, nil
}

// ValidateReport checks the signature and structure of a report event.
func ValidateReport(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseReport(event)
	return err
}

// NewReport builds an unsigned kind:1984 event flagging blobs, with reason
// as the human-readable report content. Caller must sign it.
func NewReport(pubkey string, blobs []ReportedBlob, reason string) (*nip01.Event, error) {
	if len(blobs) == 0 {
		return nil, ErrEmptyReport
	}
	tags := make([][]string, 0, len(blobs))
	for _, blob := range blobs {
		if !IsSHA256Hex(blob.Hash) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidHash, blob.Hash)
		}
		tag := []string{"x", blob.Hash}
		if blob.Type != "" {
			tag = append(tag, blob.Type)
		}
		tags = append(tags, tag)
	}
	return nip01.NewUnsignedEvent(KindReport, pubkey, reason, tags...), nil
}
