package nipB7

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewReportAndParse(t *testing.T) {
	ev, err := NewReport("", []ReportedBlob{
		{Hash: testHash, Type: "malware"},
	}, "this file contains malware")
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}
	ev = signed(t, ev)

	report, err := ParseReport(ev)
	if err != nil {
		t.Fatalf("ParseReport() error = %v", err)
	}
	if len(report.Blobs) != 1 || report.Blobs[0].Hash != testHash || report.Blobs[0].Type != "malware" {
		t.Errorf("Blobs = %+v", report.Blobs)
	}

	if err := ValidateReport(ev); err != nil {
		t.Errorf("ValidateReport() error = %v", err)
	}
}

func TestNewReportMultipleBlobs(t *testing.T) {
	other := "b" + testHash[1:]
	ev, err := NewReport("", []ReportedBlob{
		{Hash: testHash, Type: "nudity"},
		{Hash: other, Type: "spam"},
	}, "batch report")
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}

	report, err := ParseReport(ev)
	if err != nil {
		t.Fatalf("ParseReport() error = %v", err)
	}
	if len(report.Blobs) != 2 {
		t.Fatalf("len(Blobs) = %d, want 2", len(report.Blobs))
	}
}

func TestNewReportErrors(t *testing.T) {
	if _, err := NewReport("", nil, "reason"); !errors.Is(err, ErrEmptyReport) {
		t.Errorf("err = %v, want ErrEmptyReport", err)
	}
	if _, err := NewReport("", []ReportedBlob{{Hash: "not-a-hash"}}, "reason"); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("err = %v, want ErrInvalidHash", err)
	}
}

func TestParseReportIgnoresNonXTags(t *testing.T) {
	ev := &nip01.Event{
		Kind: KindReport,
		Tags: [][]string{{"p", "somepubkey"}, {"e", "someeventid"}, {"x", testHash, "spam"}},
	}
	report, err := ParseReport(ev)
	if err != nil {
		t.Fatalf("ParseReport() error = %v", err)
	}
	if len(report.Blobs) != 1 || report.Blobs[0].Hash != testHash {
		t.Errorf("Blobs = %+v", report.Blobs)
	}
}

func TestParseReportErrors(t *testing.T) {
	tests := []struct {
		name    string
		kind    int
		tags    [][]string
		wantErr error
	}{
		{name: "wrong kind", kind: 1, tags: [][]string{{"x", testHash}}, wantErr: ErrWrongReportKind},
		{name: "no x tags", kind: KindReport, tags: nil, wantErr: ErrEmptyReport},
		{name: "bad hash", kind: KindReport, tags: [][]string{{"x", "not-a-hash"}}, wantErr: ErrInvalidHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			_, err := ParseReport(ev)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateReportBadSignature(t *testing.T) {
	ev, err := NewReport("", []ReportedBlob{{Hash: testHash}}, "reason")
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}
	if err := ValidateReport(ev); err == nil {
		t.Error("expected error for unsigned event")
	}
}
