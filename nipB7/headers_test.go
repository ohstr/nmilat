package nipB7

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUploadRequirementsRoundTrip(t *testing.T) {
	want := UploadRequirements{SHA256: testHash, ContentLength: 2048, ContentType: "image/png"}
	h := http.Header{}
	want.SetHeaders(h)

	got, err := ParseUploadRequirements(h)
	if err != nil {
		t.Fatalf("ParseUploadRequirements() error = %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestUploadRequirementsOptionalFieldsOmitted(t *testing.T) {
	got, err := ParseUploadRequirements(http.Header{})
	if err != nil {
		t.Fatalf("ParseUploadRequirements() error = %v", err)
	}
	if got != (UploadRequirements{}) {
		t.Errorf("got %+v, want zero value", got)
	}
}

func TestParseUploadRequirementsErrors(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr error
	}{
		{name: "bad hash", headers: map[string]string{HeaderSHA256: "not-a-hash"}, wantErr: ErrInvalidHash},
		{name: "non-numeric length", headers: map[string]string{HeaderContentLength: "abc"}, wantErr: ErrInvalidContentLength},
		{name: "negative length", headers: map[string]string{HeaderContentLength: "-1"}, wantErr: ErrInvalidContentLength},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			_, err := ParseUploadRequirements(h)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusForbidden, "policy violation")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := ReasonFromResponse(rec.Header()); got != "policy violation" {
		t.Errorf("reason = %q, want %q", got, "policy violation")
	}
}

func TestWriteErrorNoReason(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusNotFound, "")

	if rec.Header().Get(HeaderReason) != "" {
		t.Errorf("expected no X-Reason header, got %q", rec.Header().Get(HeaderReason))
	}
}
