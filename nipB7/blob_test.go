package nipB7

import (
	"errors"
	"testing"
)

func validDescriptor() BlobDescriptor {
	return BlobDescriptor{
		URL:      "https://cdn.example/" + testHash,
		Sha256:   testHash,
		Size:     1024,
		Type:     "image/png",
		Uploaded: 1700000000,
	}
}

func TestBlobDescriptorValidate(t *testing.T) {
	d := validDescriptor()
	if err := d.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

func TestBlobDescriptorValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*BlobDescriptor)
		wantErr error
	}{
		{name: "missing url", mutate: func(d *BlobDescriptor) { d.URL = "" }, wantErr: ErrMissingURL},
		{name: "bad hash", mutate: func(d *BlobDescriptor) { d.Sha256 = "not-a-hash" }, wantErr: ErrInvalidHash},
		{name: "zero size", mutate: func(d *BlobDescriptor) { d.Size = 0 }, wantErr: ErrInvalidSize},
		{name: "negative size", mutate: func(d *BlobDescriptor) { d.Size = -1 }, wantErr: ErrInvalidSize},
		{name: "zero uploaded", mutate: func(d *BlobDescriptor) { d.Uploaded = 0 }, wantErr: ErrInvalidUploaded},
		{name: "negative uploaded", mutate: func(d *BlobDescriptor) { d.Uploaded = -1 }, wantErr: ErrInvalidUploaded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := validDescriptor()
			tt.mutate(&d)
			err := d.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSortDescending(t *testing.T) {
	descriptors := []BlobDescriptor{
		{Sha256: testHash, Uploaded: 100},
		{Sha256: testHash, Uploaded: 300},
		{Sha256: testHash, Uploaded: 200},
	}
	SortDescending(descriptors)
	want := []int64{300, 200, 100}
	for i, w := range want {
		if descriptors[i].Uploaded != w {
			t.Errorf("descriptors[%d].Uploaded = %d, want %d", i, descriptors[i].Uploaded, w)
		}
	}
}

func TestListQueryEncode(t *testing.T) {
	q := ListQuery{Cursor: testHash, Limit: 10, Since: 111, Until: 222}
	values := q.Encode()
	if values.Get("cursor") != testHash {
		t.Errorf("cursor = %q, want %q", values.Get("cursor"), testHash)
	}
	if values.Get("limit") != "10" {
		t.Errorf("limit = %q, want 10", values.Get("limit"))
	}
	if values.Get("since") != "111" {
		t.Errorf("since = %q, want 111", values.Get("since"))
	}
	if values.Get("until") != "222" {
		t.Errorf("until = %q, want 222", values.Get("until"))
	}
}

func TestListQueryEncodeEmpty(t *testing.T) {
	values := ListQuery{}.Encode()
	if len(values) != 0 {
		t.Errorf("Encode() = %v, want empty", values)
	}
}
