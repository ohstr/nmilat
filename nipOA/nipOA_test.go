package nipOA

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// Official NIP-OA test vectors, transcribed verbatim from the spec.
const (
	vectorOwnerPubkey  = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	vectorAgentPubkey  = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	vectorConditions   = "kind=1&created_at<1713957000"
	vectorPreimage     = "nostr:agent-auth:c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5:kind=1&created_at<1713957000"
	vectorSHA256Digest = "08cdecd55af4c28d3801fd69615dcf5cc04fab3bc134b38a840bf157197069a6"
	vectorSig          = "8b7df2575caf0a108374f8471722b233c53f9ff827a8b0f91861966c3b9dd5cb2e189eae9f49d72187674c2f5bd244145e10ff86c9f257ffe65a1ee5f108b369"
)

func vectorTag() []string {
	return []string{"auth", vectorOwnerPubkey, vectorConditions, vectorSig}
}

func TestPreimage_MatchesOfficialVector(t *testing.T) {
	got := string(Preimage(vectorAgentPubkey, vectorConditions))
	if got != vectorPreimage {
		t.Fatalf("Preimage() = %q, want %q", got, vectorPreimage)
	}
}

func TestSHA256Preimage_MatchesOfficialVector(t *testing.T) {
	digest := sha256.Sum256(Preimage(vectorAgentPubkey, vectorConditions))
	got := hex.EncodeToString(digest[:])
	if got != vectorSHA256Digest {
		t.Fatalf("sha256(preimage) = %s, want %s", got, vectorSHA256Digest)
	}
}

func TestVerifySignature_OfficialVector(t *testing.T) {
	if err := VerifySignature(vectorOwnerPubkey, vectorAgentPubkey, vectorConditions, vectorSig); err != nil {
		t.Fatalf("VerifySignature() on the official vector: %v", err)
	}
}

func TestParseAuthTag_OfficialVector(t *testing.T) {
	tags := [][]string{vectorTag()}

	tag, err := ParseAuthTag(tags, vectorAgentPubkey)
	if err != nil {
		t.Fatalf("ParseAuthTag() on the official vector: %v", err)
	}
	if tag == nil {
		t.Fatal("ParseAuthTag() = nil, want a parsed Tag")
	}
	if tag.OwnerPubkey != vectorOwnerPubkey {
		t.Errorf("OwnerPubkey = %q, want %q", tag.OwnerPubkey, vectorOwnerPubkey)
	}
	if tag.Sig != vectorSig {
		t.Errorf("Sig = %q, want %q", tag.Sig, vectorSig)
	}
	if len(tag.Conditions.Kinds) != 1 || tag.Conditions.Kinds[0] != 1 {
		t.Errorf("Conditions.Kinds = %v, want [1]", tag.Conditions.Kinds)
	}
	if len(tag.Conditions.CreatedAtLT) != 1 || tag.Conditions.CreatedAtLT[0] != 1713957000 {
		t.Errorf("Conditions.CreatedAtLT = %v, want [1713957000]", tag.Conditions.CreatedAtLT)
	}
	if tag.Conditions.Raw != vectorConditions {
		t.Errorf("Conditions.Raw = %q, want %q", tag.Conditions.Raw, vectorConditions)
	}
}

func TestParseAuthTag_NoAuthTag_ReturnsNilNil(t *testing.T) {
	tag, err := ParseAuthTag([][]string{{"p", vectorOwnerPubkey}}, vectorAgentPubkey)
	if err != nil {
		t.Fatalf("ParseAuthTag() with no auth tag: err = %v, want nil", err)
	}
	if tag != nil {
		t.Fatalf("ParseAuthTag() with no auth tag: tag = %v, want nil", tag)
	}
}

// Official invalid vectors, transcribed verbatim.
func TestParseAuthTag_OfficialInvalidVectors(t *testing.T) {
	tests := []struct {
		name      string
		tags      [][]string
		event     string
		wantErrIs error
	}{
		{
			name: "two auth tags",
			tags: [][]string{
				vectorTag(),
				vectorTag(),
			},
			event:     vectorAgentPubkey,
			wantErrIs: ErrMultipleAuthTags,
		},
		{
			name:      "fewer than four elements",
			tags:      [][]string{{"auth", vectorOwnerPubkey, vectorConditions}},
			event:     vectorAgentPubkey,
			wantErrIs: ErrWrongElementCount,
		},
		{
			name:      "more than four elements",
			tags:      [][]string{{"auth", vectorOwnerPubkey, vectorConditions, vectorSig, "extra"}},
			event:     vectorAgentPubkey,
			wantErrIs: ErrWrongElementCount,
		},
		{
			name:      "conditions trailing delimiter",
			tags:      [][]string{{"auth", vectorOwnerPubkey, "kind=1&", vectorSig}},
			event:     vectorAgentPubkey,
			wantErrIs: ErrMalformedConditions,
		},
		{
			name:      "conditions leading zero",
			tags:      [][]string{{"auth", vectorOwnerPubkey, "kind=01", vectorSig}},
			event:     vectorAgentPubkey,
			wantErrIs: ErrMalformedConditions,
		},
		{
			name:      "self-attestation",
			tags:      [][]string{{"auth", vectorAgentPubkey, vectorConditions, vectorSig}},
			event:     vectorAgentPubkey,
			wantErrIs: ErrSelfAttestation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAuthTag(tt.tags, tt.event)
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("ParseAuthTag() err = %v, want errors.Is(_, %v)", err, tt.wantErrIs)
			}
		})
	}
}

func TestParseConditions(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Conditions
		wantErr error
	}{
		{
			name: "empty string, no constraints",
			raw:  "",
			want: Conditions{Raw: ""},
		},
		{
			name: "single kind clause",
			raw:  "kind=1",
			want: Conditions{Kinds: []int{1}, Raw: "kind=1"},
		},
		{
			name: "single created_at< clause",
			raw:  "created_at<100",
			want: Conditions{CreatedAtLT: []uint64{100}, Raw: "created_at<100"},
		},
		{
			name: "single created_at> clause",
			raw:  "created_at>100",
			want: Conditions{CreatedAtGT: []uint64{100}, Raw: "created_at>100"},
		},
		{
			name: "multiple clauses",
			raw:  "kind=1&created_at>100&created_at<200",
			want: Conditions{Kinds: []int{1}, CreatedAtGT: []uint64{100}, CreatedAtLT: []uint64{200}, Raw: "kind=1&created_at>100&created_at<200"},
		},
		{
			name: "conjunctive kind footgun still parses -- never satisfiable, not this package's concern",
			raw:  "kind=1&kind=7",
			want: Conditions{Kinds: []int{1, 7}, Raw: "kind=1&kind=7"},
		},
		{
			name: "lone zero is canonical",
			raw:  "kind=0",
			want: Conditions{Kinds: []int{0}, Raw: "kind=0"},
		},
		{
			name:    "leading zero rejected",
			raw:     "kind=01",
			wantErr: ErrMalformedConditions,
		},
		{
			name:    "trailing ampersand rejected",
			raw:     "kind=1&",
			wantErr: ErrMalformedConditions,
		},
		{
			name:    "leading ampersand rejected",
			raw:     "&kind=1",
			wantErr: ErrMalformedConditions,
		},
		{
			name:    "doubled ampersand rejected",
			raw:     "kind=1&&created_at<100",
			wantErr: ErrMalformedConditions,
		},
		{
			name:    "non-digit value rejected",
			raw:     "kind=1a",
			wantErr: ErrMalformedConditions,
		},
		{
			name:    "kind out of range",
			raw:     "kind=65536",
			wantErr: ErrMalformedConditions,
		},
		{
			name:    "created_at out of range",
			raw:     "created_at<4294967296",
			wantErr: ErrMalformedConditions,
		},
		{
			name:    "unsupported clause name",
			raw:     "foo=1",
			wantErr: ErrUnsupportedClause,
		},
		{
			name:    "whitespace rejected",
			raw:     "kind=1 ",
			wantErr: ErrMalformedConditions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseConditions(tt.raw)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseConditions(%q) err = %v, want errors.Is(_, %v)", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConditions(%q) unexpected err: %v", tt.raw, err)
			}
			if got.Raw != tt.want.Raw || !intSliceEqual(got.Kinds, tt.want.Kinds) ||
				!u64SliceEqual(got.CreatedAtLT, tt.want.CreatedAtLT) || !u64SliceEqual(got.CreatedAtGT, tt.want.CreatedAtGT) {
				t.Fatalf("ParseConditions(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestConditions_EvaluateKind(t *testing.T) {
	tests := []struct {
		name string
		cond Conditions
		kind int
		want bool
	}{
		{name: "no clauses, always satisfied", cond: Conditions{}, kind: 1, want: true},
		{name: "matching single clause", cond: Conditions{Kinds: []int{1}}, kind: 1, want: true},
		{name: "non-matching single clause", cond: Conditions{Kinds: []int{1}}, kind: 7, want: false},
		{name: "conjunctive footgun never satisfiable", cond: Conditions{Kinds: []int{1, 7}}, kind: 1, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cond.EvaluateKind(tt.kind); got != tt.want {
				t.Errorf("EvaluateKind(%d) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}

func TestConditions_EvaluateTimeClauses(t *testing.T) {
	tests := []struct {
		name      string
		cond      Conditions
		createdAt uint64
		want      bool
	}{
		{name: "no clauses, always satisfied", cond: Conditions{}, createdAt: 100, want: true},
		{name: "created_at< satisfied", cond: Conditions{CreatedAtLT: []uint64{200}}, createdAt: 100, want: true},
		{name: "created_at< violated at boundary", cond: Conditions{CreatedAtLT: []uint64{200}}, createdAt: 200, want: false},
		{name: "created_at< violated above", cond: Conditions{CreatedAtLT: []uint64{200}}, createdAt: 300, want: false},
		{name: "created_at> satisfied", cond: Conditions{CreatedAtGT: []uint64{100}}, createdAt: 200, want: true},
		{name: "created_at> violated at boundary", cond: Conditions{CreatedAtGT: []uint64{100}}, createdAt: 100, want: false},
		{name: "both satisfied", cond: Conditions{CreatedAtGT: []uint64{100}, CreatedAtLT: []uint64{200}}, createdAt: 150, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cond.EvaluateTimeClauses(tt.createdAt); got != tt.want {
				t.Errorf("EvaluateTimeClauses(%d) = %v, want %v", tt.createdAt, got, tt.want)
			}
		})
	}
}

func TestVerifySignature_RejectsWrongSignature(t *testing.T) {
	// Flip a hex digit in the signature -- must fail cryptographic
	// verification, not merely hex-decode successfully.
	badSig := "9" + vectorSig[1:]
	if err := VerifySignature(vectorOwnerPubkey, vectorAgentPubkey, vectorConditions, badSig); err == nil {
		t.Fatal("VerifySignature() with a forged signature: want error, got nil")
	}
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func u64SliceEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func BenchmarkVerifySignature(b *testing.B) {
	for b.Loop() {
		if err := VerifySignature(vectorOwnerPubkey, vectorAgentPubkey, vectorConditions, vectorSig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAuthTag(b *testing.B) {
	tags := [][]string{vectorTag()}
	for b.Loop() {
		if _, err := ParseAuthTag(tags, vectorAgentPubkey); err != nil {
			b.Fatal(err)
		}
	}
}
