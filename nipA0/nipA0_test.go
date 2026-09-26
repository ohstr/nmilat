package nipA0

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip22"
	"github.com/ohstr/nmilat/utils"
)

const (
	testPubkeyA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testEventID  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testPrivKey  = "0acd1245d4b0e9cae1a3b0e1a1e0cf3d1e5b2a7c8d9e0f1a2b3c4d5e6f70268c"
	testAudioURL = "https://blossom.primal.net/5fe7df0e46ee6b14b5a8b8b92939e84e3ca5e3950eb630299742325d5ed9891b.mp4"
)

func ev(kind int, content string, tags ...[]string) *nip01.Event {
	return &nip01.Event{Kind: kind, PubKey: testPubkeyA, Content: content, Tags: tags}
}

func TestIsVoiceMessageKind(t *testing.T) {
	for _, kind := range []int{KindVoiceMessage, KindVoiceMessageReply} {
		if !IsVoiceMessageKind(kind) {
			t.Errorf("IsVoiceMessageKind(%d) = false", kind)
		}
	}
	for _, kind := range []int{1, 1111, 1221, 1223, 1243, 1245} {
		if IsVoiceMessageKind(kind) {
			t.Errorf("IsVoiceMessageKind(%d) = true", kind)
		}
	}
}

func TestParseVoiceMessage(t *testing.T) {
	// The spec's own example imeta tag.
	specWaveform := "0 7 35 8 100 100 49 8 4 16 8 10 7 2 20 10"

	tests := []struct {
		name         string
		kind         int
		content      string
		tags         [][]string
		wantErrIs    error
		wantURL      string
		wantWaveLen  int
		wantDuration int
		wantDurSet   bool
	}{
		{
			name:    "bare url, no imeta",
			kind:    KindVoiceMessage,
			content: testAudioURL,
			wantURL: testAudioURL,
		},
		{
			name:    "spec example with imeta",
			kind:    KindVoiceMessage,
			content: testAudioURL,
			tags: [][]string{{
				ImetaTagName,
				"url " + testAudioURL,
				"waveform " + specWaveform,
				"duration 8",
			}},
			wantURL:      testAudioURL,
			wantWaveLen:  16,
			wantDuration: 8,
			wantDurSet:   true,
		},
		{
			name:    "content is trimmed",
			kind:    KindVoiceMessage,
			content: "  " + testAudioURL + "  ",
			wantURL: testAudioURL,
		},
		{
			name:       "duration zero is distinguishable from absent",
			kind:       KindVoiceMessage,
			content:    testAudioURL,
			tags:       [][]string{{ImetaTagName, "duration 0"}},
			wantURL:    testAudioURL,
			wantDurSet: true,
		},
		{
			name:      "empty content",
			kind:      KindVoiceMessage,
			content:   "",
			wantErrIs: ErrMissingURL,
		},
		{
			name:      "content is not a url",
			kind:      KindVoiceMessage,
			content:   "listen to this",
			wantErrIs: ErrMissingURL,
		},
		{
			name:      "content has a url plus prose",
			kind:      KindVoiceMessage,
			content:   testAudioURL + " listen!",
			wantErrIs: ErrMissingURL,
		},
		{
			name:      "non-integer waveform value",
			kind:      KindVoiceMessage,
			content:   testAudioURL,
			tags:      [][]string{{ImetaTagName, "waveform 0 7 loud 8"}},
			wantErrIs: ErrInvalidWaveform,
		},
		{
			name:      "non-numeric duration",
			kind:      KindVoiceMessage,
			content:   testAudioURL,
			tags:      [][]string{{ImetaTagName, "duration eight"}},
			wantErrIs: ErrInvalidDuration,
		},
		{
			name:      "negative duration",
			kind:      KindVoiceMessage,
			content:   testAudioURL,
			tags:      [][]string{{ImetaTagName, "duration -3"}},
			wantErrIs: ErrInvalidDuration,
		},
		{
			name:      "wrong kind",
			kind:      nip22.KindComment,
			content:   testAudioURL,
			wantErrIs: ErrWrongKind,
		},
		{
			name:        "negative waveform values are allowed through",
			kind:        KindVoiceMessage,
			content:     testAudioURL,
			tags:        [][]string{{ImetaTagName, "waveform -5 0 5"}},
			wantURL:     testAudioURL,
			wantWaveLen: 3,
		},
		{
			name:    "imeta field without a value is skipped",
			kind:    KindVoiceMessage,
			content: testAudioURL,
			tags:    [][]string{{ImetaTagName, "waveform", "duration 4"}},
			wantURL: testAudioURL, wantDuration: 4, wantDurSet: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := ParseVoiceMessage(ev(tc.kind, tc.content, tc.tags...))
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if msg.URL != tc.wantURL {
				t.Errorf("URL = %q, want %q", msg.URL, tc.wantURL)
			}
			if len(msg.Waveform) != tc.wantWaveLen {
				t.Errorf("waveform len = %d, want %d", len(msg.Waveform), tc.wantWaveLen)
			}
			if msg.Duration != tc.wantDuration || msg.DurationSet != tc.wantDurSet {
				t.Errorf("duration = %d/%v, want %d/%v", msg.Duration, msg.DurationSet, tc.wantDuration, tc.wantDurSet)
			}
		})
	}
}

func TestRecommendedDurationIsAdviceNotAnError(t *testing.T) {
	long := ev(KindVoiceMessage, testAudioURL, []string{ImetaTagName, "duration 3600"})

	msg, err := ParseVoiceMessage(long)
	if err != nil {
		t.Fatalf("an over-long voice message must still parse: %v", err)
	}
	if !msg.ExceedsRecommendedDuration() {
		t.Error("ExceedsRecommendedDuration() = false for an hour-long message")
	}

	atLimit := ev(KindVoiceMessage, testAudioURL, []string{ImetaTagName, "duration " + strconv.Itoa(RecommendedMaxDuration)})
	msg, err = ParseVoiceMessage(atLimit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.ExceedsRecommendedDuration() {
		t.Error("exactly the recommended maximum should not count as exceeding it")
	}

	noDuration, err := ParseVoiceMessage(ev(KindVoiceMessage, testAudioURL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if noDuration.ExceedsRecommendedDuration() {
		t.Error("an absent duration must not read as exceeding the recommendation")
	}
}

func TestWaveformBeyondRecommendedCountStillParses(t *testing.T) {
	values := make([]string, RecommendedMaxWaveformValues+50)
	for i := range values {
		values[i] = "50"
	}
	event := ev(KindVoiceMessage, testAudioURL, []string{ImetaTagName, "waveform " + strings.Join(values, " ")})

	msg, err := ParseVoiceMessage(event)
	if err != nil {
		t.Fatalf("an over-long waveform is advice-breaking, not invalid: %v", err)
	}
	if len(msg.Waveform) != RecommendedMaxWaveformValues+50 {
		t.Errorf("waveform len = %d, want %d", len(msg.Waveform), RecommendedMaxWaveformValues+50)
	}
}

func TestNewVoiceMessageRoundTrip(t *testing.T) {
	built := NewVoiceMessage(VoiceMessageParams{
		Pubkey:      testPubkeyA,
		URL:         testAudioURL,
		Waveform:    []int{0, 7, 35, 100},
		Duration:    8,
		DurationSet: true,
	})
	if built.Kind != KindVoiceMessage {
		t.Fatalf("Kind = %d", built.Kind)
	}
	if built.Content != testAudioURL {
		t.Errorf("Content = %q, want the bare url", built.Content)
	}

	msg, err := ParseVoiceMessage(built)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if len(msg.Waveform) != 4 || msg.Waveform[2] != 35 {
		t.Errorf("waveform = %v", msg.Waveform)
	}
	if msg.Duration != 8 || !msg.DurationSet {
		t.Errorf("duration = %d/%v", msg.Duration, msg.DurationSet)
	}
	if msg.MediaURL != testAudioURL {
		t.Errorf("MediaURL = %q", msg.MediaURL)
	}
	if msg.IsReply() {
		t.Error("IsReply() = true for a kind 1222 root")
	}
}

func TestNewVoiceMessageOmitsEmptyImeta(t *testing.T) {
	built := NewVoiceMessage(VoiceMessageParams{Pubkey: testPubkeyA})
	for _, tag := range built.Tags {
		if len(tag) >= 1 && tag[0] == ImetaTagName {
			t.Fatalf("an imeta tag with nothing to preview should be omitted: %v", tag)
		}
	}
}

func TestVoiceMessageReplyFollowsNIP22(t *testing.T) {
	rootAddr, err := utils.FormatATag(30311, testPubkeyA, "stream-1")
	if err != nil {
		t.Fatalf("FormatATag: %v", err)
	}

	scopes := nip22.CommentParams{
		Root: nip22.ScopeParams{
			Pointer: nip22.PointerParams{Type: nip22.PointerAddress, Value: rootAddr},
			Kind:    "30311",
		},
		Parent: nip22.ScopeParams{
			Pointer: nip22.PointerParams{Type: nip22.PointerEvent, Value: testEventID, AuthorPubkey: testPubkeyA},
			Kind:    strconv.Itoa(KindVoiceMessage),
		},
	}

	built, err := NewVoiceMessageReply(VoiceMessageParams{
		Pubkey:      testPubkeyA,
		URL:         testAudioURL,
		Duration:    4,
		DurationSet: true,
	}, scopes)
	if err != nil {
		t.Fatalf("NewVoiceMessageReply: %v", err)
	}
	if built.Kind != KindVoiceMessageReply {
		t.Fatalf("Kind = %d, want %d", built.Kind, KindVoiceMessageReply)
	}

	msg, err := ParseVoiceMessage(built)
	if err != nil {
		t.Fatalf("reply did not parse as a voice message: %v", err)
	}
	if !msg.IsReply() || msg.Duration != 4 {
		t.Errorf("unexpected: %+v", msg)
	}

	root, parent, err := ReplyScopes(built)
	if err != nil {
		t.Fatalf("ReplyScopes: %v", err)
	}
	if root.Pointer.Value != rootAddr || root.Kind != "30311" {
		t.Errorf("root = %+v", root)
	}
	if parent.Pointer.Value != testEventID || parent.Kind != strconv.Itoa(KindVoiceMessage) {
		t.Errorf("parent = %+v", parent)
	}

	// The uppercase root / lowercase parent tag pairs are NIP-22's structure;
	// their presence is what "MUST follow the structure of NIP-22" means.
	var haveUpper, haveLower bool
	for _, tag := range built.Tags {
		if len(tag) == 0 {
			continue
		}
		switch tag[0] {
		case "A", "E", "I":
			haveUpper = true
		case "a", "e", "i":
			haveLower = true
		}
	}
	if !haveUpper || !haveLower {
		t.Errorf("reply is missing NIP-22 root/parent tag pairs: %v", built.Tags)
	}
}

func TestReplyScopesRejectsRootKind(t *testing.T) {
	built := NewVoiceMessage(VoiceMessageParams{Pubkey: testPubkeyA, URL: testAudioURL})
	if _, _, err := ReplyScopes(built); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("err = %v, want ErrWrongKind", err)
	}
}

func TestReplyScopesDoesNotMutateItsInput(t *testing.T) {
	rootAddr, err := utils.FormatATag(30311, testPubkeyA, "s")
	if err != nil {
		t.Fatalf("FormatATag: %v", err)
	}
	built, err := NewVoiceMessageReply(VoiceMessageParams{Pubkey: testPubkeyA, URL: testAudioURL}, nip22.CommentParams{
		Root:   nip22.ScopeParams{Pointer: nip22.PointerParams{Type: nip22.PointerAddress, Value: rootAddr}, Kind: "30311"},
		Parent: nip22.ScopeParams{Pointer: nip22.PointerParams{Type: nip22.PointerAddress, Value: rootAddr}, Kind: "30311"},
	})
	if err != nil {
		t.Fatalf("NewVoiceMessageReply: %v", err)
	}

	if _, _, err := ReplyScopes(built); err != nil {
		t.Fatalf("ReplyScopes: %v", err)
	}
	if built.Kind != KindVoiceMessageReply {
		t.Fatalf("ReplyScopes changed the event's kind to %d", built.Kind)
	}
}

func TestValidateVoiceMessage(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	t.Run("unsigned is rejected", func(t *testing.T) {
		built := NewVoiceMessage(VoiceMessageParams{Pubkey: pubkey, URL: testAudioURL})
		if err := ValidateVoiceMessage(built); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("err = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("signed is accepted", func(t *testing.T) {
		built := NewVoiceMessage(VoiceMessageParams{Pubkey: pubkey, URL: testAudioURL, Duration: 3, DurationSet: true})
		if err := built.Sign(testPrivKey); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := ValidateVoiceMessage(built); err != nil {
			t.Fatalf("ValidateVoiceMessage: %v", err)
		}
	})

	t.Run("signed but structurally broken is rejected", func(t *testing.T) {
		built := NewVoiceMessage(VoiceMessageParams{Pubkey: pubkey, URL: "not a url"})
		if err := built.Sign(testPrivKey); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := ValidateVoiceMessage(built); !errors.Is(err, ErrMissingURL) {
			t.Fatalf("err = %v, want ErrMissingURL", err)
		}
	})
}
