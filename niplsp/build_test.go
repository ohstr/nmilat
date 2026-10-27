package niplsp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// T23-01: NewAnnouncement reproduces K-LSP-1, the NIP-LSP example, byte for byte.
func TestNewAnnouncementKLSP1(t *testing.T) {
	ev, err := NewAnnouncement(exampleFields(), exampleCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != Kind || ev.PubKey != key1Pub || ev.CreatedAt != exampleCreatedAt {
		t.Fatalf("header %d %s %d", ev.Kind, ev.PubKey, ev.CreatedAt)
	}
	if ev.Content != "Inbound channels and just-in-time channels." {
		t.Fatalf("content %q", ev.Content)
	}
	if !reflect.DeepEqual(ev.Tags, exampleTags) {
		t.Fatalf("tags\n got %q\nwant %q", ev.Tags, exampleTags)
	}
	if ev.ID != exampleID {
		t.Fatalf("id %s, want %s", ev.ID, exampleID)
	}
	if ev.Sig != "" {
		t.Fatal("NewAnnouncement signed")
	}

	// The node id form of the key gives the same event.
	f := exampleFields()
	f.NodeKey = "02" + strings.ToUpper(key1Pub)
	ev2, err := NewAnnouncement(f, exampleCreatedAt)
	if err != nil || ev2.ID != exampleID {
		t.Fatalf("node id form: %v %v", err, ev2)
	}
}

func TestNewAnnouncementDefaults(t *testing.T) {
	f := exampleFields()
	f.Status = ""
	f.Expiration = 0
	f.Display = Display{}
	f.Relays = nil
	ev, err := NewAnnouncement(f, exampleCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if v := findTag(ev, TagStatus); v[1] != "open" {
		t.Fatalf("status %q", v)
	}
	if v := findTag(ev, TagExpiration); v[1] != "1795305600" {
		t.Fatalf("expiration %q", v)
	}
	if v := findTag(ev, TagAlt); v[1] != AltPrefix {
		t.Fatalf("alt %q", v)
	}
	for _, name := range []string{TagTitle, TagWebsite, TagImage, TagOperator, TagLabelNS, TagLabel, TagRelay} {
		if findTag(ev, name) != nil {
			t.Fatalf("empty %s written", name)
		}
	}
	if ev.Content != "" {
		t.Fatal("content")
	}

	// An operator without a relay hint, an image, two languages.
	f = exampleFields()
	f.Display.Operator = &Operator{Pubkey: key2Pub}
	f.Display.Image = "https://lsp.example.com/logo.png"
	f.Display.Languages = []string{"en", "fr"}
	ev, err = NewAnnouncement(f, exampleCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if v := findTag(ev, TagOperator); len(v) != 2 {
		t.Fatalf("p %q", v)
	}
	var labels int
	for _, tag := range ev.Tags {
		if tag[0] == TagLabel {
			labels++
		}
	}
	if labels != 2 || findTag(ev, TagImage) == nil {
		t.Fatal("labels or image")
	}
}

// T23-02: NewAnnouncement refusals.
func TestNewAnnouncementRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Fields)
		at   int64
		want error
	}{
		{"expiration 30 days + 1 s", func(f *Fields) { f.Expiration = exampleCreatedAt + MaxExpirySecs + 1 }, 0, ErrExpiryTooFar},
		{"expiration at created_at", func(f *Fields) { f.Expiration = exampleCreatedAt }, 0, ErrExpiryTooFar},
		{"protocol 2 without a fee row", func(f *Fields) { f.LSPS2 = nil }, 0, ErrNoFeeRow},
		{"duplicate lsps1 option", func(f *Fields) { f.LSPS1 = append(f.LSPS1, Option{"max_channel_balance", "1"}) }, 0, ErrDuplicateOption},
		{"duplicate lsps5 field", func(f *Fields) { f.LSPS5 = append(f.LSPS5, Option{"max_webhooks", "1"}) }, 0, ErrDuplicateOption},
		{"http image", func(f *Fields) { f.Display.Image = "http://lsp.example.com/logo.png" }, 0, ErrNotHTTPS},
		{"http website", func(f *Fields) { f.Display.Website = "http://lsp.example.com" }, 0, ErrNotHTTPS},
		{"website with a bidi control", func(f *Fields) { f.Display.Website = "https://lsp.example.com/\u202egro" }, 0, ErrNotHTTPS},
		{"non-ASCII website", func(f *Fields) { f.Display.Website = "https://lsp.exämple.com" }, 0, ErrNotHTTPS},
		{"malformed addr", func(f *Fields) { f.Addrs = []string{"lsp.example.com:9735"} }, 0, ErrBadAddr},
		{"unbracketed IPv6 addr", func(f *Fields) { f.Addrs = []string{"2001:db8::1:9735"} }, 0, ErrBadAddr},
		{"no addr", func(f *Fields) { f.Addrs = nil }, 0, ErrBadAddr},
		{"content of 281 characters", func(f *Fields) { f.Display.Content = strings.Repeat("a", 281) }, 0, ErrContentTooLong},
		{"lsps1 without protocol 1", func(f *Fields) { f.Protocols = []int{2, 5} }, 0, ErrProtocolGating},
		{"lsps2_fee without protocol 2", func(f *Fields) { f.Protocols = []int{1, 5} }, 0, ErrProtocolGating},
		{"lsps5 without protocol 5", func(f *Fields) { f.Protocols = []int{1, 2} }, 0, ErrProtocolGating},
		{"node key", func(f *Fields) { f.NodeKey = "04" + key1Pub }, 0, ErrNodeKey},
		{"chain", func(f *Fields) { f.Chain = "Bitcoin" }, 0, ErrInvalidFields},
		{"network", func(f *Fields) { f.Network = "main" }, 0, ErrInvalidFields},
		{"status", func(f *Fields) { f.Status = "gone" }, 0, ErrInvalidFields},
		{"no protocol", func(f *Fields) { f.Protocols = nil; f.LSPS1, f.LSPS2, f.LSPS5 = nil, nil, nil }, 0, ErrInvalidFields},
		{"protocol 0", func(f *Fields) { f.Protocols = append(f.Protocols, 0) }, 0, ErrInvalidFields},
		{"protocol twice", func(f *Fields) { f.Protocols = append(f.Protocols, 1) }, 0, ErrInvalidFields},
		{"lsps1 boolean as number", func(f *Fields) { f.LSPS1[2].Value = "0" }, 0, ErrInvalidFields},
		{"lsps1 leading zero", func(f *Fields) { f.LSPS1[1].Value = "06" }, 0, ErrInvalidFields},
		{"lsps1 unit suffix", func(f *Fields) { f.LSPS1[9].Name = "max_channel_balance_sat" }, 0, ErrInvalidFields},
		{"unknown lsps1 option text", func(f *Fields) { f.LSPS1 = append(f.LSPS1, Option{"new_option", "x"}) }, 0, ErrInvalidFields},
		{"operator pubkey", func(f *Fields) { f.Display.Operator.Pubkey = "abc" }, 0, ErrInvalidFields},
		{"operator relay", func(f *Fields) { f.Display.Operator.Relay = "https://relay.example.com" }, 0, ErrInvalidFields},
		{"language", func(f *Fields) { f.Display.Languages = []string{"eng"} }, 0, ErrInvalidFields},
		{"language twice", func(f *Fields) { f.Display.Languages = []string{"en", "en"} }, 0, ErrInvalidFields},
		{"relay", func(f *Fields) { f.Relays = []string{"relay.example.com"} }, 0, ErrInvalidFields},
		{"negative created_at", func(*Fields) {}, -1, ErrInvalidFields},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := exampleFields()
			c.edit(&f)
			at := c.at
			if at == 0 {
				at = exampleCreatedAt
			}
			_, err := NewAnnouncement(f, at)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	// 280 characters, counted as user-perceived characters, is allowed.
	f := exampleFields()
	f.Display.Content = strings.Repeat("é", 280)
	if _, err := NewAnnouncement(f, exampleCreatedAt); err != nil {
		t.Fatal(err)
	}
	f.Display.Content = strings.Repeat("👍🏽", 280)
	if _, err := NewAnnouncement(f, exampleCreatedAt); err != nil {
		t.Fatal(err)
	}
	// Exactly 30 days is allowed; so is an unknown lsps1 option of plain form.
	f = exampleFields()
	f.Expiration = exampleCreatedAt + MaxExpirySecs
	f.LSPS1 = append(f.LSPS1, Option{"new_option", "7"})
	if _, err := NewAnnouncement(f, exampleCreatedAt); err != nil {
		t.Fatal(err)
	}
}

// T23-12: NodeIDs and SigningPayload.
func TestNodeIDs(t *testing.T) {
	ids := NodeIDs(key1Pub)
	if ids[0] != "02"+key1Pub || ids[1] != "03"+key1Pub {
		t.Fatalf("%q", ids)
	}
	if NodeIDs(strings.ToUpper(key1Pub)) != ids {
		t.Fatal("case")
	}
}

func TestSigningPayload(t *testing.T) {
	ev, err := NewAnnouncement(exampleFields(), exampleCreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SigningPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	ser, _ := ev.Serialize()
	if string(payload) != string(ser) || !strings.HasPrefix(string(payload), `[0,"`+key1Pub+`",1792713600,10735,[["addr",`) {
		t.Fatalf("payload %s", payload)
	}

	for _, kind := range []int{0, 1, 3, 10002, 10734, 10736, 30735, 22242} {
		other := ev.Copy()
		other.Kind = kind
		other.ID = ""
		if _, err := SigningPayload(other); !errors.Is(err, ErrWrongKind) {
			t.Fatalf("kind %d: %v", kind, err)
		}
		if err := Sign(context.Background(), other, localSigner(t, key1Priv)); !errors.Is(err, ErrWrongKind) || other.Sig != "" {
			t.Fatalf("Sign kind %d: %v", kind, err)
		}
	}
	if _, err := SigningPayload(nil); err == nil {
		t.Fatal("nil event")
	}
	stale := ev.Copy()
	stale.Content = "changed after the id"
	if _, err := SigningPayload(stale); !errors.Is(err, ErrInvalidFields) {
		t.Fatalf("stale id: %v", err)
	}
	upper := ev.Copy()
	upper.PubKey = strings.ToUpper(upper.PubKey)
	if _, err := SigningPayload(upper); !errors.Is(err, ErrNodeKey) {
		t.Fatalf("uppercase pubkey: %v", err)
	}
}

func TestSign(t *testing.T) {
	ev := signed(t, exampleFields(), exampleCreatedAt)
	if ev.ID != exampleID || ev.Verify() != nil {
		t.Fatalf("signed example: %s %v", ev.ID, ev.Verify())
	}

	// A signer holding another key: refused, the event left unsigned.
	ev2, _ := NewAnnouncement(exampleFields(), exampleCreatedAt)
	err := Sign(context.Background(), ev2, localSigner(t, "0000000000000000000000000000000000000000000000000000000000000002"))
	if !errors.Is(err, ErrSignature) || ev2.Sig != "" {
		t.Fatalf("wrong key: %v", err)
	}
	// A signer that signs the id instead of hashing the payload.
	wrong := func(ctx context.Context, payload []byte) ([]byte, error) {
		id, _ := ev2.HashID()
		return localSigner(t, key1Priv)(ctx, id)
	}
	if err := Sign(context.Background(), ev2, wrong); !errors.Is(err, ErrSignature) {
		t.Fatalf("double hash: %v", err)
	}
	failing := func(context.Context, []byte) ([]byte, error) { return nil, errors.New("rpc down") }
	if err := Sign(context.Background(), ev2, failing); err == nil || ev2.Sig != "" {
		t.Fatalf("failing signer: %v", err)
	}
	short := func(context.Context, []byte) ([]byte, error) { return []byte{1, 2, 3}, nil }
	if err := Sign(context.Background(), ev2, short); !errors.Is(err, ErrSignature) {
		t.Fatalf("short signature: %v", err)
	}
	if err := Sign(context.Background(), ev2, nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("nil signer: %v", err)
	}
}

func TestDialectMappers(t *testing.T) {
	cases := []struct {
		in   string
		name string
		unit Unit
	}{
		{"max_channel_balance_sat", "max_channel_balance", UnitBase},
		{"max_channel_balance_loki", "max_channel_balance", UnitBase},
		{"min_fee_msat", "min_fee", UnitMillis},
		{"min_fee_mloki", "min_fee", UnitMillis},
		{"proportional", "proportional", UnitNone},
		{"_sat", "_sat", UnitNone},
	}
	for _, c := range cases {
		n, u := FromLSPSName(c.in)
		if n != c.name || u != c.unit {
			t.Fatalf("%s: %s %d", c.in, n, u)
		}
	}
	if ToLSPSName("min_fee", UnitMillis, DialectLoki) != "min_fee_mloki" ||
		ToLSPSName("min_fee", UnitMillis, DialectSat) != "min_fee_msat" ||
		ToLSPSName("min_channel_balance", UnitBase, DialectLoki) != "min_channel_balance_loki" ||
		ToLSPSName("min_channel_balance", UnitBase, DialectSat) != "min_channel_balance_sat" ||
		ToLSPSName("proportional", UnitNone, DialectLoki) != "proportional" {
		t.Fatal("ToLSPSName")
	}
	for _, o := range append(append([]knownOption{}, lsps1Options...), feeRowFields[:]...) {
		for _, d := range []Dialect{DialectSat, DialectLoki} {
			n, u := FromLSPSName(ToLSPSName(o.Name, o.Unit, d))
			if n != o.Name || u != o.Unit {
				t.Fatalf("round trip %s", o.Name)
			}
		}
	}
	if len(LSPS1OptionNames()) != 10 || LSPS5FieldNames()[0] != "max_webhooks" {
		t.Fatal("names")
	}
}

func TestSanitizeText(t *testing.T) {
	cases := []struct {
		in      string
		max     int
		oneLine bool
		want    string
	}{
		{"Alice's Liquidity", MaxTitle, true, "Alice's Liquidity"},
		{"Alice​'s‮ Liq✓uidity✅", MaxTitle, true, "Alice's Liquidity"},
		{"two\nlines\tand\r\ntabs\x00", MaxTitle, true, "two lines and tabs"},
		{"two\nlines\x07", MaxContent, false, "two\nlines"},
		{strings.Repeat("a", 50), MaxTitle, true, strings.Repeat("a", 40)},
		{strings.Repeat("👍🏽", 41), MaxTitle, true, strings.Repeat("👍🏽", 40)},
		{"  padded  ", MaxTitle, true, "padded"},
		{"https://evil.example", MaxTitle, true, "https://evil.example"},
		// As listing.SanitizeText: a variation selector after a mark goes with it.
		{"Alice \u2705\ufe0f", MaxTitle, true, "Alice"},
		{"a\u2714\ufe0f\nb", MaxContent, false, "a\nb"},
	}
	for _, c := range cases {
		if got := sanitizeText(c.in, c.max, c.oneLine); got != c.want {
			t.Fatalf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}
