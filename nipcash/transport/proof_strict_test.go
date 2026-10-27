package transport

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// K-PROOF-1, K-PROOF-2: the spec's item and bill proof ids.
func TestKPROOF_SpecIDs(t *testing.T) {
	hash, err := CanonicalParamsHash(nil)
	if err != nil || hash != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Fatalf("ph of {} = %s", hash)
	}
	b := ProofBinding{Target: strings.Repeat("1", 64), HubXOnly: strings.Repeat("2", 64), Method: "cash_status",
		ParamsHash: hash, Nonce: strings.Repeat("3", 64), NotAfter: 1720000060}
	for kind, want := range map[int]string{
		KindItemProof: "a121c54b100a68efbda151d0fe01c4290b7a9ea41c22409e916a0e9cb7aabb0b",
		KindBillProof: "7e4908cda700cd019f244c5c4dafc43c321a23cbc023daec37c6011bfa802c53",
	} {
		ev := &nip01.Event{Kind: kind, PubKey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			CreatedAt: 1720000000, Tags: b.tags()}
		id, _ := ev.HashID()
		if hex.EncodeToString(id) != want {
			t.Errorf("kind %d id %x", kind, id)
		}
	}
}

// T06-06, T06-07, T06-08: the item and bill proof refusals.
func TestT06_06_ProofStrictness(t *testing.T) {
	priv, b := testBinding(t)
	now := time.Now()
	resign := func(kind int, edit func(*nip01.Event)) json.RawMessage {
		ev := &nip01.Event{Kind: kind, CreatedAt: uint64(now.Unix()), Tags: b.tags()}
		edit(ev)
		if err := ev.Sign(priv); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(ev)
		return raw
	}
	set := func(name, v string) func(*nip01.Event) {
		return func(ev *nip01.Event) {
			for _, tag := range ev.Tags {
				if tag[0] == name {
					tag[1] = v
				}
			}
		}
	}
	for _, kind := range []int{KindItemProof, KindBillProof} {
		verify := VerifyItemProof
		if kind == KindBillProof {
			verify = VerifyBillProof
		}
		if _, err := verify(resign(kind, func(*nip01.Event) {}), b, now); err != nil {
			t.Fatalf("kind %d good: %v", kind, err)
		}
		other, _ := NewNonce()
		for name, edit := range map[string]func(*nip01.Event){
			"no expiration":    func(ev *nip01.Event) { ev.Tags = ev.Tags[:5] },
			"wrong expiration": set("expiration", "1"),
			"content":          func(ev *nip01.Event) { ev.Content = "x" },
			"uppercase d":      set("d", strings.ToUpper(b.Target)),
			"uppercase h":      set("h", strings.ToUpper(b.HubXOnly)),
			"uppercase ph":     set("ph", strings.ToUpper(b.ParamsHash)),
			"repeated m":       func(ev *nip01.Event) { ev.Tags = append(ev.Tags, []string{"m", b.Method}) },
			"other d":          set("d", strings.Repeat("9", 64)),
			"other h":          set("h", strings.Repeat("9", 64)),
			"other m":          set("m", b.Method+"x"),
			"other ph":         set("ph", strings.Repeat("9", 64)),
			"other en":         set("en", other),
			"now-301":          func(ev *nip01.Event) { ev.CreatedAt = uint64(now.Unix() - 301) },
		} {
			if _, err := verify(resign(kind, edit), b, now); err == nil {
				t.Errorf("kind %d %s: verified", kind, name)
			}
		}
		if _, err := verify(resign(kind, func(ev *nip01.Event) { ev.CreatedAt = uint64(now.Unix() - 300) }), b, now); err != nil {
			t.Errorf("kind %d now-300: %v", kind, err)
		}
	}
	if _, err := VerifyBillProof(resign(KindItemProof, func(*nip01.Event) {}), b, now); err == nil {
		t.Error("a 23192 verified as a bill proof")
	}
}
