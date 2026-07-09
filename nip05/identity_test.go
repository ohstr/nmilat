package nip05

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const (
	relayPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	relayPubKey  = "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"
)

func TestBuildIdentityResponse(t *testing.T) {
	domain := "nostr.local"

	tests := []struct {
		name           string
		pubkey         string
		relays         []string
		expectedName   bool
		expectedRelays int
	}{
		{
			"_", "a211a75d08c56b08fbbacd6a195ba071528e1aa669d7740b0db1264280aaeb8b",
			[]string{"ws://aa.local", "ws://vv.local", "ws://cc.local"},
			true, 3,
		},
		{
			"aaaaa", "a6848376ab8fc3ed4a7284ce0855e304cf577df00933614b3685c0007fa8",
			[]string{"ws://aa.local", "ws://vv.local", "ws://cc.local"},
			false, 0,
		},
		{
			"Bbbbb", "a4c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9",
			[]string{"ws://aa.local", "ws://vv.local", "ws://cc.local"},
			true, 3,
		},
		{
			"cc$cc", "afe2eef018c82a87f13129997718bf3d91d44f18cb51fca6a8744c6fe7a03dfb",
			[]string{"ws://aa.local", "ws://vv.local", "ws://cc.local"},
			false, 0,
		},
		{
			"dd_dd", "a69e2302ad430028ffecb8c3729931d7dcd7d0a7295a1a49e5d876f081ac560c",
			[]string{"ws://aa.local"},
			true, 1,
		},
		{
			"z10-zz", "a730cedb98530f155ea75abe5646562329ce7adc3875696586f4698c21aed1b7",
			[]string{},
			true, 0,
		},
		{
			"pre.pre_z10zz", "a730cedb98530f155ea75abe5646562329ce7adc3875696586f4698c21aed1b7",
			[]string{"http://aa.local"},
			true, 0,
		},
		{
			"sub.ieee.az", "a730cedb98530f155ea75abe5646562329ce7adc3875696586f4698c21aed1b7",
			[]string{"wss://sub.cc.local", "ws://sub.sub.vv.local/connect"},
			true, 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := &nip01.Event{
				Kind:      Kind,
				PubKey:    relayPubKey,
				CreatedAt: uint64(time.Now().Unix()),
				Tags: [][]string{
					{"d", test.name},
					append([]string{"p", test.pubkey}, test.relays...),
					{"domain", domain},
				},
			}
			if err := event.Sign(relayPrivKey); err != nil {
				t.Fatal(err)
			}

			response := BuildIdentityResponse([]*nip01.Event{event})

			if pubkey, ok := response.Names[test.name]; (test.expectedName && !ok) || (test.expectedName && pubkey != test.pubkey) {
				t.Fatalf("unexpected names want=%s got=%s", test.name, response.Names)
			}

			if relays, ok := response.Relays[test.name]; (test.expectedRelays > 0 && !ok) || (len(relays) != test.expectedRelays) {
				t.Fatalf("unexpected relays want=%d got=%s", test.expectedRelays, response.Relays)
			}
		})
	}
}

func TestBuildIdentityResponse_SkipsUnparseable(t *testing.T) {
	badEvent := &nip01.Event{Kind: Kind, Tags: [][]string{{"d", ""}}}

	response := BuildIdentityResponse([]*nip01.Event{badEvent})

	if len(response.Names) != 0 || len(response.Relays) != 0 {
		t.Errorf("expected an unparseable event to be skipped, got %+v", response)
	}
}
