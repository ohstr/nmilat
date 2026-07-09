package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip05"
	"github.com/ohstr/nmilat/nip11"
)

const (
	nip05RelayPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	nip05RelayPubKey  = "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"
)

func TestNIP05HandlerRegister(t *testing.T) {

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
			"sub.ieee.az", "a730cedb98530f155ea75abe5646562329ce7adc3875696586f4698c21aed1b7",
			[]string{"wss://sub.cc.local", "ws://sub.sub.vv.local/connect"},
			true, 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newStore(t)

			nip05Event := &nip01.Event{
				Kind:      nip05.Kind,
				PubKey:    nip05RelayPubKey,
				CreatedAt: uint64(time.Now().Unix()),
				Tags: [][]string{
					{"d", test.name},
					append([]string{"p", test.pubkey}, test.relays...),
					{"domain", domain},
				},
			}
			if err := nip05Event.Sign(nip05RelayPrivKey); err != nil {
				t.Fatal(err)
			}

			InsertTestEvents(t, store, []*nip01.Event{nip05Event})

			response := queryNIP05(t, store, test.name)

			if pubkey, ok := response.Names[test.name]; (test.expectedName && !ok) || (test.expectedName && pubkey != test.pubkey) {
				t.Fatalf("unexpected names want=%s got=%s", test.name, response.Names)
			}

			if relays, ok := response.Relays[test.name]; (test.expectedRelays > 0 && !ok) || (len(relays) != test.expectedRelays) {
				t.Fatalf("unexpected relays want=%d got=%s", test.expectedRelays, response.Relays)
			}
		})
	}
}

var nip05Metadata = &nip11.Metadata{PubKey: nip05RelayPubKey, Limitation: nip11.Limitation{MaxLimit: 10_000}}

func TestNIP05HandlerRequest(t *testing.T) {

	store := newStore(t)

	srv := httptest.NewServer(NewNIP05Handler(store, nip05Metadata))

	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var identityResponse nip05.IdentityResponse
	if err := json.Unmarshal(data, &identityResponse); err != nil {
		t.Fatal(err)
	}

	t.Logf("res=%v", identityResponse)
}

func queryNIP05(t *testing.T, store *EventStore, name string) *nip05.IdentityResponse {

	srv := httptest.NewServer(NewNIP05Handler(store, nip05Metadata))

	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Get(fmt.Sprintf("%s?name=%s", srv.URL, name))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var identityResponse nip05.IdentityResponse
	if err := json.Unmarshal(data, &identityResponse); err != nil {
		t.Logf("err=%v", string(data))
		t.Fatal(err)
	}

	return &identityResponse
}
