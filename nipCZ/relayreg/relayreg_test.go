package relayreg_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nipCZ"
	_ "github.com/ohstr/nmilat/nipCZ/relayreg"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/testlogger"
)

func newRelayConn(t *testing.T) *websocket.Conn {
	t.Helper()
	f, err := os.CreateTemp("", "nipcz-relayreg-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	store, err := relay.NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000}, relay.WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	handler := relay.NewSessionHandler(store, &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1 << 20}}, nil, relay.WithLogger(testlogger.New(t)))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		deadline := time.Now().Add(10 * time.Second)
		for handler.SessionCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	})
	return conn
}

func publish(t *testing.T, conn *websocket.Conn, ev *nip01.Event) (bool, string) {
	t.Helper()
	if err := conn.WriteJSON([]any{"EVENT", ev}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var raw []json.RawMessage
		if err := conn.ReadJSON(&raw); err != nil {
			t.Fatal(err)
		}
		var kind string
		if len(raw) < 4 || json.Unmarshal(raw[0], &kind) != nil || kind != "OK" {
			continue
		}
		var ok bool
		var msg string
		_ = json.Unmarshal(raw[2], &ok)
		_ = json.Unmarshal(raw[3], &msg)
		return ok, msg
	}
}

// zap is a valid 9522 on no target (listed, never counted) from an untrusted
// minter, with p replaced by recipient.
func zap(t *testing.T, recipient string) *nip01.Event {
	t.Helper()
	minterPriv, minterX := cashtest.Keypair(t)
	senderPriv, _ := cashtest.Keypair(t)
	_, w := cashtest.Keypair(t)
	secret, _ := cashtest.Keypair(t)
	amt := uint64(21000)
	signer, err := nipcash.LocalMintSigner(minterPriv, "satscash")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := nipcash.SignToken(nipcash.Token{HRP: "satscash", WalletPubkey: w, Secret: secret, RelayURLs: []string{"wss://hub.example"}, AttestedAmountMillis: &amt},
		nipcash.SchemeMintV1, nil, minterX, signer)
	if err != nil {
		t.Fatal(err)
	}
	s, err := nipcash.Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nip01.NewSignedEvent(nipCZ.KindCashZap, "", senderPriv,
		[]string{"p", recipient}, []string{"amount", strconv.FormatUint(amt, 10)}, []string{"chain", "bitcoin"},
		[]string{"cash", s}, []string{"w", w})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// T17-04: a validating relay refuses a malformed 9522, accepts a valid one,
// and never evaluates rule 8 or 9 (S-CZ-50).
func TestRelayValidatesCashZaps(t *testing.T) {
	conn := newRelayConn(t)
	_, recipient := cashtest.Keypair(t)
	if ok, msg := publish(t, conn, zap(t, recipient)); !ok {
		t.Fatalf("valid zap from an untrusted minter refused: %s", msg)
	}
	ok, msg := publish(t, conn, zap(t, strings.ToUpper(recipient)))
	if ok || !strings.HasPrefix(msg, "invalid:") || !strings.Contains(msg, "rule 2") {
		t.Fatalf("malformed zap: %v %q", ok, msg)
	}
	found := false
	for _, n := range relay.RegisteredNIPs() {
		if n.String() == "CZ" {
			found = true
		}
	}
	if !found {
		t.Fatal("NIP-CZ not declared")
	}
}
