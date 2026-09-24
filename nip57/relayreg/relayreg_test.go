package relayreg_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip57"
	_ "github.com/ohstr/nmilat/nip57/relayreg"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/testlogger"
)

// The validators this package registers are the relay-ingest ones, not the
// strict ones. Nothing asserted that wiring before, which is how a relay
// came to reject the majority of real zap receipts — so these tests drive a
// real relay over a websocket rather than calling nip57 directly.

const testPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

const recipient = "0000000000000000000000000000000000000000000000000000000000000001"

// lightningAddress is the lnurl tag value real clients publish, which the
// strict validator rejects.
const lightningAddress = "alice@example.com"

func newRelayConn(t *testing.T) *websocket.Conn {
	t.Helper()

	f, err := os.CreateTemp("", "relayreg-test.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	store, err := relay.NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000},
		relay.WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := relay.NewSessionHandler(store, metadata, nil, relay.WithLogger(testlogger.New(t)))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// publish sends an EVENT and returns the relay's OK verdict and message.
func publish(t *testing.T, conn *websocket.Conn, ev *nip01.Event) (bool, string) {
	t.Helper()
	if err := conn.WriteJSON([]any{"EVENT", ev}); err != nil {
		t.Fatalf("write EVENT: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	for {
		var raw []json.RawMessage
		if err := conn.ReadJSON(&raw); err != nil {
			t.Fatalf("read OK: %v", err)
		}
		if len(raw) == 0 {
			continue
		}
		var kind string
		if err := json.Unmarshal(raw[0], &kind); err != nil || kind != "OK" {
			continue
		}
		if len(raw) < 4 {
			t.Fatalf("malformed OK frame: %v", raw)
		}
		var accepted bool
		var message string
		if err := json.Unmarshal(raw[2], &accepted); err != nil {
			t.Fatalf("parse OK verdict: %v", err)
		}
		if err := json.Unmarshal(raw[3], &message); err != nil {
			t.Fatalf("parse OK message: %v", err)
		}
		return accepted, message
	}
}

// stubInvoice makes the shared bolt11 decoder succeed without needing a real
// invoice. The embedded request carries no amount tag, so no amount
// cross-check applies.
func stubInvoice(t *testing.T) {
	t.Helper()
	original := nip57.DecodeBolt11
	t.Cleanup(func() { nip57.DecodeBolt11 = original })
	nip57.DecodeBolt11 = func(string) (*nip57.Invoice, error) { return &nip57.Invoice{}, nil }
}

func signedRequest(t *testing.T, lnurl string) *nip01.Event {
	t.Helper()
	tags := [][]string{
		{"p", recipient},
		{"relays", "wss://relay.example.com"},
	}
	if lnurl != "" {
		tags = append(tags, []string{"lnurl", lnurl})
	}
	ev := &nip01.Event{CreatedAt: uint64(time.Now().Unix()), Kind: nip57.KindZapRequest, Tags: tags}
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return ev
}

func signedReceipt(t *testing.T, req *nip01.Event) *nip01.Event {
	t.Helper()
	desc, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ev := &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      nip57.KindZapReceipt,
		Tags: [][]string{
			{"p", recipient},
			{"bolt11", "lnbc10n1pjqxyz"},
			{"description", string(desc)},
		},
	}
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	return ev
}

func TestRelayAcceptsZapReceiptWithLightningAddressLnurl(t *testing.T) {
	stubInvoice(t)
	receipt := signedReceipt(t, signedRequest(t, lightningAddress))

	// Precondition: the strict validator rejects this receipt, so the test
	// is actually exercising the relay's choice of validator.
	if err := nip57.ValidateZapReceipt(receipt); err == nil {
		t.Fatal("fixture no longer trips the strict validator")
	}

	conn := newRelayConn(t)
	accepted, message := publish(t, conn, receipt)
	if !accepted {
		t.Fatalf("relay rejected a real-world zap receipt: %s", message)
	}
}

func TestRelayAcceptsZapRequestWithLightningAddressLnurl(t *testing.T) {
	req := signedRequest(t, lightningAddress)

	if err := nip57.ValidateZapRequest(req, 0); err == nil {
		t.Fatal("fixture no longer trips the strict validator")
	}

	conn := newRelayConn(t)
	accepted, message := publish(t, conn, req)
	if !accepted {
		t.Fatalf("relay rejected a zap request using a lightning address: %s", message)
	}
}

// MUST-level failures must still be rejected at ingest — the relaxation is
// not a blanket pass.
func TestRelayStillRejectsMalformedZapReceipt(t *testing.T) {
	stubInvoice(t)

	// No bolt11 tag: NIP-57 Appendix E requires it.
	desc, err := json.Marshal(signedRequest(t, lightningAddress))
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ev := &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      nip57.KindZapReceipt,
		Tags: [][]string{
			{"p", recipient},
			{"description", string(desc)},
		},
	}
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}

	conn := newRelayConn(t)
	accepted, message := publish(t, conn, ev)
	if accepted {
		t.Fatal("relay accepted a zap receipt with no bolt11 tag")
	}
	if !strings.Contains(message, "bolt11") {
		t.Errorf("rejection message should name the missing tag, got %q", message)
	}
}

func TestNIP57IsDeclared(t *testing.T) {
	for _, id := range relay.RegisteredNIPs() {
		if id == nip11.NIP(57) {
			return
		}
	}
	t.Error("NIP-57 is not declared in the relay's supported NIPs")
}
