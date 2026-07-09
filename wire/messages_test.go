package wire

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestPacketError(t *testing.T) {
	origin := errors.New("boom")
	err := NewPacketError("failed to %s", origin, "do thing")

	if err.Error() != "failed to do thing: boom" {
		t.Errorf("unexpected error string: %q", err.Error())
	}
	if !errors.Is(err, err) {
		t.Errorf("expected errors.Is to match itself")
	}
	if !IsPacketError(err) {
		t.Errorf("expected IsPacketError to be true")
	}
	if IsPacketError(errors.New("plain error")) {
		t.Errorf("expected IsPacketError to be false for a plain error")
	}

	noOrigin := NewPacketError("just a message", nil)
	if noOrigin.Error() != "just a message" {
		t.Errorf("unexpected error string without origin: %q", noOrigin.Error())
	}
}

func TestRelayPayload_UnmarshalJSON_EventPacket(t *testing.T) {
	ev := &nip01.Event{Kind: 1, Content: "hello"}
	evBytes, _ := json.Marshal(ev)
	data := []byte(`["EVENT",` + string(evBytes) + `]`)

	var payload RelayPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ep, ok := payload.Packet.(*EventPacket)
	if !ok {
		t.Fatalf("expected *EventPacket, got %T", payload.Packet)
	}
	if ep.Event.Content != "hello" {
		t.Errorf("expected content %q, got %q", "hello", ep.Event.Content)
	}
}

func TestRelayPayload_UnmarshalJSON_RequestPacket(t *testing.T) {
	data := []byte(`["REQ","sub1",{"kinds":[1],"limit":10}]`)

	var payload RelayPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rp, ok := payload.Packet.(*RequestPacket)
	if !ok {
		t.Fatalf("expected *RequestPacket, got %T", payload.Packet)
	}
	if rp.SubscriptionID != "sub1" {
		t.Errorf("expected subscription ID %q, got %q", "sub1", rp.SubscriptionID)
	}
	if len(rp.Filters.GetAll()) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(rp.Filters.GetAll()))
	}
}

func TestRelayPayload_UnmarshalJSON_ClosePacket(t *testing.T) {
	var payload RelayPayload
	if err := json.Unmarshal([]byte(`["CLOSE","sub1"]`), &payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cp, ok := payload.Packet.(*ClosePacket)
	if !ok {
		t.Fatalf("expected *ClosePacket, got %T", payload.Packet)
	}
	if cp.SubscriptionID != "sub1" {
		t.Errorf("expected subscription ID %q, got %q", "sub1", cp.SubscriptionID)
	}
	if cp.String() != "subscriptionID:sub1" {
		t.Errorf("unexpected String() output: %q", cp.String())
	}
}

func TestRelayPayload_UnmarshalJSON_AuthPacket(t *testing.T) {
	ev := &nip01.Event{Kind: 22242}
	evBytes, _ := json.Marshal(ev)
	data := []byte(`["AUTH",` + string(evBytes) + `]`)

	var payload RelayPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ap, ok := payload.Packet.(*AuthPacket)
	if !ok {
		t.Fatalf("expected *AuthPacket, got %T", payload.Packet)
	}
	if ap.Event.Kind != 22242 {
		t.Errorf("expected kind 22242, got %d", ap.Event.Kind)
	}
}

func TestRelayPayload_UnmarshalJSON_CountPacket(t *testing.T) {
	var payload RelayPayload
	if err := json.Unmarshal([]byte(`["COUNT","sub1",{"kinds":[1]}]`), &payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cp, ok := payload.Packet.(*CountPacket)
	if !ok {
		t.Fatalf("expected *CountPacket, got %T", payload.Packet)
	}
	if cp.SubscriptionID != "sub1" {
		t.Errorf("expected subscription ID %q, got %q", "sub1", cp.SubscriptionID)
	}
}

func TestRelayPayload_UnmarshalJSON_NegentropyPackets(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Packet
	}{
		{"NEG-OPEN", `["NEG-OPEN","sub1",{"kinds":[1]},"initmsg"]`, &NegOpenPacket{}},
		{"NEG-MSG", `["NEG-MSG","sub1","msg"]`, &NegMsgPacket{}},
		{"NEG-CLOSE", `["NEG-CLOSE","sub1"]`, &NegClosePacket{}},
		{"NEG-ERR", `["NEG-ERR","sub1","code1"]`, &NegErrPacket{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload RelayPayload
			if err := json.Unmarshal([]byte(tt.data), &payload); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if payload.Packet == nil {
				t.Fatal("expected a non-nil packet")
			}
		})
	}
}

func TestRelayPayload_UnmarshalJSON_Errors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"not an array", `"just a string"`},
		{"too short", `["EVENT"]`},
		{"unknown packet type", `["BOGUS","x"]`},
		{"bad EVENT size", `["EVENT","a","b"]`},
		{"bad EVENT payload", `["EVENT",123]`},
		{"bad REQ size", `["REQ","sub1"]`},
		{"bad REQ filter", `["REQ","sub1",123]`},
		{"bad CLOSE size", `["CLOSE"]`},
		{"bad AUTH size", `["AUTH"]`},
		{"bad AUTH payload", `["AUTH",123]`},
		{"bad COUNT size", `["COUNT","sub1"]`},
		{"bad NEG-OPEN size", `["NEG-OPEN","sub1"]`},
		{"bad NEG-MSG size", `["NEG-MSG","sub1"]`},
		{"bad NEG-CLOSE size", `["NEG-CLOSE","sub1","extra"]`},
		{"bad NEG-ERR size", `["NEG-ERR","sub1"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload RelayPayload
			err := json.Unmarshal([]byte(tt.data), &payload)
			if err == nil {
				t.Fatalf("expected an error for input %q", tt.data)
			}
			if !IsPacketError(err) {
				t.Errorf("expected a *PacketError, got %T: %v", err, err)
			}
		})
	}
}

func TestRequestPacket_MarshalJSON(t *testing.T) {
	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})

	rp := NewRequestPacket("sub1", filters)
	data, err := rp.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected error unmarshaling marshaled output: %v", err)
	}
	if len(raw) != 3 {
		t.Fatalf("expected 3 elements (REQ, subID, filter), got %d", len(raw))
	}
	if string(raw[0]) != `"REQ"` {
		t.Errorf("expected first element to be REQ, got %s", raw[0])
	}
}

func TestClosePacket_MarshalJSON(t *testing.T) {
	cp := NewClosePacket("sub1")
	data, err := cp.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `["CLOSE","sub1"]` {
		t.Errorf("unexpected marshaled output: %s", data)
	}
}

func TestEventPacket_MarshalJSON(t *testing.T) {
	ev := &nip01.Event{Kind: 1, Content: "hi"}
	ep := NewEventPacket(ev)
	data, err := ep.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raw) != 2 || string(raw[0]) != `"EVENT"` {
		t.Errorf("unexpected marshaled output: %s", data)
	}
	if ep.String() == "" {
		t.Errorf("expected non-empty String() output")
	}
}

func TestNegentropyPackets_MarshalJSON(t *testing.T) {
	filter := &nip01.SubscriptionFilter{Kinds: []int{1}}

	if data, err := (&NegOpenPacket{SubscriptionID: "s", Filter: filter, Message: "m"}).MarshalJSON(); err != nil || len(data) == 0 {
		t.Errorf("NegOpenPacket.MarshalJSON failed: err=%v data=%s", err, data)
	}
	if data, err := (&NegMsgPacket{SubscriptionID: "s", Message: "m"}).MarshalJSON(); err != nil {
		t.Errorf("NegMsgPacket.MarshalJSON failed: %v", err)
	} else if string(data) != `["NEG-MSG","s","m"]` {
		t.Errorf("unexpected output: %s", data)
	}
	if data, err := (&NegClosePacket{SubscriptionID: "s"}).MarshalJSON(); err != nil {
		t.Errorf("NegClosePacket.MarshalJSON failed: %v", err)
	} else if string(data) != `["NEG-CLOSE","s"]` {
		t.Errorf("unexpected output: %s", data)
	}
	if data, err := (&NegErrPacket{SubscriptionID: "s", Code: "c"}).MarshalJSON(); err != nil {
		t.Errorf("NegErrPacket.MarshalJSON failed: %v", err)
	} else if string(data) != `["NEG-ERR","s","c"]` {
		t.Errorf("unexpected output: %s", data)
	}
}

func TestCountPacket_MarshalJSON(t *testing.T) {
	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})
	cp := &CountPacket{SubscriptionID: "sub1", Filters: filters}

	data, err := cp.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raw) != 3 || string(raw[0]) != `"COUNT"` {
		t.Errorf("unexpected marshaled output: %s", data)
	}
}

func TestAuthPacket_MarshalJSON(t *testing.T) {
	ap := &AuthPacket{Event: &nip01.Event{Kind: 22242}}
	data, err := ap.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raw) != 2 || string(raw[0]) != `"AUTH"` {
		t.Errorf("unexpected marshaled output: %s", data)
	}
}

func TestClientPayload_UnmarshalJSON_Dispatch(t *testing.T) {
	tests := []struct {
		name string
		data string
		want SubscriptionResponse
	}{
		{"EVENT", `["EVENT","sub1",{"kind":1}]`, &EventSubscriptionResponse{}},
		{"EOSE", `["EOSE","sub1"]`, &EOSESubscriptionResponse{}},
		{"OK", `["OK","id1",true,"ok"]`, &OkSubscriptionResponse{}},
		{"CLOSED", `["CLOSED","sub1","done"]`, &ClosedSubscriptionResponse{}},
		{"NOTICE", `["NOTICE","hi"]`, &NoticeSubscriptionResponse{}},
		{"COUNT", `["COUNT","sub1",{"count":5}]`, &CountSubscriptionResponse{}},
		{"AUTH", `["AUTH","challenge1"]`, &AuthChallengeResponse{}},
		{"NEG-MSG", `["NEG-MSG","sub1","msg"]`, &NegMsgResponse{}},
		{"NEG-ERR", `["NEG-ERR","sub1","code"]`, &NegErrResponse{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cp ClientPayload
			if err := json.Unmarshal([]byte(tt.data), &cp); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cp.SubscriptionResponse == nil {
				t.Fatal("expected a non-nil response")
			}
		})
	}

	t.Run("unknown", func(t *testing.T) {
		var cp ClientPayload
		if err := json.Unmarshal([]byte(`["BOGUS","x"]`), &cp); err == nil {
			t.Fatal("expected an error for unknown payload format")
		}
	})
}

func TestNoticeSubscriptionResponse_RoundTrip(t *testing.T) {
	nsr := &NoticeSubscriptionResponse{Message: "hello"}
	data, err := nsr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got NoticeSubscriptionResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Message != "hello" {
		t.Errorf("expected message %q, got %q", "hello", got.Message)
	}

	if err := (&NoticeSubscriptionResponse{}).UnmarshalJSON([]byte(`["NOTICE"]`)); err == nil {
		t.Error("expected error for wrong length")
	}
	if err := (&NoticeSubscriptionResponse{}).UnmarshalJSON([]byte(`["WRONG","hi"]`)); err == nil {
		t.Error("expected error for wrong type tag")
	}
	if err := (&NoticeSubscriptionResponse{}).UnmarshalJSON([]byte(`["NOTICE",42]`)); err == nil {
		t.Error("expected error for non-string message")
	}
}

func TestEventSubscriptionResponse_RoundTrip(t *testing.T) {
	ev := &nip01.Event{Kind: 1, Content: "hi"}
	esr := &EventSubscriptionResponse{SubscriptionID: "sub1", Event: ev}
	data, err := esr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got EventSubscriptionResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SubscriptionID != "sub1" || got.Event.Content != "hi" {
		t.Errorf("unexpected round-trip result: %+v", got)
	}

	if err := (&EventSubscriptionResponse{}).UnmarshalJSON([]byte(`["EVENT","sub1"]`)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestEventSubscriptionResponse_MarshalJSON_UsesEventBytes(t *testing.T) {
	esr := &EventSubscriptionResponse{SubscriptionID: "sub1", EventBytes: []byte(`{"kind":1}`)}
	data, err := esr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `["EVENT","sub1",{"kind":1}]` {
		t.Errorf("unexpected marshaled output: %s", data)
	}
}

func TestEOSESubscriptionResponse_RoundTrip(t *testing.T) {
	esr := &EOSESubscriptionResponse{SubscriptionID: "sub1"}
	data, err := esr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got EOSESubscriptionResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SubscriptionID != "sub1" {
		t.Errorf("expected subscription ID %q, got %q", "sub1", got.SubscriptionID)
	}

	if err := (&EOSESubscriptionResponse{}).UnmarshalJSON([]byte(`["EOSE"]`)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestOkSubscriptionResponse_RoundTrip(t *testing.T) {
	osr := &OkSubscriptionResponse{EventID: "id1", Accepted: true, Message: "ok"}
	data, err := osr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got OkSubscriptionResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EventID != "id1" || !got.Accepted || got.Message != "ok" {
		t.Errorf("unexpected round-trip result: %+v", got)
	}

	if err := (&OkSubscriptionResponse{}).UnmarshalJSON([]byte(`["OK","id1",true]`)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestClosedSubscriptionResponse_RoundTrip(t *testing.T) {
	csr := &ClosedSubscriptionResponse{SubscriptionID: "sub1", Message: "done"}
	data, err := csr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got ClosedSubscriptionResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SubscriptionID != "sub1" || got.Message != "done" {
		t.Errorf("unexpected round-trip result: %+v", got)
	}

	if err := (&ClosedSubscriptionResponse{}).UnmarshalJSON([]byte(`["CLOSED","sub1"]`)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestCountSubscriptionResponse_MarshalJSON(t *testing.T) {
	csr := &CountSubscriptionResponse{SubscriptionID: "sub1", Count: 42}
	data, err := csr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raw) != 3 || string(raw[0]) != `"COUNT"` {
		t.Errorf("unexpected marshaled output: %s", data)
	}
}

func TestCountSubscriptionResponse_RoundTrip(t *testing.T) {
	csr := &CountSubscriptionResponse{SubscriptionID: "sub1", Count: 42}
	data, err := csr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got CountSubscriptionResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SubscriptionID != "sub1" || got.Count != 42 {
		t.Errorf("unexpected round-trip result: %+v", got)
	}

	// A client's ClientPayload dispatcher must also recognize COUNT, not
	// just the standalone type's own UnmarshalJSON (this is the bug fix:
	// COUNT previously had no case in ClientPayload.UnmarshalJSON's switch).
	var cp ClientPayload
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatalf("ClientPayload failed to dispatch COUNT: %v", err)
	}
	dispatched, ok := cp.SubscriptionResponse.(*CountSubscriptionResponse)
	if !ok {
		t.Fatalf("expected *CountSubscriptionResponse, got %T", cp.SubscriptionResponse)
	}
	if dispatched.SubscriptionID != "sub1" || dispatched.Count != 42 {
		t.Errorf("unexpected dispatched result: %+v", dispatched)
	}

	if err := (&CountSubscriptionResponse{}).UnmarshalJSON([]byte(`["COUNT","sub1"]`)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestAuthChallengeResponse_MarshalJSON(t *testing.T) {
	acr := &AuthChallengeResponse{Challenge: "chal1"}
	data, err := acr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `["AUTH","chal1"]` {
		t.Errorf("unexpected marshaled output: %s", data)
	}
}

func TestAuthChallengeResponse_RoundTrip(t *testing.T) {
	acr := &AuthChallengeResponse{Challenge: "chal1"}
	data, err := acr.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got AuthChallengeResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Challenge != "chal1" {
		t.Errorf("unexpected round-trip result: %+v", got)
	}

	// Same bug-fix guarantee as COUNT above: a relay's AUTH challenge must
	// be recognized by ClientPayload's dispatcher, not just the type itself.
	var cp ClientPayload
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatalf("ClientPayload failed to dispatch AUTH: %v", err)
	}
	dispatched, ok := cp.SubscriptionResponse.(*AuthChallengeResponse)
	if !ok {
		t.Fatalf("expected *AuthChallengeResponse, got %T", cp.SubscriptionResponse)
	}
	if dispatched.Challenge != "chal1" {
		t.Errorf("unexpected dispatched result: %+v", dispatched)
	}

	if err := (&AuthChallengeResponse{}).UnmarshalJSON([]byte(`["AUTH"]`)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestNegMsgResponse_RoundTrip(t *testing.T) {
	r := &NegMsgResponse{SubscriptionID: "sub1", Message: "msg"}
	data, err := r.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got NegMsgResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SubscriptionID != "sub1" || got.Message != "msg" {
		t.Errorf("unexpected round-trip result: %+v", got)
	}

	if err := (&NegMsgResponse{}).UnmarshalJSON([]byte(`["NEG-MSG","sub1"]`)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestNegErrResponse_RoundTrip(t *testing.T) {
	r := &NegErrResponse{SubscriptionID: "sub1", Code: "code1"}
	data, err := r.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got NegErrResponse
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SubscriptionID != "sub1" || got.Code != "code1" {
		t.Errorf("unexpected round-trip result: %+v", got)
	}

	if err := (&NegErrResponse{}).UnmarshalJSON([]byte(`["NEG-ERR","sub1"]`)); err == nil {
		t.Error("expected error for wrong length")
	}

	// relay.damus.io sends a trailing 4th field beyond the NIP-77 spec's
	// 3-element NEG-ERR; it should be tolerated and ignored, not rejected.
	var extra NegErrResponse
	if err := extra.UnmarshalJSON([]byte(`["NEG-ERR","sub1","blocked: too many query results",1000]`)); err != nil {
		t.Errorf("expected relay's extra trailing field to be tolerated, got: %v", err)
	}
	if extra.SubscriptionID != "sub1" || extra.Code != "blocked: too many query results" {
		t.Errorf("unexpected result with trailing field: %+v", extra)
	}
}
