package nip46

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	testClientPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	testSignerPrivKey = "5a3c66fe899f8922d5cff0030b5affa83bcad6b7913e5681395a21979fd25bbf"
)

func TestRequestResponseRoundTrip(t *testing.T) {
	for _, encryption := range []string{EncryptionNIP04, EncryptionNIP44V2} {
		t.Run(encryption, func(t *testing.T) {
			signerPubkey, err := utils.GetPublicKey(testSignerPrivKey)
			if err != nil {
				t.Fatal(err)
			}
			clientPubkey, err := utils.GetPublicKey(testClientPrivKey)
			if err != nil {
				t.Fatal(err)
			}

			reqEvent, requestID, err := NewRequestEvent(testClientPrivKey, signerPubkey, MethodConnect, []string{signerPubkey, "secret-code"}, encryption)
			if err != nil {
				t.Fatalf("NewRequestEvent() error = %v", err)
			}
			if err := reqEvent.Sign(testClientPrivKey); err != nil {
				t.Fatal(err)
			}

			parsedReq, err := ParseRequestEvent(reqEvent, testSignerPrivKey)
			if err != nil {
				t.Fatalf("ParseRequestEvent() error = %v", err)
			}
			if parsedReq.RequestID != requestID {
				t.Errorf("RequestID = %q, want %q", parsedReq.RequestID, requestID)
			}
			if parsedReq.Method != MethodConnect {
				t.Errorf("Method = %q, want %q", parsedReq.Method, MethodConnect)
			}
			if len(parsedReq.Params) != 2 || parsedReq.Params[0] != signerPubkey || parsedReq.Params[1] != "secret-code" {
				t.Errorf("Params = %v", parsedReq.Params)
			}

			respEvent, err := NewResponseEvent(testSignerPrivKey, clientPubkey, requestID, "ack", encryption)
			if err != nil {
				t.Fatalf("NewResponseEvent() error = %v", err)
			}
			if err := respEvent.Sign(testSignerPrivKey); err != nil {
				t.Fatal(err)
			}

			parsedResp, err := ParseResponseEvent(respEvent, testClientPrivKey)
			if err != nil {
				t.Fatalf("ParseResponseEvent() error = %v", err)
			}
			if parsedResp.RequestID != requestID {
				t.Errorf("RequestID = %q, want %q", parsedResp.RequestID, requestID)
			}
			if parsedResp.Result != "ack" {
				t.Errorf("Result = %q, want %q", parsedResp.Result, "ack")
			}
			if parsedResp.Error != "" {
				t.Errorf("Error = %q, want empty", parsedResp.Error)
			}
		})
	}
}

func TestErrorResponseEvent(t *testing.T) {
	clientPubkey, err := utils.GetPublicKey(testClientPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	respEvent, err := NewErrorResponseEvent(testSignerPrivKey, clientPubkey, "req-1", "user rejected", EncryptionNIP04)
	if err != nil {
		t.Fatalf("NewErrorResponseEvent() error = %v", err)
	}
	if err := respEvent.Sign(testSignerPrivKey); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseResponseEvent(respEvent, testClientPrivKey)
	if err != nil {
		t.Fatalf("ParseResponseEvent() error = %v", err)
	}
	if parsed.Error != "user rejected" {
		t.Errorf("Error = %q, want %q", parsed.Error, "user rejected")
	}
	if parsed.Result != "" {
		t.Errorf("Result = %q, want empty", parsed.Result)
	}
}

func TestParseRequestEvent_WrongKind(t *testing.T) {
	if _, err := ParseRequestEvent(&nip01.Event{Kind: 1}, testSignerPrivKey); err == nil {
		t.Fatal("expected error for wrong kind")
	}
}

func TestParseResponseEvent_WrongKind(t *testing.T) {
	if _, err := ParseResponseEvent(&nip01.Event{Kind: 1}, testClientPrivKey); err == nil {
		t.Fatal("expected error for wrong kind")
	}
}
