package nip47

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

func marshalParams(v any) (json.RawMessage, error) {
	return json.Marshal(v)
}

func unmarshalParams(raw json.RawMessage, v any) error {
	return json.Unmarshal(raw, v)
}

const (
	testWalletPrivKey = "5a3c66fe899f8922d5cff0030b5affa83bcad6b7913e5681395a21979fd25bbf"
	testAppPrivKey    = "e46d12f2e1a4f4ac7b4245bf00b9cfe0b9699c3dbccc210d8bcbda9ef681e304"
)

func pubkeyOf(t *testing.T, privKeyHex string) string {
	t.Helper()
	pub, err := utils.GetPublicKey(privKeyHex)
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}
	return pub
}

func TestInfoEventRoundTrip(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	methods := []string{MethodPayInvoice, MethodGetBalance, MethodGetInfo}
	notifTypes := []string{NotificationPaymentReceived, NotificationPaymentSent}
	encryptions := []string{EncryptionNIP44V2, EncryptionNIP04}

	ev := NewInfoEvent(walletPubkey, methods, notifTypes, encryptions)
	if err := ev.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	info, err := ParseInfoEvent(ev)
	if err != nil {
		t.Fatalf("ParseInfoEvent() error = %v", err)
	}
	if len(info.Methods) != 3 || info.Methods[0] != MethodPayInvoice {
		t.Errorf("Methods = %v", info.Methods)
	}
	if len(info.NotificationTypes) != 2 {
		t.Errorf("NotificationTypes = %v", info.NotificationTypes)
	}
	if len(info.SupportedEncryptions) != 2 || info.SupportedEncryptions[0] != EncryptionNIP44V2 {
		t.Errorf("SupportedEncryptions = %v", info.SupportedEncryptions)
	}
}

func TestInfoEventDefaultsToNIP04(t *testing.T) {
	ev := &nip01.Event{Kind: KindNWCInfo, Content: MethodGetInfo}
	info, err := ParseInfoEvent(ev)
	if err != nil {
		t.Fatalf("ParseInfoEvent() error = %v", err)
	}
	if len(info.SupportedEncryptions) != 1 || info.SupportedEncryptions[0] != EncryptionNIP04 {
		t.Errorf("SupportedEncryptions = %v, want [%s]", info.SupportedEncryptions, EncryptionNIP04)
	}
}

func TestRequestResponseRoundTrip(t *testing.T) {
	for _, encryption := range []string{EncryptionNIP04, EncryptionNIP44V2} {
		t.Run(encryption, func(t *testing.T) {
			walletPubkey := pubkeyOf(t, testWalletPrivKey)
			appPubkey := pubkeyOf(t, testAppPrivKey)

			reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodPayInvoice, PayInvoiceParams{Invoice: "lnbc50n1..."}, encryption)
			if err != nil {
				t.Fatalf("NewRequestEvent() error = %v", err)
			}
			if reqEv.PubKey != appPubkey {
				t.Errorf("request PubKey = %q, want %q", reqEv.PubKey, appPubkey)
			}
			if err := reqEv.Sign(testAppPrivKey); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			gotReq, err := ParseRequestEvent(reqEv, testWalletPrivKey)
			if err != nil {
				t.Fatalf("ParseRequestEvent() error = %v", err)
			}
			if gotReq.Method != MethodPayInvoice {
				t.Errorf("Method = %q", gotReq.Method)
			}
			var payParams PayInvoiceParams
			if err := unmarshalParams(gotReq.Params, &payParams); err != nil {
				t.Fatalf("unmarshal params error = %v", err)
			}
			if payParams.Invoice != "lnbc50n1..." {
				t.Errorf("Invoice = %q", payParams.Invoice)
			}

			respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodPayInvoice, PayInvoiceResult{Preimage: "abcd1234"}, reqEv, encryption)
			if err != nil {
				t.Fatalf("NewResponseEvent() error = %v", err)
			}
			if respEv.PubKey != walletPubkey {
				t.Errorf("response PubKey = %q, want %q", respEv.PubKey, walletPubkey)
			}
			if err := respEv.Sign(testWalletPrivKey); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			gotResp, err := ParseResponseEvent(respEv, testAppPrivKey)
			if err != nil {
				t.Fatalf("ParseResponseEvent() error = %v", err)
			}
			if gotResp.ResultType != MethodPayInvoice {
				t.Errorf("ResultType = %q", gotResp.ResultType)
			}
			if gotResp.RequestEventID != reqEv.ID {
				t.Errorf("RequestEventID = %q, want %q", gotResp.RequestEventID, reqEv.ID)
			}
			if gotResp.SubPaymentID != "" {
				t.Errorf("SubPaymentID = %q, want empty", gotResp.SubPaymentID)
			}
			var payResult PayInvoiceResult
			if err := unmarshalParams(gotResp.Result, &payResult); err != nil {
				t.Fatalf("unmarshal result error = %v", err)
			}
			if payResult.Preimage != "abcd1234" {
				t.Errorf("Preimage = %q", payResult.Preimage)
			}
		})
	}
}

func TestMultiPayResponseFanoutCorrelation(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodMultiPayInvoice, MultiPayInvoiceParams{Invoices: []MultiPayInvoiceItem{
		{Id: "one", PayInvoiceParams: PayInvoiceParams{Invoice: "lnbc1..."}},
		{Id: "two", PayInvoiceParams: PayInvoiceParams{Invoice: "lnbc2..."}},
	}}, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	subPaymentIDs := []string{"one", "two"}
	for _, id := range subPaymentIDs {
		respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodMultiPayInvoice, PayInvoiceResult{Preimage: "preimage-" + id}, reqEv, EncryptionNIP44V2, []string{"d", id})
		if err != nil {
			t.Fatalf("NewResponseEvent() error = %v", err)
		}
		if err := respEv.Sign(testWalletPrivKey); err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		got, err := ParseResponseEvent(respEv, testAppPrivKey)
		if err != nil {
			t.Fatalf("ParseResponseEvent() error = %v", err)
		}
		if got.RequestEventID != reqEv.ID {
			t.Errorf("RequestEventID = %q, want %q", got.RequestEventID, reqEv.ID)
		}
		if got.SubPaymentID != id {
			t.Errorf("SubPaymentID = %q, want %q", got.SubPaymentID, id)
		}
		var payResult PayInvoiceResult
		if err := unmarshalParams(got.Result, &payResult); err != nil {
			t.Fatalf("unmarshal result error = %v", err)
		}
		if payResult.Preimage != "preimage-"+id {
			t.Errorf("Preimage = %q, want %q", payResult.Preimage, "preimage-"+id)
		}
	}
}

func TestGetBudgetRoundTrip(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodGetBudget, nil, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	gotReq, err := ParseRequestEvent(reqEv, testWalletPrivKey)
	if err != nil {
		t.Fatalf("ParseRequestEvent() error = %v", err)
	}
	if gotReq.Method != MethodGetBudget {
		t.Errorf("Method = %q, want %q", gotReq.Method, MethodGetBudget)
	}

	renewsAt := int64(2000000000)
	respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodGetBudget, GetBudgetResult{
		UsedBudgetMloki:  1000,
		TotalBudgetMloki: 5000,
		RenewsAt:         &renewsAt,
		RenewalPeriod:    "monthly",
	}, reqEv, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	got, err := ParseResponseEvent(respEv, testAppPrivKey)
	if err != nil {
		t.Fatalf("ParseResponseEvent() error = %v", err)
	}
	var budget GetBudgetResult
	if err := unmarshalParams(got.Result, &budget); err != nil {
		t.Fatalf("unmarshal result error = %v", err)
	}
	if budget.UsedBudgetMloki != 1000 || budget.TotalBudgetMloki != 5000 || budget.RenewalPeriod != "monthly" {
		t.Errorf("GetBudgetResult = %+v", budget)
	}
	if budget.RenewsAt == nil || *budget.RenewsAt != renewsAt {
		t.Errorf("RenewsAt = %v, want %d", budget.RenewsAt, renewsAt)
	}
}

func TestBadRequestErrorRoundTrip(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodPayInvoice, nil, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	respEv, err := NewErrorResponseEvent(testWalletPrivKey, appPubkey, MethodPayInvoice, Error{Code: ErrBadRequest, Message: "missing invoice"}, reqEv, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	got, err := ParseResponseEvent(respEv, testAppPrivKey)
	if err != nil {
		t.Fatalf("ParseResponseEvent() error = %v", err)
	}
	if got.Error == nil || got.Error.Code != ErrBadRequest {
		t.Errorf("Error = %+v, want code %q", got.Error, ErrBadRequest)
	}
}

func TestPayInvoiceParamsMetadataRoundTrip(t *testing.T) {
	metadata, err := marshalParams(map[string]string{"source": "test"})
	if err != nil {
		t.Fatalf("marshalParams() error = %v", err)
	}
	params, err := marshalParams(PayInvoiceParams{Invoice: "lnbc1...", Metadata: metadata})
	if err != nil {
		t.Fatalf("marshalParams() error = %v", err)
	}

	var got PayInvoiceParams
	if err := unmarshalParams(params, &got); err != nil {
		t.Fatalf("unmarshal error = %v", err)
	}
	var meta map[string]string
	if err := unmarshalParams(got.Metadata, &meta); err != nil {
		t.Fatalf("unmarshal metadata error = %v", err)
	}
	if meta["source"] != "test" {
		t.Errorf("Metadata = %v", meta)
	}
}

func TestNotificationRoundTrip(t *testing.T) {
	for _, useNIP44 := range []bool{false, true} {
		t.Run(map[bool]string{false: "nip04", true: "nip44"}[useNIP44], func(t *testing.T) {
			walletPubkey := pubkeyOf(t, testWalletPrivKey)
			appPubkey := pubkeyOf(t, testAppPrivKey)

			payloadBytes, err := marshalParams(Transaction{Type: "incoming", PaymentHash: "deadbeef", AmountMloki: 1000})
			if err != nil {
				t.Fatalf("marshalParams() error = %v", err)
			}
			notif := Notification{NotificationType: NotificationPaymentReceived, Notification: payloadBytes}

			ev, err := NewNotificationEvent(testWalletPrivKey, appPubkey, notif, useNIP44)
			if err != nil {
				t.Fatalf("NewNotificationEvent() error = %v", err)
			}
			if ev.PubKey != walletPubkey {
				t.Errorf("PubKey = %q, want %q", ev.PubKey, walletPubkey)
			}
			wantKind := KindNWCLegacyNotification
			if useNIP44 {
				wantKind = KindNWCNotification
			}
			if ev.Kind != wantKind {
				t.Errorf("Kind = %d, want %d", ev.Kind, wantKind)
			}
			if err := ev.Sign(testWalletPrivKey); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			got, err := ParseNotificationEvent(ev, testAppPrivKey)
			if err != nil {
				t.Fatalf("ParseNotificationEvent() error = %v", err)
			}
			if got.NotificationType != NotificationPaymentReceived {
				t.Errorf("NotificationType = %q", got.NotificationType)
			}
			var tx Transaction
			if err := unmarshalParams(got.Notification, &tx); err != nil {
				t.Fatalf("unmarshal notification payload error = %v", err)
			}
			if tx.PaymentHash != "deadbeef" || tx.AmountMloki != 1000 {
				t.Errorf("Transaction = %+v", tx)
			}
		})
	}
}
