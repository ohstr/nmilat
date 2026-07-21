package nipB7

import (
	"errors"
	"net/http"
	"testing"
)

func TestParsePaymentRequest(t *testing.T) {
	h := http.Header{}
	h.Set(HeaderLightning, "lnbc1...")
	req, ok := ParsePaymentRequest(h)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if req.Lightning != "lnbc1..." {
		t.Errorf("Lightning = %q", req.Lightning)
	}
	if req.Cashu != "" {
		t.Errorf("Cashu = %q, want empty", req.Cashu)
	}
}

func TestParsePaymentRequestAbsent(t *testing.T) {
	_, ok := ParsePaymentRequest(http.Header{})
	if ok {
		t.Error("ok = true, want false when no payment headers present")
	}
}

func TestParsePaymentRequestBoth(t *testing.T) {
	h := http.Header{}
	h.Set(HeaderCashu, "cashuB...")
	h.Set(HeaderLightning, "lnbc1...")
	req, ok := ParsePaymentRequest(h)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if req.Cashu == "" || req.Lightning == "" {
		t.Errorf("expected both methods present, got %+v", req)
	}
}

func TestPaymentRequestSetProof(t *testing.T) {
	h := http.Header{}
	pr := PaymentRequest{}
	if err := pr.SetProof(h, PaymentMethodLightning, "preimage"); err != nil {
		t.Fatalf("SetProof() error = %v", err)
	}
	if h.Get(HeaderLightning) != "preimage" {
		t.Errorf("header = %q, want preimage", h.Get(HeaderLightning))
	}
}

func TestPaymentRequestSetProofCashu(t *testing.T) {
	h := http.Header{}
	pr := PaymentRequest{}
	if err := pr.SetProof(h, PaymentMethodCashu, "cashuBtoken"); err != nil {
		t.Fatalf("SetProof() error = %v", err)
	}
	if h.Get(HeaderCashu) != "cashuBtoken" {
		t.Errorf("header = %q, want cashuBtoken", h.Get(HeaderCashu))
	}
}

func TestPaymentRequestSetProofUnsupported(t *testing.T) {
	h := http.Header{}
	pr := PaymentRequest{}
	if err := pr.SetProof(h, "dogecoin", "proof"); !errors.Is(err, ErrUnsupportedPaymentMethod) {
		t.Errorf("err = %v, want ErrUnsupportedPaymentMethod", err)
	}
}
