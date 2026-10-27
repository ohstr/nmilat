package nipcash

import (
	"encoding/json"
	"math/bits"
)

// PendingSecret is a cash secret generated for a call, written ahead with it.
// Role is "" for the call's own cash target, SecretRoleRemainder for a split's
// remainder target, SecretRoleRemint for a cancelled withdrawal's re-mint.
type PendingSecret struct {
	Secret string `json:"secret"`
	Role   string `json:"role,omitempty"`
}

// PendingCall is a call carrying a request_id, written ahead before it is sent
// and kept until it is closed (NIP-CASH §Lost Replies). It holds what a lookup
// and a re-placement need, and no secret beyond the ones the call generated or
// is authorized by.
type PendingCall struct {
	RequestID string `json:"request_id"`
	// Deadline is the exact not_after (or NIP-47 expiration) sent.
	Deadline int64  `json:"deadline"`
	Method   string `json:"method"`
	// Target is the bill named (Sources[0] for a consolidate), the Cash Hub
	// connection's TLV 0 for a mint, the Order connection's for an order.
	Target      string `json:"target"`
	HubIdentity string `json:"hub_identity"`
	// MaxRequestAge is the H read before sending.
	MaxRequestAge int64           `json:"max_request_age"`
	Device        string          `json:"device"`
	Secrets       []PendingSecret `json:"secrets,omitempty"`
	// SourceSecret is the cash secret authorizing the call, for a bearer lookup.
	SourceSecret string `json:"source_secret,omitempty"`
	Amount       uint64 `json:"amount"`
	Chain        string `json:"chain,omitempty"`
	DerivedFrom  string `json:"derived_from,omitempty"`
	// Attempt is 0 for the original, 1 to 3 for re-placements.
	Attempt int `json:"attempt"`
	// LastCode is the code of the call's last answer when it was a coded refusal
	// other than BAD_REQUEST and REQUEST_REUSED; "" otherwise.
	LastCode string `json:"last_code,omitempty"`
	// SawReused records a REQUEST_REUSED answer (which never sets LastCode).
	SawReused bool            `json:"saw_reused,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	// BuyerKey and Notify are a cash_order's (NIP-CO).
	BuyerKey string `json:"buyer_key,omitempty"`
	Notify   string `json:"notify,omitempty"`
	// PayBy is set from an order reply that was held; 0 while none was.
	PayBy int64 `json:"pay_by,omitempty"`
	// LastDetail is the detail of the answer that set LastCode ("" for none).
	LastDetail Detail `json:"last_detail,omitempty"`
	// Quote, Address and HoldsUntil are a cash_withdraw's: the quote event as
	// sent (a JSON string), its address and its holds_until. A call recovered
	// from withdraw_request_id has no Quote.
	Quote      string `json:"quote,omitempty"`
	Address    string `json:"address,omitempty"`
	HoldsUntil int64  `json:"holds_until,omitempty"`
	// Receipt is a cash_withdraw's receipt, set by the caller once it verified.
	Receipt string `json:"receipt,omitempty"`
}

// bearerSecret is the cash secret a credential presents, "" for any other.
func bearerSecret(cred Credential) string {
	if c, ok := cred.(secretCredential); ok {
		return c.secret
	}
	return ""
}

func targetSecrets(to Target, role string) []PendingSecret {
	if t, ok := to.(*CashTarget); ok && t != nil {
		return []PendingSecret{{Secret: t.Secret(), Role: role}}
	}
	return nil
}

// Pending is the call to write ahead for this transfer of the bill target: its
// generated secrets (the cash target's, the remainder's), the bearer secret
// authorizing it, and the wire request as Params (commitments only).
func (p CashTransferParams) Pending(target string) (PendingCall, error) {
	req, err := p.Request(target)
	if err != nil {
		return PendingCall{}, err
	}
	raw, err := withoutSecrets(req)
	if err != nil {
		return PendingCall{}, err
	}
	amount := p.CurrentAmount
	if p.SplitAmount != nil {
		amount = *p.SplitAmount
	}
	secrets := targetSecrets(p.To, "")
	if p.RemainderTarget != nil {
		secrets = append(secrets, PendingSecret{Secret: p.RemainderTarget.Secret(), Role: SecretRoleRemainder})
	}
	return PendingCall{
		RequestID: p.RequestID, Method: MethodCashTransfer, Target: target,
		Secrets: secrets, SourceSecret: bearerSecret(p.Credential), Amount: amount, Params: raw,
	}, nil
}

// Pending is the call to write ahead for this consolidate; its target is
// Sources[0], its amount the sum of the sources.
func (p CashConsolidateParams) Pending() (PendingCall, error) {
	req, err := p.Request()
	if err != nil {
		return PendingCall{}, err
	}
	raw, err := withoutSecrets(req)
	if err != nil {
		return PendingCall{}, err
	}
	var amount uint64
	for _, s := range p.Sources {
		sum, carry := bits.Add64(amount, s.Amount, 0)
		if carry != 0 {
			return PendingCall{}, ErrAmountOverflow
		}
		amount = sum
	}
	return PendingCall{
		RequestID: p.RequestID, Method: MethodCashConsolidate, Target: p.Sources[0].WalletPubkey,
		Secrets: targetSecrets(p.To, ""), SourceSecret: bearerSecret(p.Sources[0].Credential), Amount: amount, Params: raw,
	}, nil
}

// withoutSecrets is v as JSON with every "cash_secret" removed, at any depth:
// Params never hold a secret (the bearer one is SourceSecret).
func withoutSecrets(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	var strip func(any)
	strip = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			delete(t, "cash_secret")
			for _, c := range t {
				strip(c)
			}
		case []any:
			for _, c := range t {
				strip(c)
			}
		}
	}
	strip(tree)
	return json.Marshal(tree)
}

// Pending is the call to write ahead for this mint over the Cash Hub
// connection whose TLV 0 is target: the cash targets' secrets and the sum of
// the recipients' amounts.
func (p MintCashParams) Pending(target string) (PendingCall, error) {
	req, err := p.Request()
	if err != nil {
		return PendingCall{}, err
	}
	raw, err := withoutSecrets(req)
	if err != nil {
		return PendingCall{}, err
	}
	var amount uint64
	var secrets []PendingSecret
	for _, a := range p.Recipients {
		amount += a.AmountMillis
		if t, ok := a.Recipient.(*CashTarget); ok && t != nil {
			secrets = append(secrets, PendingSecret{Secret: t.Secret()})
		}
	}
	return PendingCall{RequestID: p.RequestID, Method: MethodMintCash, Target: target, Secrets: secrets, Amount: amount, Params: raw}, nil
}
