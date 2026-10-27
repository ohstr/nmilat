package vectors

import (
	"encoding/json"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// servingCase: the method a Hub serves an item under (ServingMethod), and
// the I8 shape check (BearerShapeOK) of that serving method with or without
// a proof and a cash_secret.
type servingCase struct {
	Name     string `json:"name"`
	Method   string `json:"method"`
	Params   string `json:"params"`
	HasProof bool   `json:"hasProof"`
	Serving  string `json:"serving,omitempty"`
	Error    string `json:"error,omitempty"`
	ShapeOK  bool   `json:"shapeOk"`
	Servable bool   `json:"servable"`
}

// costCase: K-VB-1 and K-VB-2, an item's verification cost: one per
// signature a Hub checks (bill proof, item proof, and each signed event the
// params carry).
type costCase struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Params   string `json:"params"`
	HasProof bool   `json:"hasProof"`
	Cost     int    `json:"cost"`
}

func servingCases() []servingCase {
	var out []servingCase
	add := func(name, method, params string, proof bool) {
		c := servingCase{Name: name, Method: method, Params: params, HasProof: proof}
		s, err := nipcash.ServingMethod(method, json.RawMessage(params))
		c.Serving, c.Error = s, errString(err)
		it := transport.Item{Params: json.RawMessage(params)}
		if err == nil {
			c.ShapeOK = transport.BearerShapeOK(s, proof, it.IsBearer())
			c.Servable = transport.IsServableMethod(s)
		}
		out = append(out, c)
	}
	sec := `"cash_secret":"` + vecRID + vecRID + `"`
	add("cash_status signed", "cash_status", `{"scope":"mine"}`, true)
	add("cash_status cash-mode (no proof, no secret)", "cash_status", `{"scope":"mine"}`, false)
	add("cash_status with a secret (I8)", "cash_status", `{`+sec+`}`, false)
	add("cash_redeem signed", "cash_redeem", `{"invoice":"x","identity_event":"{}"}`, true)
	add("cash_redeem bearer", "cash_redeem", `{"invoice":"x",`+sec+`}`, false)
	add("cash_redeem with both (I8)", "cash_redeem", `{"invoice":"x",`+sec+`}`, true)
	add("cash_redeem with neither (I8)", "cash_redeem", `{"invoice":"x"}`, false)
	add("cash_transfer signed", "cash_transfer", `{"identity_event":"{}"}`, true)
	add("cash_consolidate", "cash_consolidate", `{"sources":[]}`, true)
	add("cash_order with its proof", "cash_order", `{"payment":"lightning"}`, true)
	add("cash_order without proof (I8)", "cash_order", `{"payment":"lightning"}`, false)
	add("cash_withdraw_quote signed", "cash_withdraw_quote", `{"address":"`+kAddr1+`"}`, true)
	add("cash_withdraw_quote cash-mode (no proof, no secret)", "cash_withdraw_quote", `{"address":"`+kAddr1+`"}`, false)
	add("cash_withdraw_quote with a secret (I8)", "cash_withdraw_quote", `{"address":"`+kAddr1+`",`+sec+`}`, false)
	add("cash_withdraw signed", "cash_withdraw", `{"quote":"{}","identity_event":"{}"}`, true)
	add("cash_withdraw bearer", "cash_withdraw", `{"quote":"{}",`+sec+`}`, false)
	add("cash_withdraw with neither (I8)", "cash_withdraw", `{"quote":"{}"}`, false)
	add("cash_withdraw cancel: served as cash_lookup", "cash_withdraw", `{"cancel":true,"request_id":"`+vecRID+`"}`, true)
	add("cash_withdraw bearer cancel: served as cash_lookup", "cash_withdraw", `{"cancel":true,"request_id":"`+vecRID+`",`+sec+`}`, false)
	add("cash_withdraw cancel with a deadline", "cash_withdraw", `{"cancel":true,"request_id":"`+vecRID+`","deadline":1720000060}`, true)
	add("cash_withdraw cancel without request_id", "cash_withdraw", `{"cancel":true}`, true)
	add("cash_withdraw malformed cancel", "cash_withdraw", `{"cancel":"yes"}`, true)
	add("cash_lookup", "cash_lookup", `{"request_id":"`+vecRID+`","deadline":1720000060}`, true)
	add("create_circle_wallet", "create_circle_wallet", `{"identity_event":"{}"}`, true)
	add("mint_cash is not served privately", "mint_cash", `{}`, true)
	add("get_info", "get_info", `{}`, true)
	return out
}

func costCases() []costCase {
	var out []costCase
	add := func(id, name, params string, proof bool) {
		it := transport.Item{Params: json.RawMessage(params), BillProof: json.RawMessage(`{}`)}
		if proof {
			it.Proof = json.RawMessage(`{}`)
		}
		out = append(out, costCase{id, name, params, proof, it.VerificationCost()})
	}
	add("K-VB-1", "pubkey redeem", `{"identity_event":"{}"}`, true)
	add("K-VB-1", "bearer redeem", `{"cash_secret":"s"}`, false)
	add("K-VB-1", "CK transfer", `{"identity_event":"{}","attestation_event":"{}"}`, true)
	add("K-VB-1", "consolidate 3 pubkey sources", `{"sources":[{"identity_event":"{}"},{"identity_event":"{}"},{"identity_event":"{}"}]}`, true)
	add("K-VB-1", "consolidate 2 pubkey + 1 CK", `{"sources":[{"identity_event":"{}"},{"identity_event":"{}"},{"identity_event":"{}","attestation_event":"{}"}]}`, true)
	add("K-VB-1", "signed status", `{}`, true)
	add("K-VB-1", "cash-mode status", `{}`, false)
	add("K-VB-1", "private join", `{"identity_event":{"kind":23199}}`, true)
	add("K-VB-2", "pubkey quote", `{}`, true)
	add("K-VB-2", "CK quote", `{"attestation_event":"{}"}`, true)
	add("K-VB-2", "cash-mode quote", `{}`, false)
	add("K-VB-2", "pubkey withdraw", `{"identity_event":"{}","quote":{"kind":23187}}`, true)
	add("K-VB-2", "CK withdraw", `{"identity_event":"{}","attestation_event":"{}","quote":{"kind":23187}}`, true)
	add("K-VB-2", "bearer withdraw", `{"cash_secret":"s","quote":{"kind":23187}}`, false)
	add("K-VB-2", "cancel by pubkey", `{"cancel":true}`, true)
	add("K-VB-2", "bearer cancel", `{"cancel":true,"cash_secret":"s"}`, false)
	return out
}
