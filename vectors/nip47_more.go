package vectors

import (
	"encoding/json"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
)

func nip47ExpirationCases() []expirationCase {
	var out []expirationCase
	for _, c := range []struct {
		name string
		tags [][]string
	}{
		{"K-N47-1: one expiration", [][]string{{"p", wdBill}, {"expiration", "1720000060"}}},
		{"none", [][]string{{"p", wdBill}}},
		{"two", [][]string{{"expiration", "1720000060"}, {"expiration", "1720000061"}}},
		{"not a number", [][]string{{"expiration", "soon"}}},
		{"leading zero", [][]string{{"expiration", "01720000060"}}},
		{"zero", [][]string{{"expiration", "0"}}},
		{"no value", [][]string{{"expiration"}}},
	} {
		v, ok, err := nip47.RequestExpiration(&nip01.Event{Tags: c.tags})
		out = append(out, expirationCase{c.name, c.tags, v, ok, errString(err)})
	}
	return out
}

func nip47NotificationCases(walletPub, appPub string) []notificationCase {
	var out []notificationCase
	add := func(name, typ string, payload any, nip44 bool) {
		raw, _ := json.Marshal(payload)
		ev, err := nip47.NewNotificationEvent(walletSecret, appPub, nip47.Notification{NotificationType: typ, Notification: raw}, nip44)
		if err != nil {
			panic(err)
		}
		ev.CreatedAt = attTime
		if err := ev.Sign(walletSecret); err != nil {
			panic(err)
		}
		c := notificationCase{Name: name, Event: *ev}
		n, err := nip47.ParseNotificationEvent(ev, appSecret)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Type = n.NotificationType
			_ = json.Unmarshal(n.Notification, &c.Payload)
		}
		out = append(out, c)
	}
	tx := map[string]any{"type": "incoming", "payment_hash": strings.Repeat("ab", 32), "amount": 21000, "created_at": attTime, "settled_at": attTime}
	withSeededRand("nip47-notifications", func() int {
		add("payment_received, nip44 (kind 23197)", nip47.NotificationPaymentReceived, tx, true)
		add("payment_sent, nip04 (kind 23196)", nip47.NotificationPaymentSent, tx, false)
		add("hold_invoice_accepted", nip47.NotificationHoldInvoiceAccepted, tx, true)
		add("rotation_pending", nip47.NotificationRotationPending, nip47.RotationPending{ConnectionPubkey: wdSlice, CompletesAt: attTime + 86400}, true)
		return 0
	})
	return out
}

func nip47GetInfoCases() []circleInfoCase {
	var out []circleInfoCase
	add := func(name, result string) {
		c := circleInfoCase{Name: name, Result: result, MissingAlways: []string{}}
		var r nip47.GetInfoResult
		if err := json.Unmarshal([]byte(result), &r); err != nil {
			c.Error = err.Error()
		} else {
			raw, _ := json.Marshal(r)
			_ = json.Unmarshal(raw, &c.Want)
			if r.CircleWallet != nil {
				c.MissingAlways = nonNil(r.CircleWallet.MissingAlways())
				c.Accepting = r.CircleWallet.Accepting
			}
			c.ValidNetwork = nip47.ValidNetwork(r.Network)
		}
		out = append(out, c)
	}
	add("network and chain", `{"pubkey":"`+connIdentity+`","network":"mainnet","chain":"bitcoin","methods":["get_info","mint_cash"]}`)
	for _, n := range []string{"testnet", "signet", "regtest", "Mainnet", ""} {
		add("network "+n, `{"network":"`+n+`","chain":"bitcoin","methods":["get_info"]}`)
	}
	add("no chain", `{"network":"mainnet","methods":["get_info"]}`)
	add("circle_wallet accepting", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],"circle_wallet":{"available_millis":0,"max_exp_secs":0,"fees_ppm":0,"circle_policy":"allowlist","fee_reserve":{"ppm":5000,"min_millis":10000},"dust_threshold_millis":1000,"accepting":true}}`)
	add("circle_wallet not accepting", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],"circle_wallet":{"available_millis":0,"max_exp_secs":0,"fees_ppm":0,"circle_policy":"allowlist","fee_reserve":{"ppm":5000,"min_millis":10000},"dust_threshold_millis":1000,"accepting":false}}`)
	add("circle_wallet without accepting", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],"circle_wallet":{"available_millis":0,"max_exp_secs":0,"fees_ppm":0,"circle_policy":"allowlist"}}`)
	add("private_methods", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],"private_methods":["cash_status","cash_redeem"]}`)
	return out
}
