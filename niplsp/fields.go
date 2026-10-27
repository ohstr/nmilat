package niplsp

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/internal/credcodec"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// Option is one lsps1 option or lsps5 field: its name without a unit suffix
// and its value as the tag carries it (an unsigned decimal, or true/false).
type Option struct {
	Name  string
	Value string
}

// FeeRow is one row of LSPS2 get_info's opening_fee_params_menu, without its
// valid_until and promise, which are never announced. Amounts are in millis.
type FeeRow struct {
	MinFeeMillis         uint64 // min_fee_msat
	Proportional         uint64 // parts per million
	MinLifetime          uint64 // blocks
	MaxClientToSelfDelay uint64 // blocks
	MinPaymentSizeMillis uint64 // min_payment_size_msat
	MaxPaymentSizeMillis uint64 // max_payment_size_msat
}

// values are the row in the lsps2_fee tag's order.
func (r FeeRow) values() [6]uint64 {
	return [6]uint64{r.MinFeeMillis, r.Proportional, r.MinLifetime, r.MaxClientToSelfDelay,
		r.MinPaymentSizeMillis, r.MaxPaymentSizeMillis}
}

// Operator is the p tag: the operator's Nostr pubkey and a relay hint.
type Operator struct {
	Pubkey string
	Relay  string
}

// Display is what the LSP says about itself. None of it is a verified fact.
type Display struct {
	Title    string    // title, plain text
	Content  string    // the event content, at most MaxContent characters
	Website  string    // an https URL
	Image    string    // an https URL of a logo
	Operator *Operator // p
	// Languages are ISO-639-1 codes, written as NIP-32 labels.
	Languages []string
}

// Meta is everything in an announcement that is not LSPS step data.
type Meta struct {
	// NodeKey is the node key, 64 hex characters x-only; NewAnnouncement and
	// FromLSPSInfo also take the 66-character node id and keep its x-only form.
	NodeKey string
	// Addrs are where the node accepts connections, host:port, in order.
	Addrs []string
	// Chain is the chain's name (the n tag), e.g. "bitcoin".
	Chain string
	// Network is mainnet, testnet, signet or regtest.
	Network string
	// Status is open, paused or closed; empty means open.
	Status Status
	// Expiration is the NIP-40 expiration, unix seconds; 0 means created_at
	// plus MaxExpirySecs.
	Expiration int64
	Display    Display
	// Relays are the r tags: where the LSP publishes this announcement.
	Relays []string
}

// Fields are an announcement's whole content.
type Fields struct {
	Meta
	// Protocols are the LSPS numbers the LSP lists in LSPS0 list_protocols.
	Protocols []int
	// LSPS1 are LSPS1 get_info options, named without a unit suffix, amounts
	// in base units.
	LSPS1 []Option
	// LSPS2 are the opening_fee_params_menu rows.
	LSPS2 []FeeRow
	// LSPS5 are LSPS5 set_webhook response fields (max_webhooks).
	LSPS5 []Option
}

// HasProtocol reports p among Protocols.
func (f *Fields) HasProtocol(p int) bool {
	for _, q := range f.Protocols {
		if q == p {
			return true
		}
	}
	return false
}

// LSPS1Value is the value of the lsps1 option name.
func (f *Fields) LSPS1Value(name string) (string, bool) { return optionValue(f.LSPS1, name) }

// LSPS5Value is the value of the lsps5 field name.
func (f *Fields) LSPS5Value(name string) (string, bool) { return optionValue(f.LSPS5, name) }

func optionValue(opts []Option, name string) (string, bool) {
	for _, o := range opts {
		if o.Name == name {
			return o.Value, true
		}
	}
	return "", false
}

// valueKind is the JSON type of a known LSPS option.
type valueKind int

const (
	kindNumber valueKind = iota
	kindBool
)

// knownOption is an LSPS option this package knows: its announced name, the
// unit its LSPS name carries, its type, and which value is better for a buyer.
type knownOption struct {
	Name   string
	Unit   Unit
	Kind   valueKind
	Better direction
}

// direction says which way a value is better for the buyer.
type direction int

const (
	lowerBetter direction = iota
	higherBetter
	trueBetter
)

// lsps1Options are the LSPS1 get_info options, in bLIP-51 order, which is the
// order FromLSPSInfo writes them in.
var lsps1Options = []knownOption{
	{"min_required_channel_confirmations", UnitNone, kindNumber, lowerBetter},
	{"min_funding_confirms_within_blocks", UnitNone, kindNumber, lowerBetter},
	{"supports_zero_channel_reserve", UnitNone, kindBool, trueBetter},
	{"max_channel_expiry_blocks", UnitNone, kindNumber, higherBetter},
	{"min_initial_client_balance", UnitBase, kindNumber, lowerBetter},
	{"max_initial_client_balance", UnitBase, kindNumber, higherBetter},
	{"min_initial_lsp_balance", UnitBase, kindNumber, lowerBetter},
	{"max_initial_lsp_balance", UnitBase, kindNumber, higherBetter},
	{"min_channel_balance", UnitBase, kindNumber, lowerBetter},
	{"max_channel_balance", UnitBase, kindNumber, higherBetter},
}

// lsps5Fields are the LSPS5 fields an announcement carries.
var lsps5Fields = []knownOption{
	{"max_webhooks", UnitNone, kindNumber, higherBetter},
}

// feeRowFields are the lsps2_fee positions 1-6.
var feeRowFields = [6]knownOption{
	{"min_fee", UnitMillis, kindNumber, lowerBetter},
	{"proportional", UnitNone, kindNumber, lowerBetter},
	{"min_lifetime", UnitNone, kindNumber, higherBetter},
	{"max_client_to_self_delay", UnitNone, kindNumber, higherBetter},
	{"min_payment_size", UnitMillis, kindNumber, lowerBetter},
	{"max_payment_size", UnitMillis, kindNumber, higherBetter},
}

// LSPS1OptionNames are the LSPS1 get_info options this package knows, named
// as an announcement names them, in bLIP-51 order.
func LSPS1OptionNames() []string { return names(lsps1Options) }

// LSPS5FieldNames are the LSPS5 fields this package knows.
func LSPS5FieldNames() []string { return names(lsps5Fields) }

func names(opts []knownOption) []string {
	out := make([]string, len(opts))
	for i, o := range opts {
		out[i] = o.Name
	}
	return out
}

func lookupOption(table []knownOption, name string) (knownOption, bool) {
	for _, o := range table {
		if o.Name == name {
			return o, true
		}
	}
	return knownOption{}, false
}

// canonicalUint parses an unsigned decimal with no leading zeros.
func canonicalUint(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, false
	}
	return v, true
}

// validValue reports a value of the option's form; an unknown option's value
// is an unsigned decimal or a boolean.
func validValue(o knownOption, known bool, v string) bool {
	_, isNum := canonicalUint(v)
	isBool := v == "true" || v == "false"
	if !known {
		return isNum || isBool
	}
	if o.Kind == kindBool {
		return isBool
	}
	return isNum
}

// validOptionName is a name of a-z, 0-9 and '_' with no LSPS unit suffix.
func validOptionName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	_, u := FromLSPSName(s)
	return u == UnitNone
}

// ValidAddr reports host:port with an IPv4 address, a bracketed IPv6 address
// or an onion address as the host, and a port from 1 to 65535: the addr form
// NIP-LSP shares with the NIP-CASH Hub announcement.
func ValidAddr(s string) bool { return transport.ValidAddr(s) }

func validHTTPS(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

func validRelay(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "wss" || u.Scheme == "ws") && u.Host != ""
}

func validLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validLanguage(s string) bool {
	return len(s) == 2 && s[0] >= 'a' && s[0] <= 'z' && s[1] >= 'a' && s[1] <= 'z'
}

func validChain(s string) bool   { return credcodec.ValidChainName(s) }
func validNetwork(s string) bool { return nip47.ValidNetwork(s) }

// xOnlyNodeKey takes a node key as 64 hex characters or a 66-character node
// id and returns its lowercase x-only form.
func xOnlyNodeKey(k string) (string, bool) {
	k = strings.ToLower(k)
	if len(k) == 66 && (strings.HasPrefix(k, "02") || strings.HasPrefix(k, "03")) {
		k = k[2:]
	}
	return k, validLowerHex64(k)
}

// NodeIDs are the two node ids an x-only node key can stand for: 02 and 03
// followed by the key (NIP-LSP §Client Behavior, Connecting). A client uses
// the one its view of the network knows, or else tries both.
func NodeIDs(pubkey string) [2]string {
	pk := strings.ToLower(pubkey)
	return [2]string{"02" + pk, "03" + pk}
}
