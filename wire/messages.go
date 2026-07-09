// Package wire defines the Nostr relay wire-protocol packet types (EVENT,
// REQ, EOSE, OK, NOTICE, CLOSE, AUTH, and NIP-77 negentropy packets) and
// their JSON encoding. Most consumers should reach for relay/client
// instead of this package directly — it hides these packet types behind a
// higher-level Connection API.
package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

type Packet interface {
	// Marker interface
}

type PacketError struct {
	Message string
	Origin  error
}

func (pe *PacketError) Error() string {
	if pe.Origin != nil {
		return fmt.Sprintf("%s: %v", pe.Message, pe.Origin)
	}
	return pe.Message
}

func NewPacketError(message string, err error, args ...interface{}) *PacketError {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	return &PacketError{
		Message: message,
		Origin:  err,
	}
}

func IsPacketError(err error) bool {
	var pe *PacketError
	return errors.As(err, &pe)
}

type RelayPayload struct {
	Packet Packet
}

func (p *RelayPayload) UnmarshalJSON(data []byte) error {

	var params []json.RawMessage
	if err := json.Unmarshal(data, &params); err != nil {
		// return NewPacketError("unexpected payload format", err) // Need NewPacketError?
		// We can define PacketError here too.
		return &PacketError{Message: "unexpected payload format", Origin: err}
	}

	if len(params) < 2 {
		return &PacketError{Message: fmt.Sprintf("invalid packet size, got=%d", len(params))}
	}

	packetType := strings.ReplaceAll(string(params[0]), `"`, "")

	switch packetType {
	case "EVENT":
		if len(params) != 2 {
			return &PacketError{Message: fmt.Sprintf("bad size for EVENT packet, expected=%d got=%d", 2, len(params))}
		}

		var event nip01.Event
		if err := json.Unmarshal(params[1], &event); err != nil {
			return &PacketError{Message: "invalid event", Origin: err}
		}

		p.Packet = &EventPacket{
			Event: &event,
		}

	case "REQ":
		if len(params) < 3 {
			return &PacketError{Message: fmt.Sprintf("bad size for REQ packet, expected>=%d got=%d %v", 3, len(params), string(data))}
		}

		filters := nip01.NewSubscriptionFilterGroup()
		for i := 2; i < len(params); i++ {
			var filter nip01.SubscriptionFilter
			if err := json.Unmarshal(params[i], &filter); err != nil {
				return &PacketError{Message: "invalid filter", Origin: err}
			}
			filters.Add(&filter)
		}

		p.Packet = &RequestPacket{
			SubscriptionID: strings.ReplaceAll(string(params[1]), `"`, ""),
			Filters:        filters,
		}

	case "CLOSE":
		if len(params) != 2 {
			return &PacketError{Message: fmt.Sprintf("bad size for CLOSE packet, expected=%d got=%d", 2, len(params))}
		}

		p.Packet = &ClosePacket{
			SubscriptionID: strings.ReplaceAll(string(params[1]), `"`, ""),
		}

	case "AUTH":
		if len(params) != 2 {
			return &PacketError{Message: fmt.Sprintf("bad size for AUTH packet, expected=%d got=%d", 2, len(params))}
		}

		var event nip01.Event
		if err := json.Unmarshal(params[1], &event); err != nil {
			return &PacketError{Message: "invalid auth event", Origin: err}
		}

		p.Packet = &AuthPacket{
			Event: &event,
		}

	case "COUNT":
		if len(params) < 3 {
			return &PacketError{Message: fmt.Sprintf("bad size for COUNT packet, expected>=%d got=%d", 3, len(params))}
		}

		filters := nip01.NewSubscriptionFilterGroup()
		for i := 2; i < len(params); i++ {
			var filter nip01.SubscriptionFilter
			if err := json.Unmarshal(params[i], &filter); err != nil {
				return &PacketError{Message: "invalid filter", Origin: err}
			}
			filters.Add(&filter)
		}

		p.Packet = &CountPacket{
			SubscriptionID: strings.ReplaceAll(string(params[1]), `"`, ""),
			Filters:        filters,
		}

	case "NEG-OPEN":
		// ["NEG-OPEN", <subscription_id>, <filter>, <initial_message>]
		if len(params) != 4 {
			return &PacketError{Message: fmt.Sprintf("bad size for NEG-OPEN packet, expected=%d got=%d", 4, len(params))}
		}

		var filter nip01.SubscriptionFilter
		if err := json.Unmarshal(params[2], &filter); err != nil {
			return &PacketError{Message: "invalid filter", Origin: err}
		}

		initialMsg := strings.ReplaceAll(string(params[3]), `"`, "")

		p.Packet = &NegOpenPacket{
			SubscriptionID: strings.ReplaceAll(string(params[1]), `"`, ""),
			Filter:         &filter,
			Message:        initialMsg,
		}

	case "NEG-MSG":
		// ["NEG-MSG", <subscription_id>, <message>]
		if len(params) != 3 {
			return &PacketError{Message: fmt.Sprintf("bad size for NEG-MSG packet, expected=%d got=%d", 3, len(params))}
		}

		p.Packet = &NegMsgPacket{
			SubscriptionID: strings.ReplaceAll(string(params[1]), `"`, ""),
			Message:        strings.ReplaceAll(string(params[2]), `"`, ""),
		}

	case "NEG-CLOSE":
		// ["NEG-CLOSE", <subscription_id>]
		if len(params) != 2 {
			return &PacketError{Message: fmt.Sprintf("bad size for NEG-CLOSE packet, expected=%d got=%d", 2, len(params))}
		}

		p.Packet = &NegClosePacket{
			SubscriptionID: strings.ReplaceAll(string(params[1]), `"`, ""),
		}

	case "NEG-ERR":
		// ["NEG-ERR", <subscription_id>, <code_id>]
		if len(params) != 3 {
			return &PacketError{Message: fmt.Sprintf("bad size for NEG-ERR packet, expected=%d got=%d", 3, len(params))}
		}

		p.Packet = &NegErrPacket{
			SubscriptionID: strings.ReplaceAll(string(params[1]), `"`, ""),
			Code:           strings.ReplaceAll(string(params[2]), `"`, ""),
		}

	default:
		return &PacketError{Message: fmt.Sprintf("invalid packet, got=%s", packetType)}
	}

	return nil
}

/////////////////////////////////////////////////////////////////////
// REQ
/////////////////////////////////////////////////////////////////////

type RequestPacket struct {
	SubscriptionID string
	Filters        *nip01.SubscriptionFilterGroup
}

func NewRequestPacket(subID string, filters *nip01.SubscriptionFilterGroup) *RequestPacket {
	return &RequestPacket{
		SubscriptionID: subID,
		Filters:        filters,
	}
}

func (rp *RequestPacket) MarshalJSON() ([]byte, error) {

	parts := []interface{}{
		"REQ",
		rp.SubscriptionID,
	}

	for _, filter := range rp.Filters.GetAll() {
		parts = append(parts, filter)
	}

	return json.Marshal(parts)
}

func (rp *RequestPacket) String() string {
	return fmt.Sprintf("subscriptionID:%+v filters:%+v", rp.SubscriptionID, rp.Filters)
}

/////////////////////////////////////////////////////////////////////
// CLOSE
/////////////////////////////////////////////////////////////////////

type ClosePacket struct {
	SubscriptionID string
}

func NewClosePacket(subID string) *ClosePacket {
	return &ClosePacket{
		SubscriptionID: subID,
	}
}

func (rp *ClosePacket) MarshalJSON() ([]byte, error) {

	result := make([]interface{}, 2)
	result[0] = "CLOSE"
	result[1] = rp.SubscriptionID

	return json.Marshal(result)
}

func (cp *ClosePacket) String() string {
	return fmt.Sprintf("subscriptionID:%+v", cp.SubscriptionID)
}

/////////////////////////////////////////////////////////////////////
// AUTH
/////////////////////////////////////////////////////////////////////

type AuthPacket struct {
	Event *nip01.Event
}

func (ap *AuthPacket) MarshalJSON() ([]byte, error) {
	result := make([]interface{}, 2)
	result[0] = "AUTH"
	result[1] = ap.Event
	return json.Marshal(result)
}

/////////////////////////////////////////////////////////////////////
// COUNT
/////////////////////////////////////////////////////////////////////

type CountPacket struct {
	SubscriptionID string
	Filters        *nip01.SubscriptionFilterGroup
}

func (cp *CountPacket) MarshalJSON() ([]byte, error) {
	parts := []interface{}{
		"COUNT",
		cp.SubscriptionID,
	}
	for _, filter := range cp.Filters.GetAll() {
		parts = append(parts, filter)
	}
	return json.Marshal(parts)
}

/////////////////////////////////////////////////////////////////////
// EVENT
/////////////////////////////////////////////////////////////////////

type EventPacket struct {
	Event *nip01.Event
}

func NewEventPacket(ev *nip01.Event) *EventPacket {
	return &EventPacket{
		Event: ev,
	}
}

func (ep *EventPacket) MarshalJSON() ([]byte, error) {

	result := make([]interface{}, 2)
	result[0] = "EVENT"
	result[1] = ep.Event

	return json.Marshal(result)

}

func (ep *EventPacket) String() string {
	return fmt.Sprintf("event:%+v", ep.Event)
}

/////////////////////////////////////////////////////////////////////
// NEGENTROPY
/////////////////////////////////////////////////////////////////////

type NegOpenPacket struct {
	SubscriptionID string
	Filter         *nip01.SubscriptionFilter
	Message        string
}

func (p *NegOpenPacket) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"NEG-OPEN", p.SubscriptionID, p.Filter, p.Message})
}

type NegMsgPacket struct {
	SubscriptionID string
	Message        string
}

func (p *NegMsgPacket) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"NEG-MSG", p.SubscriptionID, p.Message})
}

type NegClosePacket struct {
	SubscriptionID string
}

func (p *NegClosePacket) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"NEG-CLOSE", p.SubscriptionID})
}

type NegErrPacket struct {
	SubscriptionID string
	Code           string
}

func (p *NegErrPacket) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"NEG-ERR", p.SubscriptionID, p.Code})
}

/////////////////////////////////////////////////////////////////////
// RESPONSES
/////////////////////////////////////////////////////////////////////

type SubscriptionResponse interface{}

type ClientPayload struct {
	SubscriptionResponse
}

func (sr *ClientPayload) UnmarshalJSON(data []byte) error {

	var params []json.RawMessage
	if err := json.Unmarshal(data, &params); err != nil {
		return fmt.Errorf("unexpected payload format: %w", err)
	}

	if len(params) < 1 {
		return fmt.Errorf("invalid payload size, got=%d", len(params))
	}

	messageType := strings.ReplaceAll(string(params[0]), `"`, "")

	switch messageType {
	case "EVENT":
		sr.SubscriptionResponse = &EventSubscriptionResponse{}
	case "EOSE":
		sr.SubscriptionResponse = &EOSESubscriptionResponse{}
	case "OK":
		sr.SubscriptionResponse = &OkSubscriptionResponse{}
	case "CLOSED":
		sr.SubscriptionResponse = &ClosedSubscriptionResponse{}
	case "NOTICE":
		sr.SubscriptionResponse = &NoticeSubscriptionResponse{}
	case "COUNT":
		sr.SubscriptionResponse = &CountSubscriptionResponse{}
	case "AUTH":
		sr.SubscriptionResponse = &AuthChallengeResponse{}
	case "NEG-MSG":
		sr.SubscriptionResponse = &NegMsgResponse{}
	case "NEG-ERR":
		sr.SubscriptionResponse = &NegErrResponse{}
	default:
		return fmt.Errorf("unknown payload format, got=%s", string(data))
	}

	return json.Unmarshal(data, sr.SubscriptionResponse)
}

type NoticeSubscriptionResponse struct {
	Message string
}

func (nsr *NoticeSubscriptionResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"NOTICE", nsr.Message})
}

func (nsr *NoticeSubscriptionResponse) UnmarshalJSON(data []byte) error {
	var result []interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}

	expectedLen := 2
	if len(result) != expectedLen {
		return fmt.Errorf("failed to parse Notice packet, unexpected length: want=%d got=%d", expectedLen, len(result))
	}

	if val, ok := result[0].(string); !ok || val != "NOTICE" {
		return fmt.Errorf("failed to parse Notice packet, unexpected type: want=NOTICE got=%v", result[0])
	}

	if val, ok := result[1].(string); !ok {
		return fmt.Errorf("failed to parse Notice packet, invalid `accepted` field: want=OK got=%v", result[1])
	} else {
		nsr.Message = val
	}

	return nil
}

type EventSubscriptionResponse struct {
	SubscriptionID string
	Event          *nip01.Event
	// For sending raw bytes if available (optimization)
	EventBytes []byte
}

func (esr *EventSubscriptionResponse) MarshalJSON() ([]byte, error) {
	// Optimization: if we have pre-marshaled event bytes, reuse them.
	// But JSON array construction is manual here.
	// ["EVENT", <subscription_id>, <event JSON>]
	// We construct it manually to avoid parsing EventBytes.
	if len(esr.EventBytes) > 0 {
		var b strings.Builder
		b.WriteString(`["EVENT","`)
		b.WriteString(esr.SubscriptionID)
		b.WriteString(`",`)
		b.Write(esr.EventBytes)
		b.WriteString(`]`)
		return []byte(b.String()), nil
	}

	// Fallback to struct marshalling
	return json.Marshal([]interface{}{"EVENT", esr.SubscriptionID, esr.Event})
}

func (esr *EventSubscriptionResponse) UnmarshalJSON(data []byte) error {
	var result []json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if len(result) != 3 {
		return fmt.Errorf("invalid EVENT response length")
	}
	esr.SubscriptionID = strings.ReplaceAll(string(result[1]), `"`, "")
	esr.Event = &nip01.Event{}
	return json.Unmarshal(result[2], esr.Event)
}

type EOSESubscriptionResponse struct {
	SubscriptionID string
}

func (esr *EOSESubscriptionResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"EOSE", esr.SubscriptionID})
}

func (esr *EOSESubscriptionResponse) UnmarshalJSON(data []byte) error {
	var result []interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if len(result) != 2 {
		return fmt.Errorf("invalid EOSE response length")
	}
	esr.SubscriptionID = result[1].(string)
	return nil
}

type OkSubscriptionResponse struct {
	EventID  string
	Accepted bool
	Message  string
}

func (osr *OkSubscriptionResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"OK", osr.EventID, osr.Accepted, osr.Message})
}

func (osr *OkSubscriptionResponse) UnmarshalJSON(data []byte) error {
	var result []interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if len(result) != 4 {
		return fmt.Errorf("invalid OK response length")
	}
	osr.EventID = result[1].(string)
	osr.Accepted = result[2].(bool)
	osr.Message = result[3].(string)
	return nil
}

type ClosedSubscriptionResponse struct {
	SubscriptionID string
	Message        string
}

func (csr *ClosedSubscriptionResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"CLOSED", csr.SubscriptionID, csr.Message})
}

func (csr *ClosedSubscriptionResponse) UnmarshalJSON(data []byte) error {
	var result []interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if len(result) != 3 {
		return fmt.Errorf("invalid CLOSED response length")
	}
	csr.SubscriptionID = result[1].(string)
	csr.Message = result[2].(string)
	return nil
}

type CountSubscriptionResponse struct {
	SubscriptionID string
	Count          int64
}

func (csr *CountSubscriptionResponse) MarshalJSON() ([]byte, error) {
	// NIP-45: ["COUNT", <subscription_id>, { "count": <num> }]
	return json.Marshal([]interface{}{"COUNT", csr.SubscriptionID, map[string]int64{"count": csr.Count}})
}

func (csr *CountSubscriptionResponse) UnmarshalJSON(data []byte) error {
	var result []json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if len(result) != 3 {
		return fmt.Errorf("invalid COUNT response length")
	}
	csr.SubscriptionID = strings.ReplaceAll(string(result[1]), `"`, "")

	var payload struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(result[2], &payload); err != nil {
		return fmt.Errorf("invalid COUNT payload: %w", err)
	}
	csr.Count = payload.Count
	return nil
}

type AuthChallengeResponse struct {
	Challenge string
}

func (acr *AuthChallengeResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{
		"AUTH",
		acr.Challenge,
	})
}

func (acr *AuthChallengeResponse) UnmarshalJSON(data []byte) error {
	var result []interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if len(result) != 2 {
		return fmt.Errorf("invalid AUTH challenge length")
	}
	challenge, ok := result[1].(string)
	if !ok {
		return fmt.Errorf("invalid AUTH challenge: want=string got=%v", result[1])
	}
	acr.Challenge = challenge
	return nil
}

/////////////////////////////////////////////////////////////////////
// NEGENTROPY RESPONSES
/////////////////////////////////////////////////////////////////////

type NegMsgResponse struct {
	SubscriptionID string
	Message        string
}

func (r *NegMsgResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"NEG-MSG", r.SubscriptionID, r.Message})
}

func (r *NegMsgResponse) UnmarshalJSON(data []byte) error {
	var result []interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	if len(result) != 3 {
		return fmt.Errorf("invalid NEG-MSG response length: got=%d", len(result))
	}
	if val, ok := result[1].(string); ok {
		r.SubscriptionID = val
	}
	if val, ok := result[2].(string); ok {
		r.Message = val
	}
	return nil
}

type NegErrResponse struct {
	SubscriptionID string
	Code           string
}

func (r *NegErrResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"NEG-ERR", r.SubscriptionID, r.Code})
}

func (r *NegErrResponse) UnmarshalJSON(data []byte) error {
	var result []interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	// Some relays (e.g. relay.damus.io) send trailing fields beyond the
	// 3-element NIP-77 spec; tolerate and ignore them rather than erroring.
	if len(result) < 3 {
		return fmt.Errorf("invalid NEG-ERR response length: got=%d", len(result))
	}
	if val, ok := result[1].(string); ok {
		r.SubscriptionID = val
	}
	if val, ok := result[2].(string); ok {
		r.Code = val
	}
	return nil
}
