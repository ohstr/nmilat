package nipLS

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip46"
)

// echoLen answers with the byte length of params[0]; signer_big with
// a result of params[0] bytes.
var echoLen = map[string]Handler{
	"signer_echo_len": func(_ context.Context, r *Request) (string, error) {
		if len(r.Params) == 0 {
			return "0", nil
		}
		return strconv.Itoa(len(r.Params[0])), nil
	},
	"signer_big": func(_ context.Context, r *Request) (string, error) {
		n, _ := strconv.Atoi(r.Params[0])
		return strings.Repeat("r", n), nil
	},
}

// requestOfSize is a signer_echo_len request line of exactly n bytes, no "\n".
func requestOfSize(t *testing.T, id string, n int) []byte {
	t.Helper()
	empty, _ := json.Marshal(nip46.Request{RequestID: id, Method: "signer_echo_len", Params: []string{""}})
	line, _ := json.Marshal(nip46.Request{RequestID: id, Method: "signer_echo_len", Params: []string{strings.Repeat("p", n-len(empty))}})
	if len(line) != n {
		t.Fatalf("built a %d-byte request, want %d", len(line), n)
	}
	return line
}

// T16-02 (S-LS-03, 04): over-long lines get an empty-id invalid answer,
// the rest of the line is discarded, the connection is kept.
func TestSpecLineCap(t *testing.T) {
	h := start(t, ServerConfig{Methods: echoLen})
	r := rawDial(t, h)

	wantTooLong := func(what string) {
		t.Helper()
		resp := r.read()
		if resp.RequestID != "" || resp.Error != ErrPrefixInvalid+"line too long" || resp.Result != "" {
			t.Fatalf("%s: answered %+v", what, resp)
		}
	}

	// 1048577 bytes and "\n".
	r.write(append([]byte(strings.Repeat("a", MaxMessageSize+1)), '\n'))
	wantTooLong("1048577-byte line")
	r.ping("1")

	// 1048577 bytes without "\n": answered before the line ends; the
	// rest (several MiB) is discarded through its "\n" without a second
	// answer.
	r.write([]byte(strings.Repeat("b", MaxMessageSize+1)))
	wantTooLong("1048577 bytes, no newline")
	for i := 0; i < 4; i++ {
		r.write([]byte(strings.Repeat(`{"id":"no","method":"ping","params":[]}`, MaxMessageSize/32)))
	}
	r.write([]byte("tail\n"))
	r.ping("2")

	// The end of an over-long line and the next request in one write.
	r.write([]byte(strings.Repeat("c", MaxMessageSize+1)))
	wantTooLong("third over-long line")
	r.write([]byte("tail\n" + `{"id":"same-write","method":"ping","params":[]}` + "\n"))
	if resp := r.read(); resp.RequestID != "same-write" || resp.Result != "pong" {
		t.Fatalf("request after the discarded tail answered %+v", resp)
	}

	// Exactly 1048576 bytes and "\n" is served.
	r.write(append(requestOfSize(t, "exact", MaxMessageSize), '\n'))
	if resp := r.read(); resp.RequestID != "exact" || resp.Error != "" {
		t.Fatalf("1048576-byte request answered %+v", resp)
	}

	// "\r\n" counts the "\r": 1048576 bytes and "\r\n" is over.
	r.write(append(requestOfSize(t, "cr", MaxMessageSize), '\r', '\n'))
	wantTooLong("1048576 bytes and CRLF")
	r.ping("3")

	// A shorter line ending in "\r\n" is fine.
	r.write([]byte(`{"id":"4","method":"ping","params":[]}` + "\r\n"))
	if resp := r.read(); resp.RequestID != "4" || resp.Result != "pong" {
		t.Fatalf("CRLF ping answered %+v", resp)
	}
}

// The splitter never holds more than MaxMessageSize+1 bytes of a line.
func TestSpecSplitterBounded(t *testing.T) {
	var l lineSplitter
	data := []byte(strings.Repeat("x", MaxMessageSize+1))
	adv, tok, err := l.split(data, false)
	if err != nil || adv != MaxMessageSize+1 || tok == nil || len(tok) != 0 || !l.overlong {
		t.Fatalf("over-long: %d %q %v overlong=%v", adv, tok, err, l.overlong)
	}
	l.overlong = false
	// While discarding, everything given is consumed, nothing returned.
	if adv, tok, _ := l.split([]byte("yyyy"), false); adv != 4 || tok != nil {
		t.Fatalf("discard: %d %q", adv, tok)
	}
	if adv, tok, _ := l.split([]byte("yy\n{}"), false); adv != 3 || tok != nil || l.discarding {
		t.Fatalf("discard end: %d %q", adv, tok)
	}
	// A whole line behind the discarded one comes back in the same call.
	l.discarding = true
	if adv, tok, _ := l.split([]byte("yy\n{}\n{"), false); adv != 6 || string(tok) != "{}" || l.discarding {
		t.Fatalf("discard end and line: %d %q", adv, tok)
	}
	if adv, tok, _ := l.split([]byte("{}\r\n"), false); adv != 4 || string(tok) != "{}\r" {
		t.Fatalf("line: %d %q", adv, tok)
	}
	if adv, tok, _ := l.split([]byte("{}"), true); adv != 2 || string(tok) != "{}" {
		t.Fatalf("final line: %d %q", adv, tok)
	}
	if adv, tok, _ := l.split(nil, true); adv != 0 || tok != nil {
		t.Fatalf("eof: %d %q", adv, tok)
	}
}

// T16-03 (S-LS-05): the client refuses an over-cap request and writes
// nothing; the signer answers an over-cap result with an error.
func TestSpecSendCap(t *testing.T) {
	h := start(t, ServerConfig{Methods: echoLen})
	c := dial(t, h)
	ctx := context.Background()

	empty, _ := json.Marshal(nip46.Request{RequestID: "2", Method: "signer_echo_len", Params: []string{""}})
	fits := strings.Repeat("p", MaxMessageSize-len(empty))
	if got, err := c.Call(ctx, "signer_echo_len", fits); err != nil || got != strconv.Itoa(len(fits)) {
		t.Fatalf("1048576-byte request: %q, %v", got, err)
	}
	if _, err := c.Call(ctx, "signer_echo_len", fits+"pp"); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("1048577+ byte request: %v", err)
	}
	// Nothing was written: the connection is still in step.
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping after a refused send: %v", err)
	}

	// A result whose response line is exactly 1048576 bytes is sent and read.
	const overhead = len(`{"id":"4","result":""}`)
	if got, err := c.Call(ctx, "signer_big", strconv.Itoa(MaxMessageSize-overhead)); err != nil || len(got) != MaxMessageSize-overhead {
		t.Fatalf("1048576-byte response: %d bytes, %v", len(got), err)
	}
	// One byte more is replaced by an error for the same id.
	_, err := c.Call(ctx, "signer_big", strconv.Itoa(MaxMessageSize-overhead+1))
	var e *Error
	if !errors.As(err, &e) || e.Code != nil || e.Reason != "result too large" {
		t.Fatalf("over-cap result: %v", err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping after an over-cap result: %v", err)
	}
}
