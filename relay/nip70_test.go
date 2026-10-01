package relay

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// protectedNote is an ordinary kind:1 carrying NIP-70's marker, so these tests
// exercise the gate itself rather than NIP-43's relay-authored rules.
func protectedNote(t *testing.T, privKey string) *nip01.Event {
	t.Helper()
	ev := nip01.NewUnsignedEvent(1, "", "protected", []string{"-"})
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return ev
}

func TestNip70_UnauthenticatedProtectedEventIsRefused(t *testing.T) {
	sess := newSelfAuthTestSession(t, "")

	resp := sendEventAndAwaitOKForSession(t, sess, protectedNote(t, authTestPrivKey))

	if resp.Accepted {
		t.Fatal("Accepted = true, want false for a protected event with no AUTH")
	}
	// auth-required tells the client to run AUTH and retry, which is the only
	// thing that can help here.
	if !strings.HasPrefix(resp.Message, "auth-required:") {
		t.Fatalf("Message = %q, want an auth-required prefix", resp.Message)
	}
}

func TestNip70_ProtectedEventFromAnotherAuthorIsRefused(t *testing.T) {
	sess := newSelfAuthTestSession(t, "")
	ev := protectedNote(t, authTestPrivKey)

	// Someone else authenticated on this connection; a valid signature on a
	// protected event they did not author must not be enough.
	other := &nip01.Event{}
	if err := other.Sign("0000000000000000000000000000000000000000000000000000000000000001"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	authSessionAs(sess, other.PubKey)

	resp := sendEventAndAwaitOKForSession(t, sess, ev)

	if resp.Accepted {
		t.Fatal("Accepted = true, want false for a protected event from a different author")
	}
	// restricted, not auth-required: this connection has authenticated, so
	// retrying the AUTH flow cannot change the outcome.
	if !strings.HasPrefix(resp.Message, "restricted:") {
		t.Fatalf("Message = %q, want a restricted prefix", resp.Message)
	}
}

func TestNip70_AuthorMayPublishItsOwnProtectedEvent(t *testing.T) {
	sess := newSelfAuthTestSession(t, "")
	authSessionAs(sess, authTestPubKey)

	resp := sendEventAndAwaitOKForSession(t, sess, protectedNote(t, authTestPrivKey))

	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for the author's own protected event (message: %s)", resp.Message)
	}
}

func TestNip70_UnprotectedEventIsUnaffected(t *testing.T) {
	sess := newSelfAuthTestSession(t, "")

	ev := nip01.NewUnsignedEvent(1, "", "ordinary")
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)

	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for an unprotected event (message: %s)", resp.Message)
	}
}
