package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// joinPaths records which transport join took.
type joinPaths struct {
	privateErr       error
	privateIdentity  string
	privateCalls     int
	standardCalls    int
	standardResponse *nipcw.CreateCircleWalletResponse
}

func (p *joinPaths) private(_ context.Context, identity string) (*nipcw.CreateCircleWalletResponse, error) {
	p.privateCalls++
	p.privateIdentity = identity
	if p.privateErr != nil {
		return nil, p.privateErr
	}
	return &nipcw.CreateCircleWalletResponse{WalletPubkey: "private"}, nil
}

func (p *joinPaths) standard(context.Context) (*nipcw.CreateCircleWalletResponse, error) {
	p.standardCalls++
	return &nipcw.CreateCircleWalletResponse{WalletPubkey: "standard"}, nil
}

const testIdentity = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func TestJoin_NoIdentityUsesStandard(t *testing.T) {
	for _, info := range []*nip47.CircleWalletInfo{nil, {CirclePolicy: nip47.CirclePolicyAllowlist}} {
		p := &joinPaths{}
		got, err := join(context.Background(), info, JoinOptions{}, p.private, p.standard)
		if err != nil {
			t.Fatal(err)
		}
		if got.Private || got.FallbackReason != nil || p.privateCalls != 0 || p.standardCalls != 1 {
			t.Fatalf("info %+v: result %+v, private %d, standard %d", info, got, p.privateCalls, p.standardCalls)
		}
	}
}

func TestJoin_IdentityJoinsPrivately(t *testing.T) {
	p := &joinPaths{}
	got, err := join(context.Background(), &nip47.CircleWalletInfo{Identity: testIdentity}, JoinOptions{}, p.private, p.standard)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Private || got.WalletPubkey != "private" || p.standardCalls != 0 {
		t.Fatalf("result %+v, standard calls %d", got, p.standardCalls)
	}
	if p.privateIdentity != testIdentity {
		t.Fatalf("private join used identity %q, want get_info's %q", p.privateIdentity, testIdentity)
	}
}

// NIP-CW §Finding the Private Transport: a fallback is allowed but never silent.
func TestJoin_NoAnnouncementFallsBackAndSaysSo(t *testing.T) {
	reason := errors.New("no announcement")
	p := &joinPaths{privateErr: &unavailableError{err: reason}}
	got, err := join(context.Background(), &nip47.CircleWalletInfo{Identity: testIdentity}, JoinOptions{}, p.private, p.standard)
	if err != nil {
		t.Fatal(err)
	}
	if got.Private || !errors.Is(got.FallbackReason, reason) || p.standardCalls != 1 {
		t.Fatalf("result %+v, standard calls %d: want a reported fallback", got, p.standardCalls)
	}
}

func TestJoin_RequirePrivateRefusesFallback(t *testing.T) {
	for name, info := range map[string]*nip47.CircleWalletInfo{
		"no identity":     {},
		"no announcement": {Identity: testIdentity},
	} {
		p := &joinPaths{privateErr: &unavailableError{err: errors.New("no announcement")}}
		_, err := join(context.Background(), info, JoinOptions{RequirePrivate: true}, p.private, p.standard)
		if !errors.Is(err, ErrPrivateJoinUnavailable) || p.standardCalls != 0 {
			t.Fatalf("%s: err %v, standard calls %d", name, err, p.standardCalls)
		}
	}
}

// Once the private request is out, an error is final: the join may have run.
func TestJoin_SentPrivateJoinNeverFallsBack(t *testing.T) {
	refused := &relayclient.WalletError{Method: nipcw.MethodCreateCircleWallet, Code: nipcw.ErrRestricted}
	p := &joinPaths{privateErr: refused}
	_, err := join(context.Background(), &nip47.CircleWalletInfo{Identity: testIdentity}, JoinOptions{}, p.private, p.standard)
	var walletErr *relayclient.WalletError
	if !errors.As(err, &walletErr) || walletErr.Code != nipcw.ErrRestricted || p.standardCalls != 0 {
		t.Fatalf("err %v, standard calls %d: want the refusal, no fallback", err, p.standardCalls)
	}
}

// No reachable announcement is a failure before sending, so Join may fall back.
func TestPrivateJoin_NoAnnouncementIsUnavailable(t *testing.T) {
	c := &Client{
		hubPubkey: testIdentity,
		pairing:   &nip47.PairingInfo{WalletPubkey: testIdentity, RelayURLs: []string{"ws://127.0.0.1:1"}, Secret: testIdentity},
	}
	params, err := withConnectionKey(nipcw.CreateCircleWalletParams{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.privateJoin(context.Background(), testIdentity, params)
	var unavailable *unavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err %v: want an unavailableError Join can fall back from", err)
	}
}
