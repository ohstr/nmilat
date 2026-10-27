// Package signeruri opens a signer from any URI a client accepts for one:
// a bunker:// URI (a remote signer over relays, NIP-46) or a
// bunker+unix:// URI (a local signer on a unix socket, NIP-LS), so code
// that takes a bunker:// URI takes the other spellings too.
//
//	s, err := signeruri.Dial(ctx, uri, bunker.ClientOptions{Perms: "sign_event:1"})
//	if err != nil { ... }
//	defer s.(io.Closer).Close()
//	err = s.Sign(ctx, ev)
//
// It lives apart from nip46/bunker and nipLS so neither imports the other.
package signeruri

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip46/bunker"
	"github.com/ohstr/nmilat/nipLS"
)

// ErrUnsupportedScheme means the URI names neither a bunker:// nor a
// local (bunker+unix://, unix:// or bare absolute path) signer.
var ErrUnsupportedScheme = errors.New("signeruri: unsupported signer URI scheme")

// Dial connects to the signer uri names:
//
//   - bunker://<pubkey>?relay=... goes to bunker.Dial with opts, and
//     returns a *bunker.Client;
//   - bunker+unix:///abs/path.sock, unix:///abs/path.sock or a bare
//     absolute path goes to nipLS.Dial (nipLS.ParseURI decides whether it
//     is valid), and returns a *nipLS.Client; opts is not used.
//
// Any other scheme fails with ErrUnsupportedScheme. Both returned types
// are a nip46.Key and have a Close method, which the caller calls when
// done. ctx bounds connecting only.
func Dial(ctx context.Context, uri string, opts bunker.ClientOptions) (nip46.Signer, error) {
	// The trimmed string, with its scheme lowercased (schemes are
	// case-insensitive), is what the chosen dialer parses.
	uri = strings.TrimSpace(uri)
	scheme, rest, hasScheme := strings.Cut(uri, "://")
	if hasScheme {
		scheme = strings.ToLower(scheme)
		uri = scheme + "://" + rest
		switch scheme {
		case bunker.URIScheme:
			c, err := bunker.Dial(ctx, uri, opts)
			if err != nil {
				return nil, err
			}
			return c, nil
		case nipLS.URIScheme, "unix":
		default:
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
		}
	}
	c, err := nipLS.Dial(ctx, uri)
	if err != nil {
		return nil, err
	}
	return c, nil
}
