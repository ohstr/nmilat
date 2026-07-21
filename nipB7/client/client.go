// Package client is an HTTP client for talking to Blossom servers (as
// distinct from nipB7 itself, which only builds/parses the protocol's
// events and types and makes no network calls). It mirrors nmilat's
// relay/client split: nipB7 stays a dependency-light protocol library,
// while this package is the piece that actually dials out.
//
// Every method streams request/response bodies rather than buffering whole
// blobs in memory, takes a context.Context for cancellation, and performs
// no retries or caching of its own — callers control timeouts via ctx and
// connection reuse/pooling via Client.HTTPClient.
package client

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
)

// ErrEmptyServer is returned when a method is called with an empty server
// URL.
var ErrEmptyServer = errors.New("nipB7/client: server url is empty")

// ErrNoServers is returned by GetFromServers when given an empty server
// list.
var ErrNoServers = errors.New("nipB7/client: no servers given")

// Client is a Blossom HTTP client. The zero value is ready to use.
type Client struct {
	// HTTPClient is the underlying HTTP client used for every request. A
	// nil value falls back to http.DefaultClient. Set this to control
	// timeouts, transport-level connection pooling, or TLS config — the
	// same *http.Client is reused across calls so connections are pooled
	// rather than re-dialed per request.
	HTTPClient *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// setAuthHeader encodes auth (if non-nil) as the request's "Authorization:
// Nostr <token>" header (BUD-11).
func setAuthHeader(req *http.Request, auth *nip01.Event) error {
	if auth == nil {
		return nil
	}
	header, err := nipB7.EncodeAuthHeader(auth)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", header)
	return nil
}

// joinPath builds server+path, tolerating a trailing slash on server.
func joinPath(server, path string) (string, error) {
	if server == "" {
		return "", ErrEmptyServer
	}
	return strings.TrimRight(server, "/") + path, nil
}
