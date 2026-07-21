package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
)

// GetOptions configures Client.Get/Client.Head/Client.GetFromServers. All
// fields are optional.
type GetOptions struct {
	Ext   string       // file extension, e.g. "png"
	Range string       // raw Range header value, e.g. "bytes=0-1023"
	Auth  *nip01.Event // signed kind:24242 token; most servers don't require auth for GET
}

// Get retrieves a blob by hash from server (BUD-01's GET /<sha256>[.ext]).
// The caller MUST close the returned response's Body — this streams the
// blob rather than buffering it, so a large file costs one connection's
// worth of memory, not the whole payload.
func (c *Client) Get(ctx context.Context, server, hash string, opts GetOptions) (*http.Response, error) {
	u, err := nipB7.BuildServerURL(server, hash, opts.Ext)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if opts.Range != "" {
		req.Header.Set("Range", opts.Range)
	}
	if err := setAuthHeader(req, opts.Auth); err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, newResponseError(server, resp)
	}
	return resp, nil
}

// GetFromServers tries each server in order and returns the first
// successful response, along with which server served it — the file
// recovery process NIP-B7's server list exists for. Servers are tried
// sequentially rather than in parallel: the point of a server list is
// redundancy on failure, not multiplying request volume on every call. If
// ctx is canceled partway through, that error is returned immediately
// instead of continuing to the next server. The caller MUST close the
// returned response's Body.
func (c *Client) GetFromServers(ctx context.Context, servers []string, hash string, opts GetOptions) (resp *http.Response, usedServer string, err error) {
	if len(servers) == 0 {
		return nil, "", ErrNoServers
	}

	var errs []error
	for _, server := range servers {
		resp, err := c.Get(ctx, server, hash, opts)
		if err == nil {
			return resp, server, nil
		}
		if ctx.Err() != nil {
			return nil, "", err
		}
		errs = append(errs, fmt.Errorf("%s: %w", server, err))
	}
	return nil, "", fmt.Errorf("nipB7/client: all %d servers failed: %w", len(servers), errors.Join(errs...))
}

// BlobInfo is the metadata a HEAD /<sha256> response reports (BUD-01).
type BlobInfo struct {
	ContentType   string
	ContentLength int64
	AcceptRanges  bool
}

// Head fetches a blob's metadata without its body (BUD-01's
// HEAD /<sha256>[.ext]).
func (c *Client) Head(ctx context.Context, server, hash string, opts GetOptions) (*BlobInfo, error) {
	u, err := nipB7.BuildServerURL(server, hash, opts.Ext)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, err
	}
	if err := setAuthHeader(req, opts.Auth); err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, newResponseError(server, resp)
	}
	return &BlobInfo{
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		AcceptRanges:  strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes"),
	}, nil
}
