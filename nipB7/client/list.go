package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
)

// List retrieves pubkey's uploaded blobs from server (BUD-12's
// GET /list/<pubkey>), newest first.
func (c *Client) List(ctx context.Context, server, pubkey string, query nipB7.ListQuery, auth *nip01.Event) ([]nipB7.BlobDescriptor, error) {
	u, err := joinPath(server, "/list/"+url.PathEscape(pubkey))
	if err != nil {
		return nil, err
	}
	if values := query.Encode(); len(values) > 0 {
		u += "?" + values.Encode()
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if err := setAuthHeader(httpReq, auth); err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, newResponseError(server, resp)
	}

	var descriptors []nipB7.BlobDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&descriptors); err != nil {
		return nil, fmt.Errorf("nipB7/client: decoding blob list: %w", err)
	}
	return descriptors, nil
}
