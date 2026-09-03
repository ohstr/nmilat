package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
)

type mirrorRequestBody struct {
	URL string `json:"url"`
}

// Mirror asks server to fetch and store the blob at sourceURL (BUD-04's
// PUT /mirror), returning its Blob Descriptor.
func (c *Client) Mirror(ctx context.Context, server, sourceURL string, auth *nip01.Event) (*nipB7.BlobDescriptor, error) {
	u, err := joinPath(server, "/mirror")
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(mirrorRequestBody{URL: sourceURL})
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := setAuthHeader(httpReq, auth); err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, newResponseError(server, resp)
	}

	var descriptor nipB7.BlobDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&descriptor); err != nil {
		return nil, fmt.Errorf("nipB7/client: decoding blob descriptor: %w", err)
	}
	if err := descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("nipB7/client: server returned invalid blob descriptor: %w", err)
	}
	return &descriptor, nil
}
