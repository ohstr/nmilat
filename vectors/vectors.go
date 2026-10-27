// Package vectors builds the cross-implementation test vector files of the
// cash protocols (NIP-CASH, NIP-CW, NIP-CO, NIP-CP, NIP-CZ, NIP-IC, NIP-LSP
// and the NIPs they rest on).
//
// Every expected value is computed by calling nmilat on a fixed set of
// inputs. Nothing here re-implements protocol logic: if nmilat changes
// behaviour, the regenerated JSON changes and a drift check against the
// committed files (testdata/vectors at the module root) turns red.
//
// Inputs are deterministic: fixed keys, RFC 6979 signatures from
// nipcash.LocalMintSigner, and, where a function draws randomness (NIP-44
// nonces, NIP-04 IVs, cash secrets), crypto/rand.Reader temporarily replaced
// by a seeded stream. Because of that replacement, WriteAll and the builders
// must not run concurrently with other users of crypto/rand.Reader; they are
// meant for an export command or a test, not for a running service.
package vectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Version is the value of every file's "nmilat" header field. It is a fixed
// string, not the module version, so that regenerating at another commit
// produces identical bytes; the commit that produced a file is the one that
// committed it.
const Version = "github.com/ohstr/nmilat devel"

// File is one vector file: its name (for example "tlv.json") and the
// function that builds its content.
type File struct {
	Name  string
	Build func() (any, error)
}

// Files returns every vector file in a fixed order.
func Files() []File {
	return []File{
		{"tlv.json", buildTLV},
		{"hub-group.json", buildHubGroup},
		{"cash-string.json", buildCashString},
		{"provenance.json", buildProvenance},
		{"connection-key.json", buildConnectionKey},
		{"nip44.json", buildNIP44},
		{"nip01.json", buildNIP01},
		{"bolt11.json", buildBolt11},
		{"claim.json", buildClaim},
		{"nip19.json", buildNIP19},
		{"nip47.json", buildNIP47},
		{"nip04.json", buildNIP04},
		{"nipcw.json", buildNIPCW},
		{"reply-key.json", buildReplyKey},
		{"canonical-params.json", buildCanonicalParams},
		{"padding.json", buildPadding},
		{"envelope.json", buildEnvelope},
		{"proof.json", buildProofVectors},
		{"announcement.json", buildAnnouncement},
		{"private-join.json", buildPrivateJoin},
		{"relay-hash.json", buildRelayHash},
		{"request-id.json", buildRequestID},
		{"lookup.json", buildLookup},
		{"mint-cash.json", buildMintCash},
		{"budget-period.json", buildBudgetPeriod},
		{"cw-fees.json", buildCWFees},
		{"npv1.json", buildNPV1},
		{"nconnection.json", buildNConnection},
		{"pow.json", buildPow},
		{"connection.json", buildConnection},
	}
}

// buildMu serializes builders: some replace crypto/rand.Reader while they run.
var buildMu sync.Mutex

// Build returns the encoded bytes of one file: indented JSON without HTML
// escaping and with a trailing newline.
func Build(f File) ([]byte, error) {
	buildMu.Lock()
	defer buildMu.Unlock()
	v, err := f.Build()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Name, err)
	}
	data, err := marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Name, err)
	}
	return data, nil
}

// WriteAll builds every file of Files and writes it into dir, creating dir
// if needed.
func WriteAll(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range Files() {
		data, err := Build(f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, f.Name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// header opens every vector file so a reader can tell where it came from.
type header struct {
	Description string `json:"description"`
	Source      string `json:"source"`
	Nmilat      string `json:"nmilat"`
}

func newHeader(description, source string) header {
	return header{Description: description, Source: source, Nmilat: Version}
}

// marshal is json.MarshalIndent without HTML escaping, so strings such as
// "a<b" stay readable, plus a trailing newline.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// errString is the error text a failed call produced, or "" on success. It
// is recorded for humans; a port only has to fail, not match it.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func strPtr(s string) *string { return &s }
