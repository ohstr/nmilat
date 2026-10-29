#!/usr/bin/env bash
# Refuses the identifiers the final cash NIPs removed from the cash packages (SPEC-SYNC-PLAN WP-19).
# A line that must keep one carries "legacy-check: <reason>" and is skipped. nip47/, relay/ and nip46/
# are not searched: plain NIP-47 keeps its URI form and NIP-04.
set -euo pipefail

root="${1:-$(git rev-parse --show-toplevel)}"
cd "$root"

markers=(
	'IdempotencyKey'
	'PairingURI'
	'ParsePairingURI'
	'BuildPairingURI'
	'json:"pairing_uri'
	'json:"idempotency_key'
	'FallbackReason'
	'ConfirmFallback'
	'RequirePrivate'
	'ErrPrivateJoinUnavailable'
	'MaxNotAfterWindow'
	'(^|[^A-Za-z0-9_])MintPayload\('
	'LegacyMintPayload'
	'ErrLegacyEncode'
	'lokicash-mint'
	'satscash-mint'
	'MatchClaim'
	'CashStatusRow'
	'Anyone\(\)'
	'EncryptionNIP04'
)
paths=(nipcash nipcw nipCO nipCZ nipCP nipIC nipAZ internal/cashtest)

pattern=$(IFS='|'; echo "${markers[*]}")
hits=$(git grep -nE "$pattern" -- "${paths[@]}" | grep -v 'legacy-check:' || true)
if [ -n "$hits" ]; then
	echo "legacy-check: identifiers the cash NIPs removed (mark a line that must keep one with \"legacy-check: <reason>\"):"
	echo "$hits"
	exit 1
fi
echo "legacy-check: no legacy markers"
