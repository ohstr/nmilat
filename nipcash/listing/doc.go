// Package listing implements NIP-CASH §Listing Offers: the offer listing (kind
// 31190), the operator's offers (kind 11191), recommendations (kind 31191),
// reports (kind 1984, NIP-56) and curators (a NIP-51 follow set with d
// "cash-discover").
//
// A listing advertises and never decides. The terms always come from get_info
// on the listed connection, read when the user picks the offer (CheckTap); a
// hint is shown as listed, never as terms.
//
// The Hub side builds listings only from its own typed connection records
// (NewListing takes a *nipCO.OrderConnection or a *nipcw.CircleHubConnection,
// never a pasted string and never a cashhub1 one), signed by TLV 4, and retires
// them in the §Hub Rules order (ClosedListing, then NewListingDeletion).
//
// The wallet side runs the "before showing" checks in order (ParseListing for
// steps 1 to 4, VersionBook.Current for step 5), keeps the newest version per
// address (VersionBook), takes signals only from the user's follows and
// curators (Trust, SignalsFor) and ranks with RankKey. Nothing but a mismatch in
// a reply the listed connection signed, or the Hub's own closed signal, hides a
// listing: no answer, a silent relay or any error code leaves it shown as
// unavailable (TapOutcome).
//
// Every text a lister writes (title, location, content, the string's label) is
// untrusted: display it through SanitizeText, draw marks outside it, and never
// render or open a link in it. No string of a listing but its connection is
// decoded or dialled, and no connection URI form is read or written here.
package listing
