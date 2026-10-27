// Package cashtest is the NIP-CASH test harness: an in-process relay set, a fake
// Hub that serves the private transport (kinds 23190/23191) and its kind-23194
// connection, a manual clock and fault hooks.
//
// It is internal on purpose. Tests in this module drive the real SDK against it;
// the exported scenario suite in nipcash/conformance runs against it in CI and,
// through an adapter, against any real Hub.
//
// The fake decides with the module's own transport helpers (envelope decoding,
// freshness, the reply key), so it cannot drift from what the SDK expects. Hub
// rules whose shared helpers do not exist yet are not faked here: a test says
// how each item is answered through WithDecide. The one ledger is
// ServeWithdrawals': bills minted by mint_cash, their cash_status, and on-chain
// withdrawals paid on a fake Chain.
package cashtest
