// Package nippf implements NIP-PF, Poll Forms: a form (kind 1069) asks one or
// more questions answered in one response (kind 1019); its author closes it
// with a result (kind 1070); NIP-88 polls (kind 1068) may carry the same
// recommendations, notes and closing result.
//
// The spec implemented is ohstr's draft at commit
// 503d428c4afc15fc4ff59dfd6c2ece3961fcbe87 (2026-10-30,
// https://github.com/ohstr/nips/blob/503d428c4afc15fc4ff59dfd6c2ece3961fcbe87/NIP-PF.md).
//
// Tags are read at fixed positions, in any order; positions after the ones the
// spec names are ignored. What each part does:
//
//   - ParseForm reads a form and applies every validity rule; an invalid form
//     is an error wrapping ErrInvalidForm. A question type this package does not
//     know makes the form ReadOnly (it is shown, never answered).
//   - ParseResponse and ParseResult read a response or a result on their own;
//     Form.Check and Form.CheckResult apply the rules that need the form.
//   - Form.Closing, Form.State, Form.Select and Form.Tally are the lifecycle:
//     the closing result (the earliest valid result by the form's author, ties
//     to the lowest id), the state (open, ended, decided, default, cancelled,
//     expired), the response kept per allowed pubkey and the tally.
//   - Form.Event, Form.NewResponse, Form.NewWithdrawal and Form.NewResult build
//     unsigned events and read each back before returning it, so nothing
//     invalid leaves this package.
//   - ParsePollExtras, CheckPollResult and NewPollResult are the NIP-88 side;
//     counting votes stays nip88's.
//   - Wrap and Open are the private delivery: one rumor sealed and gift-wrapped
//     (NIP-59) to each recipient and to the sender itself, so all copies share
//     the rumor's id; a wrapped event counts only when the rumor's pubkey is the
//     seal's signer.
//
// Where the spec is silent this package is strict, and says so where it
// decides: a p tag's pubkey and an e tag naming a form are 64 lower-case hex; a
// question's min or max appears at most once; endsAt and expiration of "0" are
// read as absent, as nip40 does.
package nippf
