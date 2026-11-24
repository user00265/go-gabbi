// Package gabbi signs QSO records into the GAbbI format that TrustedQSL
// writes into .tq8 files, for upload to ARRL's Logbook of the World.
//
// The package loads a TrustedQSL .p12 callsign certificate, normalizes typed
// QSO values against the TrustedQSL configuration, and writes signed GAbbI
// records. A .tq8 file is that text, gzipped.
//
// # Boundaries
//
// This is a library only. It has no binary and no main package, and it:
//
//   - reads no files and makes no network calls; inputs are byte slices or
//     readers, outputs are writers or returned values;
//   - embeds no TrustedQSL configuration; the caller fetches, stores and
//     passes it in (see the README for the process);
//   - keeps no global state and does no logging;
//   - signs through a [crypto.Signer], so keys can live in memory, a KMS or
//     an HSM, and never puts key material in error messages;
//   - leaves the duplicate store, the station data and every stream to the
//     caller.
//
// # Errors
//
// Errors wrap sentinels such as [ErrInvalidQSO] and [ErrDateRange], so check
// them with [errors.Is]. Problems with a single QSO arrive as a [*QSOError],
// which [errors.As] recovers with the QSO index and field name.
//
// # Certificate renewal
//
// Certificate request support is not written yet. When it is, its
// documentation will warn that requesting a renewal immediately invalidates
// the existing certificate.
package gabbi
