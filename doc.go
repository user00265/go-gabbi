// Package gabbi signs QSO records into the GAbbI format that TrustedQSL
// writes into .tq8 files, for upload to ARRL's Logbook of the World.
//
// The package loads callsign certificates, builds certificate requests,
// normalizes typed QSO values against the TrustedQSL configuration, and
// writes signed GAbbI records. A .tq8 file is that text, gzipped. The service
// subpackage provides optional network operations.
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
// [BuildRequest] can build a renewal without submitting it. Requesting a
// renewal before the existing certificate expires immediately invalidates it;
// callers can show [RenewalWarning] before submitting the request.
package gabbi
