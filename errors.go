package gabbi

import (
	"errors"
	"fmt"
)

// Sentinel errors. Check them with [errors.Is]. Errors returned by this
// package wrap one of these with %w, often inside a [*QSOError].
var (
	// ErrPassword means a PKCS#12 file could not be decrypted with the
	// supplied password, usually because a password was set on export.
	ErrPassword = errors.New("gabbi: incorrect or missing PKCS#12 password")

	// ErrNoCertificate means the input held no callsign certificate.
	ErrNoCertificate = errors.New("gabbi: no certificate found")

	// ErrNoKey means the input held no private key.
	ErrNoKey = errors.New("gabbi: no private key found")

	// ErrUnsupportedKey means the key is not an RSA key that TrustedQSL can
	// sign with (RSA, at most 1024 bits).
	ErrUnsupportedKey = errors.New("gabbi: unsupported key")

	// ErrCertMismatch means the station or key does not match the
	// certificate, for example a different callsign or DXCC entity.
	ErrCertMismatch = errors.New("gabbi: certificate does not match")

	// ErrDateRange means a QSO date falls outside the certificate's QSO date
	// range or the caller's date filter.
	ErrDateRange = errors.New("gabbi: QSO date out of range")

	// ErrInvalidDate means a date string is not a valid YYYY-MM-DD or
	// YYYYMMDD date under TrustedQSL's rules.
	ErrInvalidDate = errors.New("gabbi: invalid date")

	// ErrExpired means the certificate has expired.
	ErrExpired = errors.New("gabbi: certificate expired")

	// ErrInvalidQSO means a QSO field is missing or invalid.
	ErrInvalidQSO = errors.New("gabbi: invalid QSO")

	// ErrInvalidStation means a station field is missing or invalid.
	ErrInvalidStation = errors.New("gabbi: invalid station")

	// ErrConfig means the TrustedQSL configuration could not be parsed or
	// holds a structure this package cannot handle.
	ErrConfig = errors.New("gabbi: invalid configuration")

	// ErrConfigOutdated means the configuration is older than the minimum
	// supported version. Download a current config.tq6 from LoTW.
	ErrConfigOutdated = errors.New("gabbi: configuration outdated")

	// ErrDuplicate means the QSO was already signed and recorded in the
	// duplicate store.
	ErrDuplicate = errors.New("gabbi: duplicate QSO")

	// ErrNoQSOs means nothing was signed: the input was empty, or every QSO
	// was a duplicate or out of range.
	ErrNoQSOs = errors.New("gabbi: no QSOs signed")

	// ErrRestart means the first pass found duplicates. The output written
	// so far is unusable, the duplicate store must be rolled back, and the
	// caller must sign again with a restart.
	ErrRestart = errors.New("gabbi: restart required")
)

// QSOError reports a problem with one QSO. It wraps a sentinel such as
// [ErrInvalidQSO], [ErrCertMismatch] or [ErrDateRange], so callers can use
// [errors.Is] on it and [errors.As] to read the details.
type QSOError struct {
	// Index is the 0-based position of the QSO in the input. It is -1 when
	// the Writer is used directly.
	Index int
	// Field is the GAbbI name of the offending field, such as "BAND". Two
	// values are not GAbbI names: "QSO" for a failure of the record as a
	// whole, such as a duplicate, and "CQZ/ITUZ" for zones that do not fit
	// the zone map of the DXCC entity or its primary subdivision.
	Field string
	// Err is the underlying error, usually a sentinel.
	Err error
	// Detail is optional extra context. It never contains key material.
	Detail string
}

// Error returns the message, including the QSO index and field name.
func (e *QSOError) Error() string {
	msg := fmt.Sprintf("gabbi: QSO %d: %s: %v", e.Index, e.Field, e.Err)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *QSOError) Unwrap() error {
	return e.Err
}
