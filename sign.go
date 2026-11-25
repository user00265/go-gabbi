package gabbi

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"iter"
	"strings"
	"time"
)

// Action chooses what Sign does with duplicates and bad QSOs. The values
// match tqsl's -a option.
type Action int

const (
	// Compliant reports bad and duplicate QSOs, skips them and signs the
	// rest, like tqsl -a compliant.
	Compliant Action = iota
	// Abort stops at the first bad or duplicate QSO, like tqsl -a abort.
	Abort
	// All signs every QSO, duplicates included, like tqsl -a all. It takes
	// two passes when the log holds duplicates; see [Sign].
	All
)

// DupeStore holds the QSOs already signed, keyed by [DupeKey], with the
// [StationDetails] they were signed with as the value. It mirrors the table
// TrustedQSL keeps in uploaded.db (tqslconvert.cpp:765-782). Keys written by
// older TrustedQSL versions have the [LegacyDupeKey] form; Sign migrates
// them as it meets them.
//
// The caller owns the transaction. Begin one before calling Sign and commit
// it only when the [Report] says Commit; otherwise roll it back. Errors
// returned by the store stop the run.
type DupeStore interface {
	// Get returns the details stored under key, and whether key exists.
	Get(ctx context.Context, key string) (details string, found bool, err error)
	// Put stores details under key, replacing any value.
	Put(ctx context.Context, key, details string) error
	// Delete removes key. Removing a missing key is not an error.
	Delete(ctx context.Context, key string) error
}

// SignOptions controls [Sign].
type SignOptions struct {
	// Action chooses how bad and duplicate QSOs are handled.
	Action Action
	// Now is the time used for the certificate expiry check. The zero
	// value means time.Now().
	Now time.Time
	// From and To limit the QSO dates signed, inclusive at both ends and by
	// UTC date. A zero Date leaves that end open. QSOs outside the range
	// are counted as OutOfRange and skipped, under every Action.
	From, To Date
	// Dupes is the duplicate store. With a nil store no duplicate check is
	// made, although the ident still says "AllowDupes: false" unless
	// Restart is set.
	Dupes DupeStore
	// Ident names the program in the TQSL_IDENT record. Its AllowDupes
	// field is ignored: Sign sets it to Restart.
	Ident Ident
	// Normalize is passed to [Config.NormalizeQSO] for every QSO.
	Normalize NormalizeOptions
	// Restart marks the second pass after [ErrRestart]. It signs every QSO
	// without touching the store, writes "AllowDupes: true" in the ident
	// and skips bad QSOs whatever the Action.
	Restart bool
}

// Outcome is what happened to one QSO.
type Outcome int

const (
	// Signed means a tCONTACT record was written.
	Signed Outcome = iota
	// Duplicate means the store already held the QSO. Nothing was written
	// for it beyond any tCERT and tSTATION it needed.
	Duplicate
	// OutOfRange means the QSO date was outside SignOptions.From and To.
	// Nothing was written for it. Its error wraps ErrDateRange, as does a
	// Failed QSO whose date no certificate covers.
	OutOfRange
	// Failed means the QSO could not be signed: it was invalid, no
	// certificate matched, or signing failed.
	Failed
)

// String returns the outcome's name.
func (o Outcome) String() string {
	switch o {
	case Signed:
		return "Signed"
	case Duplicate:
		return "Duplicate"
	case OutOfRange:
		return "OutOfRange"
	case Failed:
		return "Failed"
	}
	return fmt.Sprintf("Outcome(%d)", int(o))
}

// Result is the outcome of one QSO.
type Result struct {
	// Index is the 0-based position of the QSO in the input.
	Index int
	// Outcome is what happened to it.
	Outcome Outcome
	// Err is nil for Signed. Otherwise it is a [*QSOError] wrapping
	// [ErrDuplicate], [ErrDateRange] for OutOfRange, or the reason the QSO
	// failed. An OutOfRange QSO and a Failed one whose date no certificate
	// covers both wrap ErrDateRange; tell them apart by Outcome.
	Err error
	// OldDetails and NewDetails are set for a Duplicate found under the
	// current key: the station details stored with it and the current
	// ones. When they differ, the station changed since the QSO was first
	// signed, and TrustedQSL asks the user to check it.
	OldDetails, NewDetails string
}

// Report describes a Sign run.
type Report struct {
	// Results holds one entry per QSO read, in input order.
	Results []Result
	// Signed, Duplicates, OutOfRange and Failed count the Results by
	// Outcome.
	Signed, Duplicates, OutOfRange, Failed int
	// Commit says whether the caller should commit the duplicate store's
	// transaction. When it is false, roll the store back and discard the
	// output.
	Commit bool
}

// Sign signs qsos at station st into w as GAbbI records, with the duplicate
// handling and -a actions of tqsl's batch mode. Wrap w in a gzip.Writer to
// produce a .tq8 file. Sign builds its own [Writer]; see it for the record
// layout.
//
// Before reading any QSO, every credential in creds is checked as
// [NewCredential] checks it: a certificate, a signer, an RSA key of at most
// 1024 bits that matches the certificate. The first failure stops the run
// with nothing written and Commit false; it wraps [ErrNoCertificate],
// [ErrNoKey], [ErrUnsupportedKey] or [ErrCertMismatch]. An empty creds gives
// ErrNoCertificate.
//
// Then, for each QSO, in order:
//
//  1. ADIF field lengths and required fields are checked
//     (tqslconvert.cpp:268-285, 1343-1371).
//  2. The date filter From and To is applied (tqslconvert.cpp:1374-1388). A
//     QSO outside it is OutOfRange.
//  3. The values are checked and normalized with [Config.NormalizeQSO]
//     (tqslconvert.cpp:1390-1490).
//  4. A credential is chosen as find_matching_cert does
//     (tqslconvert.cpp:571-599, called at 1537): the first one in creds
//     whose certificate callsign equals st.Call ignoring case, whose DXCC
//     entity equals st.DXCC and whose QSO date range holds the QSO date.
//     Expired certificates (X.509 NotAfter before the UTC date of Now) and
//     certificates superseded by another one in creds are left out first,
//     as tqsl's certificate list leaves them out
//     (openssl_cert.cpp:853-906, 991-1075). No match gives
//     [ErrCertMismatch], or [ErrDateRange] when one matched all but the
//     date.
//  5. The QSO is signed. Any tCERT or tSTATION record it needs is written
//     even if signing then fails or the QSO turns out to be a duplicate,
//     as tqsl writes them before it signs.
//  6. Unless Restart is set or Dupes is nil, the store is checked as
//     tqslconvert.cpp:1820-1967 does it. A duplicate is not written.
//  7. The tCONTACT record is written.
//
// The Action then decides what happens next:
//
//   - Compliant skips bad and duplicate QSOs and goes on.
//   - Abort stops at the first bad or duplicate QSO and returns a
//     [*QSOError] for it. Because Sign streams, part of the output is
//     already in w: write to a buffer or a temporary file and discard it.
//     Roll back the store.
//   - All skips bad QSOs and reads the whole input. If it found any
//     duplicate, it returns [ErrRestart]. Discard the output, roll back the
//     store and call Sign again with the same input and Restart set. That
//     pass signs every QSO and does not touch the store. qsos must
//     therefore be replayable. Without duplicates the first pass is final.
//
// OutOfRange QSOs are skipped under every Action and never stop a run.
//
// # Errors
//
// Go has no exceptions. The error result plays that part, and
// [errors.Is] and [errors.As] are how a caller "catches" a kind of error
// and reads its details. go-gabbi returns no exit status. The table maps
// tqsl's exit statuses onto what Sign returns:
//
//	tqsl  meaning                         Sign
//	0     all signed                      nil, with zero Duplicates, Failed and OutOfRange
//	8     nothing signed                  ErrNoQSOs: empty input, or every QSO was a
//	                                      duplicate, out of range or bad
//	9     some suppressed (compliant)     nil, with nonzero Report counts
//	8/14  abort on a duplicate            *QSOError wrapping ErrDuplicate (which of 8 and
//	                                      14 tqsl uses is settled by fixture)
//	8     abort stopped on a bad QSO      *QSOError wrapping ErrInvalidQSO, ErrCertMismatch,
//	                                      ErrDateRange, ErrInvalidStation, ...
//	15    bad passphrase                  ErrPassword (from LoadPKCS12, before Sign)
//	4, 5  failure outside per-QSO checks  ErrConfig (nil or bad configuration or writer),
//	                                      or a bad credential: ErrNoCertificate, ErrNoKey,
//	                                      ErrUnsupportedKey, ErrCertMismatch (key not the
//	                                      certificate's)
//	6, 7  file I/O                        the caller's writer or store error, wrapped
//	1     cancelled                       ctx.Err(), such as context.Canceled
//
// [ErrRestart] has no tqsl status of its own: tqsl restarts by itself.
// Per-QSO problems that did not stop the run are in [Report.Results].
// Under abort, tqsl ends a run stopped by a bad QSO with numrecs 0 and
// exit 8 (apps/tqsl.cpp:2486-2490, 2539-2541, 2642-2643, 2748).
//
// A DupeStore error always stops the run, with Commit false, under every
// Action. This deliberately differs from tqsl, which under -a compliant
// and -a all counts a database error as a skipped QSO and goes on
// (apps/tqsl.cpp:2491-2524) and ignores failed deletes
// (tqslconvert.cpp:1853, 1941). A caller-supplied store that fails part
// way through leaves the duplicate state unknown, so go-gabbi does not
// carry on.
//
// The Report is returned with every error. Commit is true only when Sign
// returns nil: the run wrote at least one tCONTACT and did not abort, ask
// for a restart or stop on an error. tqsl likewise commits its duplicate
// database only when it wrote a record (apps/tqsl.cpp:2730-2779) and rolls
// it back otherwise (tqslconvert.cpp:542-545).
func Sign(ctx context.Context, w io.Writer, cfg *Config, creds []Credential, st Station, qsos iter.Seq[QSO], opt SignOptions) (Report, error) {
	var rep Report
	if cfg == nil {
		return rep, fmt.Errorf("%w: Sign has no configuration", ErrConfig)
	}
	if w == nil {
		return rep, fmt.Errorf("%w: Sign has no io.Writer", ErrConfig)
	}
	if len(creds) == 0 {
		return rep, fmt.Errorf("%w: Sign has no credentials", ErrNoCertificate)
	}
	for i, c := range creds {
		if err := checkCredential(c.Cert, c.Signer); err != nil {
			return rep, fmt.Errorf("gabbi: credential %d: %w", i, err)
		}
	}
	if qsos == nil {
		return rep, ErrNoQSOs
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	id := opt.Ident
	id.AllowDupes = opt.Restart
	s := &signer{
		ctx:    ctx,
		cfg:    cfg,
		st:     st,
		opt:    opt,
		wr:     NewWriter(w, cfg, id, opt.Normalize),
		creds:  usableCreds(creds, DateOf(now)),
		checks: opt.Dupes != nil && !opt.Restart,
	}
	contacts := 0
	i := 0
	for q := range qsos {
		if err := ctx.Err(); err != nil {
			return rep, fmt.Errorf("gabbi: QSO %d: %w", i, err)
		}
		r, fatal := s.one(i, q)
		if fatal != nil {
			return rep, fatal
		}
		rep.Results = append(rep.Results, r)
		switch r.Outcome {
		case Signed:
			rep.Signed++
			contacts++
		case Duplicate:
			rep.Duplicates++
		case OutOfRange:
			rep.OutOfRange++
		case Failed:
			rep.Failed++
		}
		// apps/tqsl.cpp:2486-2494: only Abort stops, and the restart pass
		// ignores errors (signtype TQSL_RESTART_ALLOW_DUPES).
		if opt.Action == Abort && !opt.Restart && (r.Outcome == Duplicate || r.Outcome == Failed) {
			return rep, r.Err
		}
		i++
	}
	// apps/tqsl.cpp:2616-2619: All with duplicates rolls back and retries.
	if opt.Action == All && !opt.Restart && rep.Duplicates > 0 {
		return rep, ErrRestart
	}
	// tqsl commits the store only when it wrote at least one record
	// (apps/tqsl.cpp:2730-2779); otherwise tqsl_endConverter rolls the
	// transaction back (tqslconvert.cpp:542-545). No tCONTACT is exit 8.
	rep.Commit = contacts > 0
	if contacts == 0 {
		return rep, ErrNoQSOs
	}
	return rep, nil
}

// signer holds the state of one Sign run.
type signer struct {
	ctx    context.Context
	cfg    *Config
	st     Station
	opt    SignOptions
	wr     *Writer
	creds  []usableCred
	checks bool // consult the duplicate store
}

// one handles the QSO at index i. A non-nil fatal error stops the run: a
// store or write error.
func (s *signer) one(i int, q QSO) (r Result, fatal error) {
	r = Result{Index: i}
	fail := func(err error) (Result, error) {
		r.Outcome, r.Err = Failed, atIndex(i, err)
		return r, nil
	}
	if err := precheckQSO(q); err != nil {
		return fail(err)
	}
	// tqslconvert.cpp:1374-1388.
	d := DateOf(q.Time)
	if (!s.opt.From.IsZero() && d.Compare(s.opt.From) < 0) || (!s.opt.To.IsZero() && d.Compare(s.opt.To) > 0) {
		r.Outcome = OutOfRange
		r.Err = &QSOError{Index: i, Field: "QSO_DATE", Err: ErrDateRange,
			Detail: fmt.Sprintf("QSO date %s is outside the selected dates", d)}
		return r, nil
	}
	// The value checks (tqslconvert.cpp:1390-1490) come before the
	// certificate lookup (1537). Pass the normalized QSO to the writer so
	// it need not repeat normalization.
	n, err := s.cfg.NormalizeQSO(q, s.opt.Normalize)
	if err != nil {
		return fail(err)
	}
	cred, err := s.pick(d)
	if err != nil {
		return fail(err)
	}
	p, err := s.wr.prepareQSO(cred, s.st, n, &q)
	if err != nil {
		if p.valid {
			// Signing failed after the preamble, which tqsl has written.
			if werr := s.wr.commit(p, false); werr != nil {
				return r, fmt.Errorf("gabbi: QSO %d: %w", i, werr)
			}
		}
		return fail(err)
	}
	if s.checks {
		dupe, old, err := s.dupeCheck(p)
		if err != nil {
			return r, fmt.Errorf("gabbi: QSO %d: duplicate store: %w", i, err)
		}
		if dupe {
			// The preamble stays, as tqsl has written it.
			if err := s.wr.commit(p, false); err != nil {
				return r, fmt.Errorf("gabbi: QSO %d: %w", i, err)
			}
			qe := &QSOError{Index: i, Field: "QSO", Err: ErrDuplicate}
			if old != nil {
				r.OldDetails, r.NewDetails = *old, p.StationDetails
				qe.Detail = fmt.Sprintf("signed before at station %q, now %q", *old, p.StationDetails)
			}
			r.Outcome, r.Err = Duplicate, qe
			return r, nil
		}
	}
	if err := s.wr.commit(p, true); err != nil {
		return r, fmt.Errorf("gabbi: QSO %d: %w", i, err)
	}
	r.Outcome = Signed
	return r, nil
}

// atIndex returns err as a *QSOError at index i.
func atIndex(i int, err error) error {
	// Only a QSOError at the top is re-indexed; a wrapped one is wrapped
	// again so the outer context is kept.
	if qe, ok := err.(*QSOError); ok { //nolint:errorlint // top level only, see above
		c := *qe
		c.Index = i
		return &c
	}
	return &QSOError{Index: i, Field: "QSO", Err: err}
}

// dupeCheck is tqslconvert.cpp:1824-1967 for a signed QSO. It reports
// whether p is a duplicate and, when found under the current key, the
// stored details.
func (s *signer) dupeCheck(p pending) (dupe bool, old *string, err error) {
	ctx, store := s.ctx, s.opt.Dupes
	key := DupeKey(p.Cert, s.cfg, p.QSO)
	legacy := LegacyDupeKey(p.Cert, p.SignData)

	// 1842-1868: the old-style key marks a duplicate and is migrated.
	if _, found, err := store.Get(ctx, legacy); err != nil {
		return false, nil, err
	} else if found {
		if err := store.Delete(ctx, legacy); err != nil {
			return false, nil, err
		}
		return true, nil, store.Put(ctx, key, p.StationDetails)
	}

	// 1881-1941.
	stored, found, err := store.Get(ctx, key)
	if err != nil {
		return false, nil, err
	}
	if found {
		if strings.EqualFold(stored, p.StationDetails) || stationChanged(stored, p.StationDetails) {
			return true, &stored, nil
		}
		// Fields were only added or removed: re-sign.
		if err := store.Delete(ctx, key); err != nil {
			return false, nil, err
		}
	}
	// 1955-1966.
	return false, nil, store.Put(ctx, key, p.StationDetails)
}

// stationChanged is the comparison at tqslconvert.cpp:1897-1933. Spaces are
// removed from both strings, which are split on ','. For each old entry the
// first new entry with the same "NAME:" prefix is found; the station changed
// when the two differ and the old entry has a value. An entry only in the
// new string, or only in the old one, is not a change.
func stationChanged(oldDetails, newDetails string) bool {
	olds := strings.Split(strings.ReplaceAll(oldDetails, " ", ""), ",")
	news := strings.Split(strings.ReplaceAll(newDetails, " ", ""), ",")
	for _, o := range olds {
		key := detailsKey(o)
		for _, n := range news {
			if detailsKey(n) == key {
				if o != n && key != o {
					return true
				}
				break
			}
		}
	}
	return false
}

// detailsKey is the "NAME:" prefix of a details entry, up to and including
// the first ':', or the whole entry when it has none (string::substr with
// npos+1 == 0 takes nothing, tqslconvert.cpp:1918-1919).
func detailsKey(e string) string {
	if i := strings.IndexByte(e, ':'); i >= 0 {
		return e[:i+1]
	}
	return ""
}

// usableCred is a credential that survived get_certlist's exclusions, or
// one left out only as expired, kept so a failed match can say so.
type usableCred struct {
	cred    Credential
	expired bool
}

// usableCreds returns creds without those superseded by another
// credential's certificate, and marks those expired on today, the UTC date:
// get_certlist's exclusions (openssl_cert.cpp:853-906, 991-1075,
// 3835-3851). Expired credentials never sign. Every credential must already
// have passed checkCredential, so its Cert and Cert.X509 are set.
func usableCreds(creds []Credential, today Date) []usableCred {
	var out []usableCred
	for i, c := range creds {
		if supersededBy(c.Cert, creds, i) {
			continue
		}
		out = append(out, usableCred{cred: c, expired: DateOf(c.Cert.X509.NotAfter).Compare(today) < 0})
	}
	return out
}

// supersededBy reports whether another credential in creds names c in its
// supercededCertificate extension. tqsl compares "<issuer>;<serial>"
// strings: the issuer is X509_NAME_oneline of c's issuer, and the stored
// value is tried as written and with its first "/Email" changed to
// "/emailAddress", since ARRL writes the former and OpenSSL the latter
// (openssl_cert.cpp:1042-1068). The serial is compared as a number here,
// where tqsl prints it with %ld; the two agree for serials that fit a C
// long and are written without leading zeros.
func supersededBy(c *Certificate, creds []Credential, self int) bool {
	issuer := onelineName(c.X509.RawIssuer)
	for j, o := range creds {
		if j == self || o.Cert == nil || o.Cert.Supersedes == nil || o.Cert.Supersedes.Serial == nil {
			continue
		}
		sup := o.Cert.Supersedes
		if c.X509.SerialNumber == nil || sup.Serial.Cmp(c.X509.SerialNumber) != 0 {
			continue
		}
		if sup.Issuer == issuer || strings.Replace(sup.Issuer, "/Email", "/emailAddress", 1) == issuer {
			return true
		}
	}
	return false
}

// pick is find_matching_cert (tqslconvert.cpp:571-599) over the usable
// credentials, with the errors of tqslconvert.cpp:1539-1561.
func (s *signer) pick(d Date) (Credential, error) {
	anyFound, expired := false, false
	for _, u := range s.creds {
		c := u.cred.Cert
		if !strings.EqualFold(s.st.Call, c.Callsign) || c.DXCC != s.st.DXCC {
			continue
		}
		if u.expired {
			expired = true
			continue
		}
		anyFound = true
		if c.QSONotBefore.IsZero() || c.QSONotAfter.IsZero() ||
			d.Compare(c.QSONotBefore) < 0 || d.Compare(c.QSONotAfter) > 0 {
			continue
		}
		return u.cred, nil
	}
	if anyFound {
		return Credential{}, &QSOError{Field: "QSO_DATE", Err: ErrDateRange,
			Detail: fmt.Sprintf("no certificate for %s, DXCC entity %d, covers the QSO date %s", s.st.Call, s.st.DXCC, d)}
	}
	err := ErrCertMismatch
	detail := fmt.Sprintf("no certificate for %s, DXCC entity %d", s.st.Call, s.st.DXCC)
	if expired {
		return Credential{}, &QSOError{Field: "CALL", Err: fmt.Errorf("%w: %w", err, ErrExpired), Detail: detail + " that has not expired"}
	}
	return Credential{}, &QSOError{Field: "CALL", Err: err, Detail: detail}
}

// onelineName formats a DER-encoded X.509 name as OpenSSL's
// X509_NAME_oneline does: "/SN=value" for each attribute in order, with the
// short name of the attribute type or its dotted OID, and each byte
// outside ' ' to '~' written as \xHH. String values are taken as Go decodes
// them, so a BMPString or UniversalString is shown as its UTF-8 bytes where
// OpenSSL would show the raw ones. Undecodable input gives "".
func onelineName(der []byte) string {
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdns); err != nil || len(rest) != 0 {
		return ""
	}
	var b strings.Builder
	for _, rdn := range rdns {
		for _, atv := range rdn {
			b.WriteByte('/')
			if sn := shortName(atv.Type.String()); sn != "" {
				b.WriteString(sn)
			} else {
				b.WriteString(atv.Type.String())
			}
			b.WriteByte('=')
			v := fmt.Sprint(atv.Value)
			for i := 0; i < len(v); i++ {
				if c := v[i]; c < ' ' || c > '~' {
					fmt.Fprintf(&b, `\x%02X`, c)
				} else {
					b.WriteByte(c)
				}
			}
		}
	}
	return b.String()
}

// shortName returns OpenSSL's short name (obj_dat.h) for the attribute
// types found in certificate names, plus AROcallsign, which TrustedQSL
// registers (tqsllib.cpp:64-96), or "" for any other type.
func shortName(oid string) string {
	switch oid {
	case "2.5.4.3":
		return "CN"
	case "2.5.4.4":
		return "SN"
	case "2.5.4.5":
		return "serialNumber"
	case "2.5.4.6":
		return "C"
	case "2.5.4.7":
		return "L"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.9":
		return "street"
	case "2.5.4.10":
		return "O"
	case "2.5.4.11":
		return "OU"
	case "2.5.4.12":
		return "title"
	case "2.5.4.17":
		return "postalCode"
	case "2.5.4.42":
		return "GN"
	case "2.5.4.43":
		return "initials"
	case "2.5.4.46":
		return "dnQualifier"
	case "0.9.2342.19200300.100.1.1":
		return "UID"
	case "0.9.2342.19200300.100.1.25":
		return "DC"
	case "1.2.840.113549.1.9.1":
		return "emailAddress"
	case oidCallsign:
		return "AROcallsign"
	}
	return ""
}
