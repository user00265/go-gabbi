package gabbi

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1" // TrustedQSL signs with SHA-1 (openssl_cert.cpp:2215).
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Ident names the program that wrote a GAbbI file. It fills the TQSL_IDENT
// record at the top of the output.
type Ident struct {
	// Program is the program name, such as "MyLogger". Empty means
	// "go-gabbi".
	Program string
	// Version is the program version, such as "1.4.2". Empty means "v0".
	Version string
	// AllowDupes says whether QSOs already signed are signed again. It is
	// only reported in the ident; the Writer keeps no duplicate store.
	AllowDupes bool
}

// identMax is char temp[512] in get_ident_rec (tqslconvert.cpp:901, 914):
// the ident text holds at most 511 bytes.
const identMax = 511

// identRecord returns the TQSL_IDENT record for id and the configuration
// version: get_ident_rec (tqslconvert.cpp:896-920) up to AllowDupes. The
// "Source: ... Writer: ..." tail TrustedQSL adds for ADIF and Cabrillo input
// is left out, as there is no source log. Whether LoTW accepts an ident that
// does not start with "TQSL V" is an open question; this is the one place
// to change the text.
func identRecord(id Ident, cfg *Config) string {
	prog, ver := id.Program, id.Version
	if prog == "" {
		prog = "go-gabbi"
	}
	if ver == "" {
		ver = "v0"
	}
	major, minor := cfg.Version()
	text := fmt.Sprintf("%s %s Lib: V%s Config: V%d.%d AllowDupes: %t", prog, ver, ver, major, minor, id.AllowDupes)
	text = truncate(text, identMax)
	return "<TQSL_IDENT:" + strconv.Itoa(len(text)) + ">" + text + "\n"
}

// maxSigLen is the largest signature TrustedQSL can hold: unsigned char
// sig[129] (location.cpp:3826) less one, the size an RSA-1024 key gives.
const maxSigLen = maxKeyBits / 8

// Writer streams signed GAbbI records, the uncompressed content of a .tq8
// file, to an io.Writer. Wrap the destination in a gzip.Writer to produce
// the .tq8 itself, and close it after the last QSO.
//
// The first QSO written is preceded by the TQSL_IDENT record. Before each
// tCONTACT the Writer emits what TrustedQSL's converter would
// (tqslconvert.cpp:1562-1580, 1806-1816):
//
//   - a tCERT the first time a credential's certificate is used, with the
//     next CERT_UID starting at 1, followed by a tSTATION;
//   - a tSTATION, with the next STATION_UID starting at 1 and the current
//     CERT_UID, whenever the station's fields differ from the last tSTATION
//     written.
//
// Returning to a certificate already written reuses its CERT_UID and does
// not by itself write a tSTATION. Certificates are told apart by their DER
// bytes, stations by their validated tSTATION fields. The station
// comparison stands in for TrustedQSL's MY_* "newstation" logic, which
// starts a new tSTATION when the ADIF log's MY_* fields change the
// location; here the caller passes the Station for every QSO.
//
// Every record is followed by a blank line, as apps/tqsl.cpp:2365-2369
// writes each one with "%s\n".
//
// A Writer is not safe for concurrent use.
type Writer struct {
	w   io.Writer
	cfg *Config
	id  Ident
	opt NormalizeOptions

	started     bool           // the ident has been written
	certUIDs    map[string]int // CERT_UID by certificate DER
	curCert     string         // DER of the certificate in use
	certUID     int            // CERT_UID of curCert
	stationUID  int            // last STATION_UID written
	lastStation []stationField // fields of the last tSTATION written
	gen         uint64         // incremented on every commit
}

// NewWriter returns a Writer that signs QSOs with the rules of cfg,
// normalizes them with opt, and writes GAbbI records to w. A nil w or cfg
// is reported by the first WriteQSO.
func NewWriter(w io.Writer, cfg *Config, id Ident, opt NormalizeOptions) *Writer {
	return &Writer{w: w, cfg: cfg, id: id, opt: opt, certUIDs: map[string]int{}}
}

// WriteQSO signs q with credential c at station st and writes it, together
// with any ident, tCERT and tSTATION record it needs, in a single Write.
//
// c is first checked as [NewCredential] checks it, since a Credential may
// also be built as a literal. The per-QSO checks then run in this order:
//
//  1. q is normalized with [Config.NormalizeQSO].
//  2. st is validated with [Config.ValidateStation]; the error wraps
//     [ErrInvalidStation].
//  3. st.Call must equal the certificate callsign ignoring case, and st.DXCC
//     its DXCC entity (tqslconvert.cpp:571-599, 1590-1621); otherwise
//     [ErrCertMismatch].
//  4. The QSO's UTC date must fall within the certificate's QSO date range,
//     inclusive at both ends. A certificate without a QSO start or end date
//     signs nothing, as TrustedQSL skips it (tqslconvert.cpp:588-593). Both
//     give [ErrDateRange].
//  5. The sign data is built with [SignData] and signed with RSA PKCS#1
//     v1.5 over SHA-1. A signature longer than 128 bytes gives
//     [ErrUnsupportedKey].
//
// Per-QSO errors are a [*QSOError] with Index -1. A missing certificate,
// key or configuration gives an error wrapping [ErrNoCertificate],
// [ErrNoKey] or [ErrConfig].
//
// When any check fails, nothing is written and the Writer's state is
// unchanged, so the caller may skip the QSO and go on. When the underlying
// Write fails, the state is also unchanged, but the destination may hold
// part of the records and should be discarded.
func (wr *Writer) WriteQSO(c Credential, st Station, q QSO) error {
	p, err := wr.prepare(c, st, q)
	if err != nil {
		return err
	}
	return wr.commit(p)
}

// pending is one signed QSO, ready to write. prepare builds it and commit
// writes it. The exported-style fields are what the signing driver needs
// for its duplicate store between the two.
type pending struct {
	// QSO is the normalized QSO.
	QSO QSO
	// SignData is the signed text, as in the SIGNDATA field.
	SignData string
	// Cert is the certificate that signed; with QSO and SignData it gives
	// DupeKey and LegacyDupeKey.
	Cert *Certificate
	// StationDetails is StationDetails of the station.
	StationDetails string

	rec        []byte         // every record to write, ident included
	gen        uint64         // Writer.gen when prepared
	certKey    string         // certificate DER
	certUID    int            // CERT_UID in use after commit
	newCert    bool           // a tCERT is in rec
	stationUID int            // STATION_UID in use after commit
	fields     []stationField // the station's tSTATION fields
	newStation bool           // a tSTATION is in rec
}

// prepare runs every check of WriteQSO, signs q and builds the records,
// without writing anything or changing the Writer.
func (wr *Writer) prepare(c Credential, st Station, q QSO) (pending, error) {
	if wr == nil {
		return pending{}, errors.New("gabbi: nil Writer")
	}
	if wr.cfg == nil {
		return pending{}, fmt.Errorf("%w: Writer has no configuration", ErrConfig)
	}
	if wr.w == nil {
		return pending{}, errors.New("gabbi: Writer has no io.Writer")
	}
	if err := checkCredential(c.Cert, c.Signer); err != nil {
		return pending{}, err
	}
	cert := c.Cert

	n, err := wr.cfg.NormalizeQSO(q, wr.opt)
	if err != nil {
		return pending{}, err
	}
	fields, err := wr.cfg.stationFields(st)
	if err != nil {
		return pending{}, &QSOError{Index: -1, Field: "STATION", Err: err}
	}
	if err := checkCert(cert, st, n); err != nil {
		return pending{}, err
	}
	sd, err := SignData(wr.cfg, st, n)
	if err != nil {
		return pending{}, err
	}

	sigName := signatureField(wr.cfg.Sigspec())
	digest := sha1.Sum([]byte(sd))
	sig, err := c.Signer.Sign(rand.Reader, digest[:], crypto.SHA1)
	if err != nil {
		return pending{}, &QSOError{Index: -1, Field: sigName, Err: fmt.Errorf("gabbi: sign: %w", err)}
	}
	if len(sig) > maxSigLen {
		return pending{}, fmt.Errorf("%w: %d-byte signature, TrustedQSL holds at most %d",
			ErrUnsupportedKey, len(sig), maxSigLen)
	}

	p := pending{
		QSO:            n,
		SignData:       sd,
		Cert:           cert,
		StationDetails: StationDetails(wr.cfg, st),
		gen:            wr.gen,
		certKey:        string(cert.X509.Raw),
		certUID:        wr.certUID,
		stationUID:     wr.stationUID,
		fields:         fields,
	}
	var b strings.Builder
	if !wr.started {
		b.WriteString(identRecord(wr.id, wr.cfg) + "\n")
	}
	needStation := false
	if p.certKey != wr.curCert {
		// Switching certificates (tqslconvert.cpp:1562-1580).
		if uid, seen := wr.certUIDs[p.certKey]; seen {
			p.certUID = uid
		} else {
			p.newCert = true
			p.certUID = len(wr.certUIDs) + 1
			needStation = true
			b.WriteString(recCert(cert, p.certUID) + "\n")
		}
	}
	if needStation || !slices.Equal(fields, wr.lastStation) {
		// tqslconvert.cpp:1806-1816: loc_uid++ then get_station_rec.
		p.newStation = true
		p.stationUID++
		b.WriteString(recStation(fields, p.stationUID, p.certUID) + "\n")
	}
	b.WriteString(recContact(n, p.stationUID, sigName, sig, sd) + "\n")
	p.rec = []byte(b.String())
	return p, nil
}

// checkCert is find_matching_cert (tqslconvert.cpp:571-599) for a single
// certificate, plus the callsign and DXCC checks of tqslconvert.cpp:1590-1621.
// q must be normalized.
func checkCert(cert *Certificate, st Station, q QSO) error {
	if !strings.EqualFold(st.Call, cert.Callsign) {
		return &QSOError{Index: -1, Field: "CALL", Err: ErrCertMismatch,
			Detail: fmt.Sprintf("station callsign %s does not match certificate callsign %s", st.Call, cert.Callsign)}
	}
	if st.DXCC != cert.DXCC {
		return &QSOError{Index: -1, Field: "DXCC", Err: ErrCertMismatch,
			Detail: fmt.Sprintf("station DXCC entity %d does not match certificate DXCC entity %d", st.DXCC, cert.DXCC)}
	}
	dateErr := func(detail string) error {
		return &QSOError{Index: -1, Field: "QSO_DATE", Err: ErrDateRange, Detail: detail}
	}
	if cert.QSONotBefore.IsZero() {
		return dateErr("certificate has no QSO start date")
	}
	if cert.QSONotAfter.IsZero() {
		return dateErr("certificate has no QSO end date")
	}
	d := DateOf(q.Time)
	if d.Compare(cert.QSONotBefore) < 0 || d.Compare(cert.QSONotAfter) > 0 {
		return dateErr(fmt.Sprintf("QSO date %s is outside the certificate's QSO dates %s to %s",
			d, cert.QSONotBefore, cert.QSONotAfter))
	}
	return nil
}

// commit writes the records of p in one Write and, when that succeeds,
// records the UIDs and station it used. p must come from prepare with no
// commit in between.
func (wr *Writer) commit(p pending) error {
	if wr == nil {
		return errors.New("gabbi: nil Writer")
	}
	if p.rec == nil || p.gen != wr.gen {
		return errors.New("gabbi: stale or empty prepared QSO")
	}
	n, err := wr.w.Write(p.rec)
	if err == nil && n < len(p.rec) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("gabbi: write: %w", err)
	}
	wr.started = true
	if p.newCert {
		wr.certUIDs[p.certKey] = p.certUID
	}
	wr.curCert = p.certKey
	wr.certUID = p.certUID
	if p.newStation {
		wr.stationUID = p.stationUID
		wr.lastStation = p.fields
	}
	wr.gen++
	return nil
}
