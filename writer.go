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
	// Version is the program version, such as "1.4.2". Empty means
	// "0.0.0".
	Version string
	// AllowDupes says whether QSOs already signed are signed again. It is
	// only reported in the ident; the Writer keeps no duplicate store.
	AllowDupes bool
}

// identRecordMax is static char ident[512] in get_ident_rec
// (tqslconvert.cpp:902, 916-917): the whole record holds at most 511 bytes.
const identRecordMax = 511

// identRecord returns the TQSL_IDENT record for id and the configuration
// version: get_ident_rec (tqslconvert.cpp:896-920) up to AllowDupes. The
// "Source: ... Writer: ..." tail TrustedQSL adds for ADIF and Cabrillo input
// is left out, as there is no source log. Whether LoTW accepts an ident that
// does not start with "TQSL V" is an open question; this is the one place
// to change the text.
//
// The text is cut so the whole record, "<TQSL_IDENT:N>text\n", fits in
// 511 bytes, which leaves 494 bytes of text. TrustedQSL cuts the text at
// 511 bytes (char temp[512], tqslconvert.cpp:901, 914) and then the record
// at 511 (916-917), so text of 495 to 511 bytes gives it a record whose
// length prefix overruns the value and which loses its newline. That
// malformed record is deliberately not reproduced.
func identRecord(id Ident, cfg *Config) string {
	prog, ver := id.Program, id.Version
	if prog == "" {
		prog = "go-gabbi"
	}
	if ver == "" {
		ver = "0.0.0"
	}
	major, minor := cfg.Version()
	text := fmt.Sprintf("%s %s Lib: V%s Config: V%d.%d AllowDupes: %t", prog, ver, ver, major, minor, id.AllowDupes)
	// Overhead is "<TQSL_IDENT:" + digits + ">" + "\n".
	for len("<TQSL_IDENT:")+len(strconv.Itoa(len(text)))+len(">")+len(text)+len("\n") > identRecordMax {
		text = text[:len(text)-1]
	}
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
//     [ErrInvalidStation] and its Field names the station field.
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
//
// This is stricter than tqsl. TrustedQSL writes the tCERT and tSTATION
// records as soon as its converter returns them (apps/tqsl.cpp:2338-2373),
// before it signs the QSO or checks it for duplicates, so a QSO rejected at
// that point leaves its tCERT and tSTATION in the file. The Sign function
// reproduces that; WriteQSO does not.
func (wr *Writer) WriteQSO(c Credential, st Station, q QSO) error {
	p, err := wr.prepare(c, st, q)
	if err != nil {
		return err
	}
	return wr.commit(p, true)
}

// pending is one prepared QSO. prepare builds it and commit writes it. The
// exported-style fields are what the signing driver needs for its
// duplicate store between the two.
//
// The records are held in two parts, as TrustedQSL returns them one at a
// time: the preamble (the ident if it is the first record, then any tCERT
// and tSTATION) and the tCONTACT. commit always writes the preamble and
// applies its UID changes; the tCONTACT is optional.
type pending struct {
	// QSO is the normalized QSO.
	QSO QSO
	// SignData is the signed text, as in the SIGNDATA field. It is empty
	// when prepare failed after the preamble.
	SignData string
	// Cert is the certificate that signed; with QSO and SignData it gives
	// DupeKey and LegacyDupeKey.
	Cert *Certificate
	// StationDetails is StationDetails of the station.
	StationDetails string

	valid    bool   // built by prepare past the certificate checks
	gen      uint64 // Writer.gen when prepared
	preamble []byte // ident, tCERT and tSTATION records, each with "\n"
	contact  []byte // tCONTACT record with "\n"; nil if signing failed

	// State changes of the preamble.
	identWritten bool           // the preamble starts with the ident
	certKey      string         // certificate DER
	certUID      int            // CERT_UID in use after commit
	newCert      bool           // a tCERT is in the preamble
	stationUID   int            // STATION_UID in use after commit
	fields       []stationField // the station's tSTATION fields
	newStation   bool           // a tSTATION is in the preamble
}

// prepare runs every check of WriteQSO, signs q and builds the records,
// without writing anything or changing the Writer.
//
// When normalization or the station or certificate checks fail, it returns
// a zero pending and the error. When those pass but building the sign data
// or signing fails, it returns the error together with a pending whose
// preamble is valid and whose contact is nil, so the caller can still
// commit the preamble as TrustedQSL would have written it.
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
		qe := &QSOError{Index: -1, Field: "STATION", Err: err}
		var se *stationError
		if errors.As(err, &se) {
			qe.Field = se.field
		}
		return pending{}, qe
	}
	if err := checkCert(cert, st, n); err != nil {
		return pending{}, err
	}

	p := pending{
		QSO:            n,
		Cert:           cert,
		StationDetails: StationDetails(wr.cfg, st),
		valid:          true,
		gen:            wr.gen,
		certKey:        string(cert.X509.Raw),
		certUID:        wr.certUID,
		stationUID:     wr.stationUID,
		fields:         fields,
	}
	var b strings.Builder
	if !wr.started {
		// tqslconvert.cpp:1228-1230.
		p.identWritten = true
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
	p.preamble = []byte(b.String())

	// Signing happens in tqsl_getGABBItCONTACTData (tqslconvert.cpp:1820),
	// after the preamble records have been returned.
	sd, err := SignData(wr.cfg, st, n)
	if err != nil {
		return p, err
	}
	sigName := signatureField(wr.cfg.Sigspec())
	digest := sha1.Sum([]byte(sd))
	sig, err := c.Signer.Sign(rand.Reader, digest[:], crypto.SHA1)
	if err != nil {
		return p, &QSOError{Index: -1, Field: sigName, Err: fmt.Errorf("gabbi: sign: %w", err)}
	}
	if len(sig) > maxSigLen {
		return p, fmt.Errorf("%w: %d-byte signature, TrustedQSL holds at most %d",
			ErrUnsupportedKey, len(sig), maxSigLen)
	}
	p.SignData = sd
	p.contact = []byte(recContact(n, p.stationUID, sigName, sig, sd) + "\n")
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

// commit writes the preamble of p and, when withContact is set, its
// tCONTACT, in one Write, then applies the preamble's state changes. With
// withContact false only the preamble is written, and no Write is made when
// it is empty. State changes only after a successful write. p must come
// from prepare with no commit in between, and withContact needs a p
// prepared without error.
func (wr *Writer) commit(p pending, withContact bool) error {
	if wr == nil {
		return errors.New("gabbi: nil Writer")
	}
	if !p.valid || p.gen != wr.gen {
		return errors.New("gabbi: stale or empty prepared QSO")
	}
	if withContact && p.contact == nil {
		return errors.New("gabbi: prepared QSO has no tCONTACT")
	}
	rec := p.preamble
	if withContact {
		rec = append(slices.Clip(p.preamble), p.contact...)
	}
	if len(rec) > 0 {
		n, err := wr.w.Write(rec)
		if err == nil && n < len(rec) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("gabbi: write: %w", err)
		}
	}
	if p.identWritten {
		wr.started = true
	}
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
