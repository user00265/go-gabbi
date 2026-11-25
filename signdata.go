package gabbi

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// TrustedQSL buffer limits that shape the duplicate keys. Each is a C char
// array, so it holds one byte less than its size.
const (
	// detailsMax is char stnloc[128] and unsigned char qso[128]
	// (tqslconvert.cpp:1825-1826).
	detailsMax = 127
	// dupeKeyMax is char dupekey[128] (tqslconvert.cpp:1838).
	dupeKeyMax = 127
	// legacyKeyMax is char signdata[1024] (tqslconvert.cpp:1194).
	legacyKeyMax = 1023
)

// SignData returns the bytes TrustedQSL signs for q at station st, as
// make_sign_data and tqsl_getGABBItCONTACTData build them
// (location.cpp:754-886, 3762-3829):
//
//   - the station values, trimmed, for each tSTATION field of the
//     configuration's sigspec, in sigspec order;
//   - then the QSO values, trimmed, for each tCONTACT field, with QSO_DATE
//     as YYYY-MM-DD and QSO_TIME as HH:MM:SSZ, both in UTC;
//   - empty values left out;
//   - the whole string uppercased, ASCII letters only.
//
// q must already be normalized with [Config.NormalizeQSO]; SignData does not
// normalize it. A zero q.Time counts as a missing date.
//
// An invalid station gives an error wrapping [ErrInvalidStation]. A missing
// required contact field gives a [*QSOError] with Index -1 wrapping
// [ErrInvalidQSO]. A tCONTACT field TrustedQSL does not know gives an error
// wrapping [ErrConfig], as does a nil cfg.
func SignData(cfg *Config, st Station, q QSO) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("%w: nil Config", ErrConfig)
	}
	ss := cfg.Sigspec()
	values, err := stationValues(cfg, st)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, f := range ss.Station {
		// location.cpp:859-886: trim, then skip or fail when empty.
		v := trimC(values[f.Name])
		if v == "" {
			if f.Required {
				return "", stationErr(f.Name, "%s field required by %s V%s signature specification not found",
					f.Name, ss.Name, ss.Version)
			}
			continue
		}
		b.WriteString(v)
	}
	for _, f := range ss.Contact {
		v, known := contactValue(f.Name, q)
		if !known {
			// location.cpp:3803-3808.
			return "", fmt.Errorf("%w: Unknown field in signing specification: %s", ErrConfig, f.Name)
		}
		// The emptiness check is on the raw value and the trim comes after
		// (location.cpp:3810, 3821), so a blank value adds nothing.
		if v == "" {
			if f.Required {
				return "", &QSOError{Index: -1, Field: f.Name, Err: ErrInvalidQSO,
					Detail: f.Name + " field required by signature specification not found"}
			}
			continue
		}
		b.WriteString(trimC(v))
	}
	// string_toupper (location.cpp:403-406, 3829).
	return asciiUpper(b.String()), nil
}

// stationValues returns the canonical tSTATION values of st by GAbbI name.
func stationValues(cfg *Config, st Station) (map[string]string, error) {
	fs, err := cfg.stationFields(st)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(fs))
	for _, f := range fs {
		values[f.name] = f.value
	}
	return values, nil
}

// contactValue returns the value of the tCONTACT field name for q, untrimmed,
// as tqsl_getGABBItCONTACTData picks it (location.cpp:3781-3809). known is
// false for a name TrustedQSL does not handle.
func contactValue(name string, q QSO) (v string, known bool) {
	switch name {
	case "CALL":
		return q.Call, true
	case "BAND":
		return q.Band, true
	case "BAND_RX":
		return q.BandRX, true
	case "MODE":
		return q.Mode, true
	case "FREQ":
		return q.Freq, true
	case "FREQ_RX":
		return q.FreqRX, true
	case "PROP_MODE":
		return q.PropMode, true
	case "SAT_NAME":
		return q.SatName, true
	case "QSO_DATE":
		return qsoDate(q), true
	case "QSO_TIME":
		return qsoTime(q), true
	}
	return "", false
}

// qsoDate is tqsl_convertDateToText of the UTC date, or "" when q has no
// valid date (tqsl_isDateValid: year 1-9999).
func qsoDate(q QSO) string {
	if q.Time.IsZero() {
		return ""
	}
	t := q.Time.UTC()
	if t.Year() < 1 || t.Year() > 9999 {
		return ""
	}
	return fmt.Sprintf("%04d-%02d-%02d", t.Year(), int(t.Month()), t.Day())
}

// qsoTime is tqsl_convertTimeToText of the UTC time.
func qsoTime(q QSO) string {
	t := q.Time.UTC()
	return fmt.Sprintf("%02d:%02d:%02dZ", t.Hour(), t.Minute(), t.Second())
}

// QSODetails returns the QSO part of the sign data without the uppercase
// step: the trimmed tCONTACT values of q, in sigspec order, concatenated
// (location.cpp:3822). TrustedQSL uses it in the duplicate key. Unknown
// sigspec fields and empty values are left out; [SignData] reports them.
// A nil cfg gives "".
func QSODetails(cfg *Config, q QSO) string {
	if cfg == nil {
		return ""
	}
	var b strings.Builder
	for _, f := range cfg.Sigspec().Contact {
		if v, _ := contactValue(f.Name, q); v != "" {
			b.WriteString(trimC(v))
		}
	}
	return b.String()
}

// StationDetails returns the station description TrustedQSL stores with each
// duplicate key: "NAME: value" for each non-empty tSTATION field of the
// sigspec, in sigspec order, joined by ", " (location.cpp:880-883). Values
// keep their case. The result is cut to 127 bytes, as TrustedQSL copies it
// into a 128-byte buffer (tqslconvert.cpp:1825-1828); the cut may fall
// inside a multi-byte character. An invalid station returns an error wrapping
// [ErrInvalidStation]; a nil cfg returns an error wrapping [ErrConfig].
func StationDetails(cfg *Config, st Station) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("%w: nil Config", ErrConfig)
	}
	values, err := stationValues(cfg, st)
	if err != nil {
		return "", err
	}
	var parts []string
	for _, f := range cfg.Sigspec().Station {
		if v := trimC(values[f.Name]); v != "" {
			parts = append(parts, f.Name+": "+v)
		}
	}
	return truncate(strings.Join(parts, ", "), detailsMax), nil
}

// DupeKey returns TrustedQSL's duplicate key for q: the certificate
// callsign followed by [QSODetails], cut to 127 bytes
// (tqslconvert.cpp:1826-1839). QSODetails is cut to 127 bytes first, as
// TrustedQSL holds it in its own 128-byte buffer. A nil c counts as an
// empty callsign. A nil cfg gives "".
func DupeKey(c *Certificate, cfg *Config, q QSO) string {
	if cfg == nil {
		return ""
	}
	call := ""
	if c != nil {
		call = c.Callsign
	}
	return truncate(call+truncate(QSODetails(cfg, q), detailsMax), dupeKeyMax)
}

// LegacyDupeKey returns the duplicate key older TrustedQSL versions used:
// the sign data followed by the certificate serial in uppercase hex
// (tqslconvert.cpp:1833-1835). The serial is formatted like OpenSSL's
// BN_bn2hex (openssl_cert.cpp:1840-1844): whole bytes with leading zero bytes
// dropped, so 0x0A0B is "0A0B", zero is "0" and a negative serial gets a "-"
// prefix. The result is cut to 1023 bytes, the size of TrustedQSL's buffer
// (tqslconvert.cpp:1194).
func LegacyDupeKey(c *Certificate, signData string) string {
	return truncate(truncate(signData, legacyKeyMax)+serialHex(c), legacyKeyMax)
}

// serialHex is BN_bn2hex of the certificate serial, or "" when c has none.
func serialHex(c *Certificate) string {
	if c == nil || c.X509 == nil || c.X509.SerialNumber == nil {
		return ""
	}
	n := c.X509.SerialNumber
	b := n.Bytes() // absolute value, big-endian, no leading zero bytes
	if len(b) == 0 {
		return "0"
	}
	s := strings.ToUpper(hex.EncodeToString(b))
	if n.Sign() < 0 {
		s = "-" + s
	}
	return s
}

// truncate cuts s to at most n bytes, as a C buffer of n+1 bytes does.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
