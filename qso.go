package gabbi

import (
	"strings"
	"time"
)

// QSO is one contact to sign. Field values use ADIF spelling: BAND "20M",
// MODE "MFSK" with SUBMODE "FT4", FREQ in MHz as text. Empty means unset.
type QSO struct {
	// Call is the worked station's callsign.
	Call string
	// Band and BandRX are ADIF band names. A missing band is inferred from
	// the matching frequency.
	Band, BandRX string
	// Mode and Submode are the ADIF mode and submode. They are mapped to
	// one GAbbI mode through the configuration's ADIF mode map.
	Mode, Submode string
	// Freq and FreqRX are frequencies in MHz, such as "14.074".
	Freq, FreqRX string
	// PropMode is the ADIF propagation mode, such as "SAT".
	PropMode string
	// SatName is the satellite name, required when PropMode is "SAT".
	SatName string
	// Time is when the contact took place. Any time zone is accepted; it is
	// converted to UTC and truncated to the second.
	Time time.Time
}

// NormalizeOptions changes how [Config.NormalizeQSO] treats a QSO. They
// match TrustedQSL preferences, and change what gets signed.
type NormalizeOptions struct {
	// IgnoreSeconds sets the seconds of the QSO time to zero, like
	// TrustedQSL's "ignore seconds" preference.
	IgnoreSeconds bool
	// SkipCallCheck accepts any callsign, like TrustedQSL's "allow bad
	// callsigns" preference. Callsigns are still uppercased.
	SkipCallCheck bool
}

// NormalizeQSO checks q and returns it in the form TrustedQSL signs, as its
// ADIF converter does (tqslconvert.cpp):
//
//   - A field longer than TrustedQSL's ADIF limit, counted before trimming,
//     is rejected: 20 bytes for CALL, FREQ, FREQ_RX, SAT_NAME and
//     PROP_MODE, 16 for MODE and SUBMODE, 6 for BAND and BAND_RX.
//   - Text fields are trimmed of ASCII whitespace (C isspace only, so a
//     non-breaking space is kept) and CALL, BAND, BAND_RX, MODE, SUBMODE,
//     PROP_MODE and SAT_NAME are uppercased (ASCII only). SAT_NAME "AO-07"
//     becomes "AO-7".
//   - In FREQ and FREQ_RX every '.' after the first is dropped, and a
//     frequency that reads as 0 is cleared.
//   - A missing BAND or BAND_RX is inferred from FREQ or FREQ_RX.
//   - The callsign must look like an amateur callsign, unless
//     SkipCallCheck is set.
//   - MODE and SUBMODE are mapped to one GAbbI mode, which must exist. The
//     result has an empty Submode.
//   - BAND and BAND_RX must be configured bands. A FREQ outside BAND is
//     cleared, except for SUBMM; the same goes for FREQ_RX when BAND_RX is
//     set.
//   - PROP_MODE and SAT_NAME must be configured, and SAT_NAME is required
//     with, and only with, PROP_MODE "SAT".
//   - Time is converted to UTC and truncated to the second.
//
// One deliberate deviation: a field that is empty after trimming counts as
// unset. In TrustedQSL a present but whitespace-only field still counts as
// set (tqslconvert.cpp:977-987) and fails a later check instead, so the
// error message can differ.
//
// Errors are a [*QSOError] with Index -1 that wraps [ErrInvalidQSO]. Its
// Field is the GAbbI field name and its Detail is TrustedQSL's message.
// NormalizeQSO is idempotent: normalizing its result gives the same QSO.
func (c *Config) NormalizeQSO(q QSO, opt NormalizeOptions) (QSO, error) {
	// ADIF length limits apply to the raw value, before trimming
	// (adif.cpp:448-459).
	for _, f := range [...]struct {
		name, value string
	}{
		{"CALL", q.Call}, {"BAND", q.Band}, {"MODE", q.Mode}, {"SUBMODE", q.Submode},
		{"FREQ", q.Freq}, {"FREQ_RX", q.FreqRX}, {"BAND_RX", q.BandRX},
		{"SAT_NAME", q.SatName}, {"PROP_MODE", q.PropMode},
	} {
		if len(f.value) > adifMaxLen(f.name) {
			return QSO{}, qsoErr(f.name, "ADIF field "+f.name+" data length overflow")
		}
	}

	// Trim (tqslconvert.cpp:960-969) and uppercase (tqslconvert.cpp:978,
	// 986, 989, 1003, 1010, 1401-1404).
	n := QSO{
		Call:     asciiUpper(trimC(q.Call)),
		Band:     asciiUpper(trimC(q.Band)),
		BandRX:   asciiUpper(trimC(q.BandRX)),
		Mode:     asciiUpper(trimC(q.Mode)),
		Submode:  asciiUpper(trimC(q.Submode)),
		Freq:     fixFreq(trimC(q.Freq)),
		FreqRX:   fixFreq(trimC(q.FreqRX)),
		PropMode: asciiUpper(trimC(q.PropMode)),
		SatName:  asciiUpper(trimC(q.SatName)),
	}
	// TLEs call it AO-07; LoTW wants AO-7 (tqslconvert.cpp:1004-1008).
	if n.SatName == "AO-07" {
		n.SatName = "AO-7"
	}

	// Required fields (tqslconvert.cpp:1343-1371). FREQ counts as a band
	// (tqslconvert.cpp:982,992), even one that reads as 0.
	if n.Call == "" {
		return QSO{}, qsoErr("CALL", "Invalid contact - QSO does not specify a Callsign")
	}
	if n.Band == "" && trimC(q.Freq) == "" {
		return QSO{}, qsoErr("BAND", "Invalid contact - QSO does not specify a band or frequency")
	}
	if n.Mode == "" {
		return QSO{}, qsoErr("MODE", "Invalid contact - QSO does not specify a mode")
	}
	if q.Time.IsZero() {
		return QSO{}, qsoErr("QSO_DATE", "Invalid contact - QSO does not specify a date")
	}
	// tqsl_isDateValid: year 1-9999 (tqsllib.cpp:777-797). Checked before
	// truncating, so a time just before year 1 cannot round into it.
	if y := q.Time.UTC().Year(); y < 1 || y > 9999 {
		return QSO{}, qsoErr("QSO_DATE", "Invalid date format")
	}
	n.Time = q.Time.UTC().Truncate(time.Second)
	if opt.IgnoreSeconds {
		// tqslconvert.cpp:1022-1023.
		n.Time = n.Time.Truncate(time.Minute)
	}

	// Infer missing bands (tqslconvert.cpp:1233-1236).
	if n.Band == "" {
		n.Band = c.inferBand(n.Freq)
	}
	if n.BandRX == "" {
		n.BandRX = c.inferBand(n.FreqRX)
	}

	// Callsign (tqslconvert.cpp:1391-1400).
	if !opt.SkipCallCheck && !checkCallSign(n.Call) {
		return QSO{}, qsoErr("CALL", "Invalid amateur CALL ("+n.Call+")")
	}

	// Mode (tqslconvert.cpp:1408-1437).
	if m := c.mapMode(n.Mode, n.Submode); m != "" {
		n.Mode = m
	}
	n.Submode = ""
	if !c.hasMode(n.Mode) {
		return QSO{}, qsoErr("MODE", "Invalid MODE ("+n.Mode+")")
	}

	// Bands (tqslconvert.cpp:1438-1451).
	if _, ok := c.band(n.Band); !ok {
		return QSO{}, qsoErr("BAND", "Invalid BAND ("+n.Band+")")
	}
	if n.BandRX != "" {
		if _, ok := c.band(n.BandRX); !ok {
			return QSO{}, qsoErr("BAND_RX", "Invalid RX BAND ("+n.BandRX+")")
		}
	}

	// A frequency outside its band is dropped (tqslconvert.cpp:1452-1460).
	if n.Freq != "" && n.Band != "SUBMM" && n.Band != c.inferBand(n.Freq) {
		n.Freq = ""
	}
	if n.FreqRX != "" && n.BandRX != "" && n.BandRX != "SUBMM" && n.BandRX != c.inferBand(n.FreqRX) {
		n.FreqRX = ""
	}

	// Propagation mode and satellite (tqslconvert.cpp:1461-1490).
	if n.PropMode != "" && !c.hasPropMode(n.PropMode) {
		return QSO{}, qsoErr("PROP_MODE", "Invalid PROP_MODE ("+n.PropMode+")")
	}
	if n.SatName != "" && !c.hasSatellite(n.SatName) {
		return QSO{}, qsoErr("SAT_NAME", "Invalid SAT_NAME ("+n.SatName+")")
	}
	if n.PropMode == "SAT" && n.SatName == "" {
		return QSO{}, qsoErr("PROP_MODE", "PROP_MODE = 'SAT' but no SAT_NAME")
	}
	if n.PropMode != "SAT" && n.SatName != "" {
		return QSO{}, qsoErr("SAT_NAME", "SAT_NAME set but PROP_MODE is not 'SAT'")
	}
	return n, nil
}

// adifMaxLen is the maximum data length, in bytes, TrustedQSL's ADIF reader
// accepts for a QSO field: adif_qso_record_fields (tqslconvert.cpp:268-285)
// with the limits from tqsllib.h:48-60.
func adifMaxLen(field string) int {
	switch field {
	case "CALL":
		return 20 // TQSL_CALLSIGN_MAX
	case "BAND", "BAND_RX":
		return 6 // TQSL_BAND_MAX
	case "MODE", "SUBMODE":
		return 16 // TQSL_MODE_MAX
	case "FREQ", "FREQ_RX":
		return 20 // TQSL_FREQ_MAX
	case "SAT_NAME":
		return 20 // TQSL_SATNAME_MAX
	case "PROP_MODE":
		return 20 // TQSL_PROPMODE_MAX
	}
	return 0
}

func qsoErr(field, detail string) error {
	return &QSOError{Index: -1, Field: field, Err: ErrInvalidQSO, Detail: detail}
}

// trimC trims C-locale isspace characters, " \t\n\v\f\r", and nothing else.
func trimC(s string) string {
	return strings.Trim(s, " \t\n\v\f\r")
}

// fixFreq is fix_freq (tqslconvert.cpp:233-250), which drops every '.' after
// the first, followed by the check that clears a frequency whose atof is 0
// (tqslconvert.cpp:994-995).
func fixFreq(s string) string {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i+1] + strings.ReplaceAll(s[i+1:], ".", "")
	}
	if atof(s) == 0 {
		return ""
	}
	return s
}

// checkCallSign is checkCallSign and hasValidCallSignChars
// (tqslconvert.cpp:2234-2281). The C7 and 4Y checks are compiled out there.
func checkCallSign(call string) bool {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"
	for i := 0; i < len(call); i++ {
		if !strings.ContainsRune(letters+digits+"/", rune(call[i])) {
			return false
		}
	}
	if !strings.ContainsAny(call, letters) || !strings.ContainsAny(call, digits) {
		return false
	}
	switch call[0] {
	case '0', 'Q':
		return false
	case '1':
		if len(call) < 2 || (call[1] != 'A' && call[1] != 'M' && call[1] != 'S') {
			return false
		}
	}
	if len(call) < 3 {
		return false
	}
	for _, seg := range strings.Split(call, "/") {
		if seg == "" {
			return false
		}
	}
	return true
}
