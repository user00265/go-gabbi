package gabbi

import (
	"bytes"
	"crypto/x509"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Line numbers in comments refer to TrustedQSL at commit 9b30153 (2.8.8):
// https://sourceforge.net/p/trustedqsl/tqsl/ci/9b301538a7b8b2766917ef23d344840686138e1f/tree/
// Config line numbers refer to testdata/config-11.35.xml (TrustedQSL's src/config.xml).

// workedQSO is the QSO of knowledge.md §2.4, already normalized.
func workedQSO() QSO {
	return QSO{
		Call: "W1AW",
		Band: "20M",
		Mode: "SSB",
		Freq: "14.250",
		Time: time.Date(2026, 11, 1, 15, 30, 0, 0, time.UTC),
	}
}

func TestSignDataWorkedExample(t *testing.T) {
	for _, name := range testConfigs {
		t.Run(name, func(t *testing.T) {
			cfg := loadTestConfig(t, name)
			got, err := SignData(cfg, usStation(), workedQSO())
			if err != nil {
				t.Fatalf("SignData: %v", err)
			}
			// Station part in sigspec tSTATION order (config.xml:7830-7847):
			// CQZ "4", GRIDSQUARE "EM10dh", ITUZ "7", US_COUNTY "Travis",
			// US_STATE "TX" (location.cpp:859-886). Contact part in tCONTACT
			// order (config.xml:7818-7829): BAND, CALL, FREQ, MODE, QSO_DATE
			// "%04d-%02d-%02d", QSO_TIME "%02d:%02d:%02dZ"
			// (location.cpp:3776-3825). Then string_toupper
			// (location.cpp:3829).
			const want = "4EM10DH7TRAVISTX20MW1AW14.250SSB2026-11-0115:30:00Z"
			if got != want {
				t.Errorf("SignData =\n %q\nwant\n %q", got, want)
			}
		})
	}
}

func TestSignDataOptionalOrder(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	q := workedQSO()
	q.BandRX = "2M"
	q.FreqRX = "145.9"
	q.PropMode = "SAT"
	q.SatName = "AO-7"
	got, err := SignData(cfg, usStation(), q)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	// tCONTACT order BAND BAND_RX CALL FREQ FREQ_RX MODE PROP_MODE QSO_DATE
	// QSO_TIME SAT_NAME (config.xml:7819-7828).
	const want = "4EM10DH7TRAVISTX" + "20M2MW1AW14.250145.9SSBSAT2026-11-0115:30:00ZAO-7"
	if got != want {
		t.Errorf("SignData =\n %q\nwant\n %q", got, want)
	}
}

func TestSignDataASCIIUpper(t *testing.T) {
	// Give Travis County a non-ASCII spelling (config.xml:6126).
	x := replaceOnce(t, readTestdata(t, "config-11.35.xml"),
		`<enum value="Travis">Travis</enum>`, `<enum value="Travisé">Travisé</enum>`)
	cfg, err := ParseConfig(bytes.NewReader(x))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	st := usStation()
	st.Fields["US_COUNTY"] = "Travisé"
	got, err := SignData(cfg, st, workedQSO())
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	// string_toupper is toupper per byte in the C locale
	// (location.cpp:403-406), which leaves bytes >= 0x80 alone.
	const want = "4EM10DH7TRAVISéTX20MW1AW14.250SSB2026-11-0115:30:00Z"
	if got != want {
		t.Errorf("SignData =\n %q\nwant\n %q", got, want)
	}
}

func TestSignDataTrimsValues(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	q := workedQSO()
	q.Freq = " 14.250\t"
	got, err := SignData(cfg, usStation(), q)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	// Contact values are trimmed before they are appended
	// (location.cpp:3820-3821).
	const want = "4EM10DH7TRAVISTX20MW1AW14.250SSB2026-11-0115:30:00Z"
	if got != want {
		t.Errorf("SignData = %q, want %q", got, want)
	}
}

func TestSignDataTimeUTC(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	q := workedQSO()
	q.Time = q.Time.In(time.FixedZone("CST", -6*3600))
	got, err := SignData(cfg, usStation(), q)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	// QSO_DATE and QSO_TIME are UTC (knowledge.md §4); the format is from
	// tqsl_convertDateToText and tqsl_convertTimeToText
	// (location.cpp:3797-3802).
	if !strings.HasSuffix(got, "2026-11-0115:30:00Z") {
		t.Errorf("SignData = %q, want the UTC date and time", got)
	}
}

func TestSignDataRequiredContactField(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	for _, tt := range []struct {
		field string
		edit  func(*QSO)
	}{
		{"BAND", func(q *QSO) { q.Band = "" }},
		{"CALL", func(q *QSO) { q.Call = "" }},
		{"MODE", func(q *QSO) { q.Mode = "" }},
		{"QSO_DATE", func(q *QSO) { q.Time = time.Time{} }},
	} {
		t.Run(tt.field, func(t *testing.T) {
			q := workedQSO()
			tt.edit(&q)
			_, err := SignData(cfg, usStation(), q)
			// location.cpp:3810-3818: a required field with an empty value
			// fails with this text.
			var qe *QSOError
			if !errors.As(err, &qe) || !errors.Is(err, ErrInvalidQSO) {
				t.Fatalf("err = %v, want *QSOError wrapping ErrInvalidQSO", err)
			}
			wantDetail := tt.field + " field required by signature specification not found"
			if qe.Index != -1 || qe.Field != tt.field || qe.Detail != wantDetail {
				t.Errorf("err = %+v, want Index -1, Field %s, Detail %q", qe, tt.field, wantDetail)
			}
		})
	}
}

func TestSignDataBlankRequiredContactField(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	q := workedQSO()
	q.Call = " \t"
	got, err := SignData(cfg, usStation(), q)
	// The required check looks at the raw value (value[0] == 0,
	// location.cpp:3810) and the trim comes after (3821), so a blank
	// required value passes and adds nothing. NormalizeQSO never produces
	// one.
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if want := "4EM10DH7TRAVISTX20M14.250SSB2026-11-0115:30:00Z"; got != want {
		t.Errorf("SignData = %q, want %q", got, want)
	}
}

func TestSignDataUnknownContactField(t *testing.T) {
	// A tCONTACT field tqsl does not know. Sigspec sorts fields by name
	// (xml.cpp:156-158), so it lands last.
	x := regexp.MustCompile(`version="2.0">\s*<tCONTACT>`).ReplaceAll(
		readTestdata(t, "config-11.35.xml"), []byte(`version="2.0"><tCONTACT><ZZZ_UNKNOWN />`))
	cfg, err := ParseConfig(bytes.NewReader(x))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	_, err = SignData(cfg, usStation(), workedQSO())
	// location.cpp:3803-3808.
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "Unknown field in signing specification: ZZZ_UNKNOWN") {
		t.Errorf("err = %v, want ErrConfig with the unknown field message", err)
	}
}

func TestSignDataRequiredStationField(t *testing.T) {
	// No tSTATION field is required in LOTW 2.0 (config.xml:7830-7847), so
	// mark one.
	x := replaceOnce(t, readTestdata(t, "config-11.35.xml"), `<AU_STATE />`, `<AU_STATE required="1" />`)
	cfg, err := ParseConfig(bytes.NewReader(x))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	_, err = SignData(cfg, usStation(), workedQSO())
	// location.cpp:862-877 names the sigspec in this message.
	if !errors.Is(err, ErrInvalidStation) ||
		!strings.Contains(err.Error(), "AU_STATE field required by LOTW V2.0 signature specification not found") {
		t.Errorf("err = %v, want ErrInvalidStation with the required field message", err)
	}
}

func TestSignDataInvalidStation(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := usStation()
	st.Call = ""
	if _, err := SignData(cfg, st, workedQSO()); !errors.Is(err, ErrInvalidStation) {
		t.Errorf("err = %v, want ErrInvalidStation", err)
	}
}

func TestQSODetailsNotUppercased(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// qso_details gets the trimmed values without string_toupper
	// (location.cpp:3822; the uppercase is only applied to rec_sign_data at
	// 3829).
	if got, want := QSODetails(cfg, workedQSO()), "20MW1AW14.250SSB2026-11-0115:30:00Z"; got != want {
		t.Errorf("QSODetails = %q, want %q", got, want)
	}
	// A normalized QSO is already uppercase, so prove the case is kept
	// with a lowercase value.
	q := workedQSO()
	q.Call = "w1aw"
	if got, want := QSODetails(cfg, q), "20Mw1aw14.250SSB2026-11-0115:30:00Z"; got != want {
		t.Errorf("QSODetails = %q, want %q", got, want)
	}
}

func TestStationDetails(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// "NAME: value" joined by ", " in tSTATION order, value not uppercased
	// (location.cpp:880-883).
	const want = "CQZ: 4, GRIDSQUARE: EM10dh, ITUZ: 7, US_COUNTY: Travis, US_STATE: TX"
	if got := StationDetails(cfg, usStation()); got != want {
		t.Errorf("StationDetails = %q, want %q", got, want)
	}
}

func TestStationDetailsTruncation(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := usStation()
	st.GridSquare = strings.Repeat("A", 200)
	got := StationDetails(cfg, st)
	// tqslconvert.cpp:1825-1828 copies loc_details into char stnloc[128].
	want := ("CQZ: 4, GRIDSQUARE: " + st.GridSquare)[:127]
	if got != want {
		t.Errorf("StationDetails = %q (%d bytes), want %q", got, len(got), want)
	}
}

func TestStationDetailsInvalidStation(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := usStation()
	st.DXCC = 0
	if got := StationDetails(cfg, st); got != "" {
		t.Errorf("StationDetails = %q, want empty", got)
	}
}

func TestDupeKey(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	c := &Certificate{Callsign: "KF0TST"}
	// snprintf("%s%s", conv->callsign, qso) (tqslconvert.cpp:1838-1839).
	if got, want := DupeKey(c, cfg, workedQSO()), "KF0TST20MW1AW14.250SSB2026-11-0115:30:00Z"; got != want {
		t.Errorf("DupeKey = %q, want %q", got, want)
	}
}

func TestDupeKeyTruncation(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	q := workedQSO()
	q.Call = strings.Repeat("W", 200)
	details := QSODetails(cfg, q)
	if len(details) < 200 {
		t.Fatalf("details are %d bytes, want at least 200", len(details))
	}
	c := &Certificate{Callsign: "KF0TST"}
	got := DupeKey(c, cfg, q)
	// qso is char[128] (tqslconvert.cpp:1826) and dupekey is char[128]
	// (tqslconvert.cpp:1838-1839): both hold at most 127 bytes.
	want := ("KF0TST" + details[:127])[:127]
	if got != want || len(got) != 127 {
		t.Errorf("DupeKey = %q (%d bytes), want %q", got, len(got), want)
	}
}

func certWithSerial(n *big.Int) *Certificate {
	return &Certificate{X509: &x509.Certificate{SerialNumber: n}}
}

func TestLegacyDupeKeySerial(t *testing.T) {
	// The serial is BN_bn2hex of the certificate serial
	// (openssl_cert.cpp:1840-1844). BN_bn2hex (OpenSSL crypto/bn/bn_conv.c,
	// and bn_print.c in 1.1.1) writes uppercase hex a byte at a time and
	// drops only leading zero bytes, so 0x0A0B is "0A0B", not "A0B". Zero
	// is "0" and a negative number gets a "-" prefix.
	for _, tt := range []struct {
		serial *big.Int
		want   string
	}{
		{big.NewInt(0x0A0B), "0A0B"},
		{big.NewInt(1117788), "110E5C"},
		{big.NewInt(0xABC), "0ABC"},
		{big.NewInt(0), "0"},
		{big.NewInt(-0x0A0B), "-0A0B"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			if got := LegacyDupeKey(certWithSerial(tt.serial), "SIGN"); got != "SIGN"+tt.want {
				t.Errorf("LegacyDupeKey = %q, want %q", got, "SIGN"+tt.want)
			}
		})
	}
}

func TestLegacyDupeKeyTruncation(t *testing.T) {
	// signdata is char[1024] (tqslconvert.cpp:1194); strncat appends at most
	// sizeof(signdata) - strlen(signdata) - 1 bytes (tqslconvert.cpp:1835).
	c := certWithSerial(big.NewInt(1117788))
	sd := strings.Repeat("A", 1020)
	if got, want := LegacyDupeKey(c, sd), sd+"110"; got != want {
		t.Errorf("LegacyDupeKey is %d bytes, want %d", len(got), len(want))
	}
	// tqsl_getGABBItCONTACTData strncpy's at most 1024 bytes
	// (location.cpp:3898-3899), so longer sign data keeps 1023 bytes.
	sd = strings.Repeat("A", 2000)
	if got := LegacyDupeKey(c, sd); got != sd[:1023] {
		t.Errorf("LegacyDupeKey is %d bytes, want 1023", len(got))
	}
}

// TestNilConfigNoPanic: every function and method that takes a *Config
// returns an error or a zero value for a nil one instead of panicking.
func TestNilConfigNoPanic(t *testing.T) {
	var cfg *Config
	cred := newTestCredential(t)
	st, q := usStation(), workedQSO()
	if _, err := SignData(cfg, st, q); !errors.Is(err, ErrConfig) {
		t.Errorf("SignData: err = %v, want ErrConfig", err)
	}
	if got := QSODetails(cfg, q); got != "" {
		t.Errorf("QSODetails = %q, want empty", got)
	}
	if got := StationDetails(cfg, st); got != "" {
		t.Errorf("StationDetails = %q, want empty", got)
	}
	if got := DupeKey(cred.Cert, cfg, q); got != "" {
		t.Errorf("DupeKey = %q, want empty", got)
	}
	if _, err := cfg.NormalizeQSO(q, NormalizeOptions{}); !errors.Is(err, ErrConfig) {
		t.Errorf("NormalizeQSO: err = %v, want ErrConfig", err)
	}
	if err := cfg.ValidateStation(st); !errors.Is(err, ErrConfig) {
		t.Errorf("ValidateStation: err = %v, want ErrConfig", err)
	}
	if major, minor := cfg.Version(); major != 0 || minor != 0 {
		t.Errorf("Version = %d, %d, want 0, 0", major, minor)
	}
	if ss := cfg.Sigspec(); ss.Name != "" || ss.Station != nil || ss.Contact != nil {
		t.Errorf("Sigspec = %+v, want zero", ss)
	}
}
