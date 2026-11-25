package gabbi

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Line numbers in comments refer to TrustedQSL's src/tqslconvert.cpp at HEAD
// 9b30153, and to testdata/config-11.35.xml, which is TrustedQSL's
// src/config.xml.

// baseQSO is a valid 20M CW contact.
func baseQSO() QSO {
	return QSO{
		Call: "W1AW",
		Band: "20M", // config.xml:165
		Mode: "CW",  // config.xml:13,7621
		Time: time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC),
	}
}

func TestNormalizeQSORejectsNUL(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	for _, tc := range []struct {
		name string
		set  func(*QSO)
	}{
		{"CALL", func(q *QSO) { q.Call = "W1AW\x00X" }},
		{"FREQ", func(q *QSO) { q.Freq = "14.0\x00" }},
		{"SAT_NAME", func(q *QSO) { q.SatName = "AO-7\x00" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := baseQSO()
			tc.set(&q)
			_, err := cfg.NormalizeQSO(q, NormalizeOptions{SkipCallCheck: true})
			wantQSOError(t, err, tc.name, "")
		})
	}
}

// wantQSOError checks that err is a *QSOError for field with Index -1,
// wrapping ErrInvalidQSO, and, when detail is not empty, with that Detail.
func wantQSOError(t *testing.T, err error, field, detail string) {
	t.Helper()
	var qe *QSOError
	if !errors.As(err, &qe) {
		t.Fatalf("err = %v, want *QSOError", err)
	}
	if !errors.Is(err, ErrInvalidQSO) {
		t.Errorf("err = %v, does not wrap ErrInvalidQSO", err)
	}
	if qe.Index != -1 {
		t.Errorf("Index = %d, want -1", qe.Index)
	}
	if qe.Field != field {
		t.Errorf("Field = %q, want %q (err %v)", qe.Field, field, err)
	}
	if detail != "" && qe.Detail != detail {
		t.Errorf("Detail = %q, want %q", qe.Detail, detail)
	}
}

func TestNormalizeQSOCallChars(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// The call is uppercased (tqslconvert.cpp:978,1391), then checked by
	// checkCallSign (tqslconvert.cpp:2234-2281).
	for _, tc := range []struct {
		in, want string
	}{
		{"w1aw", "W1AW"},
		{"W1AW/P", "W1AW/P"},
		{"1A0KM", "1A0KM"}, // 1A is allowed (tqslconvert.cpp:2253)
	} {
		t.Run(tc.in, func(t *testing.T) {
			q := baseQSO()
			q.Call = tc.in
			got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			if err != nil {
				t.Fatalf("NormalizeQSO: %v", err)
			}
			if got.Call != tc.want {
				t.Errorf("Call = %q, want %q", got.Call, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		in, why string
	}{
		{"1B1AA", "1x other than 1A/1M/1S (tqslconvert.cpp:2253)"},
		{"QA1AA", "starts with Q (tqslconvert.cpp:2248)"},
		{"0A1AA", "starts with 0 (tqslconvert.cpp:2248)"},
		{"W1AW/", "trailing / (tqslconvert.cpp:2275-2276)"},
		{"/W1AW", "leading / (tqslconvert.cpp:2275-2276)"},
		{"W1//AW", "empty segment (tqslconvert.cpp:2275-2276)"},
		{"AB", "no digit (tqslconvert.cpp:2242-2243)"},
		{"WAW", "no digit (tqslconvert.cpp:2242-2243)"},
		{"W1", "shorter than 3 (tqslconvert.cpp:2265-2266)"},
		{"W1AW#", "bad character (tqslconvert.cpp:2236-2237)"},
		{"WÄ1AW", "non-ASCII (tqslconvert.cpp:2236-2237)"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			q := baseQSO()
			q.Call = tc.in
			_, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			// Message: tqslconvert.cpp:1395.
			wantQSOError(t, err, "CALL", "Invalid amateur CALL ("+asciiUpper(tc.in)+")")
		})
	}
	t.Run("skip", func(t *testing.T) {
		// The BadCalls pref skips the check (tqslconvert.cpp:1392).
		q := baseQSO()
		q.Call = "w1aw/"
		got, err := cfg.NormalizeQSO(q, NormalizeOptions{SkipCallCheck: true})
		if err != nil {
			t.Fatalf("NormalizeQSO: %v", err)
		}
		if got.Call != "W1AW/" {
			t.Errorf("Call = %q, want W1AW/", got.Call)
		}
	})
}

func TestNormalizeQSOMissing(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	for _, tc := range []struct {
		name   string
		edit   func(*QSO)
		field  string
		detail string
	}{
		// tqslconvert.cpp:1343-1365.
		{"call", func(q *QSO) { q.Call = "" }, "CALL", "Invalid contact - QSO does not specify a Callsign"},
		// Deliberate deviation: TQSL counts a present but whitespace-only
		// CALL as set (tqslconvert.cpp:977-980) and rejects it later in
		// checkCallSign; NormalizeQSO treats it as unset.
		{"blank call", func(q *QSO) { q.Call = " " }, "CALL", "Invalid contact - QSO does not specify a Callsign"},
		{"band", func(q *QSO) { q.Band = "" }, "BAND", "Invalid contact - QSO does not specify a band or frequency"},
		{"mode", func(q *QSO) { q.Mode = ""; q.Submode = "FT4" }, "MODE", "Invalid contact - QSO does not specify a mode"},
		{"date", func(q *QSO) { q.Time = time.Time{} }, "QSO_DATE", "Invalid contact - QSO does not specify a date"},
		// tqsl_isDateValid allows years 1-9999 (tqsllib.cpp:777-797);
		// tqsl_initDate fails with "Invalid date format" (tqsllib.cpp:105).
		{"year", func(q *QSO) { q.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, "QSO_DATE", "Invalid date format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := baseQSO()
			tc.edit(&q)
			_, err := cfg.NormalizeQSO(q, NormalizeOptions{SkipCallCheck: true})
			wantQSOError(t, err, tc.field, tc.detail)
		})
	}
}

func TestNormalizeQSOLength(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// Limits: tqsllib.h:48-60 via adif_qso_record_fields
	// (tqslconvert.cpp:274-284). The ADIF reader compares the declared
	// length, before trimming, and fails with "ADIF field %s data length
	// overflow" (adif.cpp:227-228,448-459).
	for _, tc := range []struct {
		field string
		max   int
		set   func(*QSO, string)
		// fill builds a value of length n that is valid at the limit.
		fill func(n int) string
	}{
		{"CALL", 20, func(q *QSO, v string) { q.Call = v }, func(n int) string { return "W1" + strings.Repeat("A", n-2) }},
		{"BAND", 6, func(q *QSO, v string) { q.Band = v }, func(n int) string { return strings.Repeat(" ", n-3) + "20M" }},
		{"MODE", 16, func(q *QSO, v string) { q.Mode = v }, func(n int) string { return strings.Repeat(" ", n-2) + "CW" }},
		{"SUBMODE", 16, func(q *QSO, v string) { q.Submode = v }, func(n int) string { return strings.Repeat(" ", n-3) + "PCW" }},
		{"FREQ", 20, func(q *QSO, v string) { q.Freq = v }, func(n int) string { return "14.0" + strings.Repeat("0", n-4) }},
		{"FREQ_RX", 20, func(q *QSO, v string) { q.FreqRX = v }, func(n int) string { return "14.0" + strings.Repeat("0", n-4) }},
		{"BAND_RX", 6, func(q *QSO, v string) { q.BandRX = v }, func(n int) string { return strings.Repeat(" ", n-3) + "40M" }},
		{"SAT_NAME", 20, func(q *QSO, v string) { q.PropMode = "SAT"; q.SatName = v }, func(n int) string { return strings.Repeat(" ", n-4) + "AO-7" }},
		{"PROP_MODE", 20, func(q *QSO, v string) { q.PropMode = v }, func(n int) string { return strings.Repeat(" ", n-3) + "EME" }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			q := baseQSO()
			tc.set(&q, tc.fill(tc.max))
			if _, err := cfg.NormalizeQSO(q, NormalizeOptions{}); err != nil {
				t.Fatalf("at limit %d: %v", tc.max, err)
			}
			q = baseQSO()
			tc.set(&q, tc.fill(tc.max+1))
			_, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			wantQSOError(t, err, tc.field, "ADIF field "+tc.field+" data length overflow")
		})
	}
	t.Run("padding", func(t *testing.T) {
		// "W1AW" padded to 21 bytes trims to a valid call, but TQSL
		// rejects the declared length first (adif.cpp:448-459).
		q := baseQSO()
		q.Call = "W1AW" + strings.Repeat(" ", 17)
		_, err := cfg.NormalizeQSO(q, NormalizeOptions{})
		wantQSOError(t, err, "CALL", "ADIF field CALL data length overflow")
	})
}

func TestNormalizeQSOBand(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	for _, tc := range []struct {
		name                string
		band, freq          string
		wantBand, wantFreq  string
		bandRX, freqRX      string
		wantBandRX, wantFRX string
		errField, errDetail string
	}{
		{
			// Inferred from FREQ (tqslconvert.cpp:1233-1234); 20M is
			// 14000-14350 kHz (config.xml:165).
			name: "infer", freq: "14.074", wantBand: "20M", wantFreq: "14.074",
		},
		{
			// Uppercased (tqslconvert.cpp:1401).
			name: "lower", band: "20m", wantBand: "20M",
		},
		{
			// 7.074 is 40M (config.xml:173), so FREQ is dropped
			// (tqslconvert.cpp:1452-1456).
			name: "outside", band: "20M", freq: "7.074", wantBand: "20M", wantFreq: "",
		},
		{
			// SUBMM (config.xml:184) keeps any FREQ
			// (tqslconvert.cpp:1452).
			name: "submm", band: "SUBMM", freq: "7.074", wantBand: "SUBMM", wantFreq: "7.074",
		},
		{
			// Not in <bands> (tqslconvert.cpp:1438-1443).
			name: "unknown", band: "99M", errField: "BAND", errDetail: "Invalid BAND (99M)",
		},
		{
			// A FREQ that infers no band leaves BAND empty, which is not
			// in <bands> (tqslconvert.cpp:1233-1234,1438-1443).
			name: "no band for freq", freq: "1", errField: "BAND", errDetail: "Invalid BAND ()",
		},
		{
			// RX band inferred (tqslconvert.cpp:1235-1236), RX freq kept.
			name: "rx infer", band: "20M", freqRX: "7.1",
			wantBand: "20M", wantBandRX: "40M", wantFRX: "7.1",
		},
		{
			// RX freq outside RX band dropped (tqslconvert.cpp:1457-1460).
			name: "rx outside", band: "20M", bandRX: "40m", freqRX: "14.1",
			wantBand: "20M", wantBandRX: "40M", wantFRX: "",
		},
		{
			// Without BAND_RX the RX freq is kept (tqslconvert.cpp:1457).
			name: "rx no band", band: "20M", freqRX: "1",
			wantBand: "20M", wantBandRX: "", wantFRX: "1",
		},
		{
			// tqslconvert.cpp:1445-1450.
			name: "rx unknown", band: "20M", bandRX: "99M",
			errField: "BAND_RX", errDetail: "Invalid RX BAND (99M)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := baseQSO()
			q.Band, q.Freq, q.BandRX, q.FreqRX = tc.band, tc.freq, tc.bandRX, tc.freqRX
			got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			if tc.errField != "" {
				wantQSOError(t, err, tc.errField, tc.errDetail)
				return
			}
			if err != nil {
				t.Fatalf("NormalizeQSO: %v", err)
			}
			if got.Band != tc.wantBand || got.Freq != tc.wantFreq {
				t.Errorf("Band, Freq = %q, %q, want %q, %q", got.Band, got.Freq, tc.wantBand, tc.wantFreq)
			}
			if got.BandRX != tc.wantBandRX || got.FreqRX != tc.wantFRX {
				t.Errorf("BandRX, FreqRX = %q, %q, want %q, %q", got.BandRX, got.FreqRX, tc.wantBandRX, tc.wantFRX)
			}
		})
	}
}

func TestNormalizeQSOFreqFix(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// fix_freq drops every '.' after the first (tqslconvert.cpp:233-250);
	// a FREQ whose atof is 0 is cleared (tqslconvert.cpp:991-999).
	for _, tc := range []struct{ in, want string }{
		{"14.074.5", "14.0745"},
		{"0", ""},
		{"0.0", ""},
		{" 14.074 ", "14.074"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			q := baseQSO()
			q.Band = "" // inferred from the fixed FREQ
			q.Freq = tc.in
			q.FreqRX = tc.in
			got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			if tc.want == "" {
				// No band can be inferred from an empty FREQ.
				wantQSOError(t, err, "BAND", "Invalid BAND ()")
				q.Band = "20M"
				got, err = cfg.NormalizeQSO(q, NormalizeOptions{})
			}
			if err != nil {
				t.Fatalf("NormalizeQSO: %v", err)
			}
			if got.Freq != tc.want {
				t.Errorf("Freq = %q, want %q", got.Freq, tc.want)
			}
			if got.FreqRX != tc.want {
				t.Errorf("FreqRX = %q, want %q", got.FreqRX, tc.want)
			}
		})
	}
}

// TestNormalizeQSOFreqGrammar: after fix_freq, FREQ and FREQ_RX must be an
// ADIF Number (ADIF 3.1.6, Data Types, Number: "a sequence of one or more
// Digits representing a decimal number, optionally preceded by a minus sign
// (ASCII 45) and optionally including a single decimal point (ASCII 46)").
// This is stricter than tqsl's atof (Ruling AR).
func TestNormalizeQSOFreqGrammar(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// Each value goes in FREQ under BAND 20M, where a FREQ outside 20M is
	// cleared (tqslconvert.cpp:1452-1456), and in FREQ_RX with no BAND_RX,
	// where BAND_RX is inferred and the value kept unless it reads as 0
	// (tqslconvert.cpp:994-995, 1235-1236, 1457-1460).
	for _, tc := range []struct {
		in               string
		bad              bool
		wantFreq, wantRX string
	}{
		{in: "14.074", wantFreq: "14.074", wantRX: "14.074"},
		{in: "14.", wantFreq: "14.", wantRX: "14."},
		{in: ".5", wantFreq: "", wantRX: ".5"},
		{in: "5.", wantFreq: "", wantRX: "5."},
		{in: "14.074.5", wantFreq: "14.0745", wantRX: "14.0745"},
		{in: "-14.074", wantFreq: "", wantRX: "-14.074"},
		{in: "0", wantFreq: "", wantRX: ""},
		{in: "-0.0", wantFreq: "", wantRX: ""},
		{in: "", wantFreq: "", wantRX: ""},
		{in: ".", bad: true},
		{in: "-", bad: true},
		{in: "1e3", bad: true},
		{in: "0x1A", bad: true},
		{in: "inf", bad: true},
		{in: "14,074", bad: true},
		{in: "+14.074", bad: true},
		{in: "14.074abc", bad: true},
		{in: "abc", bad: true},
		{in: "14 074", bad: true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			q := baseQSO()
			q.Band = "20M"
			q.Freq = tc.in
			got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			if tc.bad {
				wantQSOError(t, err, "FREQ", "Invalid FREQ ("+tc.in+"): not an ADIF Number")
			} else if err != nil {
				t.Fatalf("FREQ: %v", err)
			} else if got.Freq != tc.wantFreq {
				t.Errorf("Freq = %q, want %q", got.Freq, tc.wantFreq)
			}

			q.Freq, q.FreqRX = "", tc.in
			got, err = cfg.NormalizeQSO(q, NormalizeOptions{})
			if tc.bad {
				wantQSOError(t, err, "FREQ_RX", "Invalid FREQ_RX ("+tc.in+"): not an ADIF Number")
			} else if err != nil {
				t.Fatalf("FREQ_RX: %v", err)
			} else if got.FreqRX != tc.wantRX {
				t.Errorf("FreqRX = %q, want %q", got.FreqRX, tc.wantRX)
			}
		})
	}
}

func TestNormalizeQSOMode(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// The lookup tries MODE%SUBMODE, SUBMODE, then MODE
	// (tqslconvert.cpp:1409-1429); the result must be a <mode>
	// (tqslconvert.cpp:1431-1437).
	for _, tc := range []struct {
		mode, sub, want string
	}{
		{"MFSK", "FT4", "FT4"}, // config.xml:67,7631
		{"mfsk", "ft4", "FT4"}, // uppercased (tqslconvert.cpp:1403-1404)
		{"SSB", "USB", "SSB"},  // config.xml:139,7667
		{"CW", "", "CW"},       // config.xml:13,7621
	} {
		t.Run(tc.mode+"/"+tc.sub, func(t *testing.T) {
			q := baseQSO()
			q.Mode, q.Submode = tc.mode, tc.sub
			got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			if err != nil {
				t.Fatalf("NormalizeQSO: %v", err)
			}
			if got.Mode != tc.want || got.Submode != "" {
				t.Errorf("Mode, Submode = %q, %q, want %q, \"\"", got.Mode, got.Submode, tc.want)
			}
		})
	}
	t.Run("FOO", func(t *testing.T) {
		q := baseQSO()
		q.Mode = "foo"
		_, err := cfg.NormalizeQSO(q, NormalizeOptions{})
		wantQSOError(t, err, "MODE", "Invalid MODE (FOO)")
	})
}

func TestNormalizeQSOSat(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	t.Run("ao-07", func(t *testing.T) {
		q := baseQSO()
		// Uppercased, and AO-07 becomes AO-7 (tqslconvert.cpp:1002-1011);
		// SAT is config.xml:7690, AO-7 is config.xml:7715.
		q.PropMode, q.SatName = "sat", "ao-07"
		got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
		if err != nil {
			t.Fatalf("NormalizeQSO: %v", err)
		}
		if got.PropMode != "SAT" || got.SatName != "AO-7" {
			t.Errorf("PropMode, SatName = %q, %q, want SAT, AO-7", got.PropMode, got.SatName)
		}
	})
	for _, tc := range []struct {
		name, prop, sat, field, detail string
	}{
		// tqslconvert.cpp:1477-1483.
		{"no name", "SAT", "", "PROP_MODE", "PROP_MODE = 'SAT' but no SAT_NAME"},
		// tqslconvert.cpp:1484-1490.
		{"no sat", "", "AO-7", "SAT_NAME", "SAT_NAME set but PROP_MODE is not 'SAT'"},
		// Arsene is mixed case in config.xml:7722, and the check after
		// uppercasing is case-sensitive (tqslconvert.cpp:1469-1476).
		{"arsene", "SAT", "Arsene", "SAT_NAME", "Invalid SAT_NAME (ARSENE)"},
		// tqslconvert.cpp:1461-1468.
		{"bad prop", "XYZ", "", "PROP_MODE", "Invalid PROP_MODE (XYZ)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := baseQSO()
			q.PropMode, q.SatName = tc.prop, tc.sat
			_, err := cfg.NormalizeQSO(q, NormalizeOptions{})
			wantQSOError(t, err, tc.field, tc.detail)
		})
	}
}

func TestNormalizeQSOTimeUTC(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	chicago, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	q := baseQSO()
	// 2024-05-05 21:08:09.987654321 CDT is 2024-05-06 02:08:09 UTC.
	q.Time = time.Date(2024, 5, 5, 21, 8, 9, 987654321, chicago)
	got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
	if err != nil {
		t.Fatalf("NormalizeQSO: %v", err)
	}
	want := time.Date(2024, 5, 6, 2, 8, 9, 0, time.UTC)
	if !got.Time.Equal(want) || got.Time.Location() != time.UTC {
		t.Errorf("Time = %v, want %v", got.Time, want)
	}
	// IgnoreSeconds zeroes the seconds (tqslconvert.cpp:1022-1023).
	got, err = cfg.NormalizeQSO(q, NormalizeOptions{IgnoreSeconds: true})
	if err != nil {
		t.Fatalf("NormalizeQSO: %v", err)
	}
	want = time.Date(2024, 5, 6, 2, 8, 0, 0, time.UTC)
	if !got.Time.Equal(want) || got.Time.Location() != time.UTC {
		t.Errorf("IgnoreSeconds: Time = %v, want %v", got.Time, want)
	}
}

func TestNormalizeQSOTrim(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// Values are trimmed with isspace in the C locale
	// (tqslconvert.cpp:960-969): " \t\n\v\f\r" only.
	q := QSO{
		Call:     " \tw1aw\r\n",
		Band:     "\v20m\f",
		Mode:     " cw ",
		Freq:     "\t14.025 ",
		PropMode: " sat ",
		SatName:  " ao-07\n",
		Time:     baseQSO().Time,
	}
	got, err := cfg.NormalizeQSO(q, NormalizeOptions{})
	if err != nil {
		t.Fatalf("NormalizeQSO: %v", err)
	}
	want := QSO{Call: "W1AW", Band: "20M", Mode: "CW", Freq: "14.025", PropMode: "SAT", SatName: "AO-7", Time: baseQSO().Time}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	// U+00A0 is not a C-locale space, so it stays and the call check
	// rejects it (tqslconvert.cpp:2236-2237).
	q = baseQSO()
	q.Call = "\u00a0W1AW"
	_, err = cfg.NormalizeQSO(q, NormalizeOptions{})
	wantQSOError(t, err, "CALL", "Invalid amateur CALL (\u00a0W1AW)")
	if trimC("\u00a0x\u00a0") != "\u00a0x\u00a0" {
		t.Errorf("trimC trimmed U+00A0")
	}
	if trimC(" \t\n\v\f\rx \t\n\v\f\r") != "x" {
		t.Errorf("trimC did not trim C spaces")
	}
}

func TestNormalizeQSODoesNotModifyInput(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	q := baseQSO()
	q.Call, q.Submode = "w1aw", "x"
	orig := q
	if _, err := cfg.NormalizeQSO(q, NormalizeOptions{}); err != nil {
		t.Fatalf("NormalizeQSO: %v", err)
	}
	if q != orig {
		t.Errorf("input changed: %+v", q)
	}
}

func FuzzNormalizeQSO(f *testing.F) {
	cfg := loadTestConfig(f, "config-11.35.xml")
	f.Add("w1aw", "", "", "MFSK", "FT4", "14.074", "", "", "", int64(1714979289), false, false)
	f.Add("W1AW/P", "20m", "40M", "SSB", "USB", "14.2.5", "7.1", "sat", "ao-07", int64(0), true, false)
	f.Add("1A0KM", "SUBMM", "", "CW", "", "7.074", "", "", "", int64(-1), false, true)
	f.Add(" q ", "", "", "", "", "0", "0.0", "XYZ", "Arsene", int64(253402300800), true, true)
	f.Fuzz(func(t *testing.T, call, band, bandRX, mode, sub, freq, freqRX, prop, sat string, unix int64, ignoreSecs, skipCall bool) {
		q := QSO{Call: call, Band: band, BandRX: bandRX, Mode: mode, Submode: sub,
			Freq: freq, FreqRX: freqRX, PropMode: prop, SatName: sat, Time: time.Unix(unix, 0)}
		opt := NormalizeOptions{IgnoreSeconds: ignoreSecs, SkipCallCheck: skipCall}
		n1, err := cfg.NormalizeQSO(q, opt)
		if err != nil {
			var qe *QSOError
			if !errors.As(err, &qe) || !errors.Is(err, ErrInvalidQSO) || qe.Index != -1 || qe.Field == "" {
				t.Fatalf("bad error %#v", err)
			}
			return
		}
		n2, err := cfg.NormalizeQSO(n1, opt)
		if err != nil {
			t.Fatalf("second pass of %+v: %v", n1, err)
		}
		if n2 != n1 {
			t.Fatalf("not idempotent:\n first %+v\nsecond %+v", n1, n2)
		}
	})
}
