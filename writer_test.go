package gabbi

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Line numbers in comments refer to TrustedQSL at HEAD 9b30153 (excerpts in
// .superpowers/sdd/2026-11-24-signing-path-plan/tqsl-excerpts-task6.txt):
// src/tqslconvert.cpp, src/location.cpp and apps/tqsl.cpp.

// gField is one GAbbI field read back from writer output.
type gField struct {
	name, typ, value string
}

// gRecord is one record read back from writer output. The ident is a
// record of Type "TQSL_IDENT" holding that one field.
type gRecord struct {
	Type   string
	Fields []gField
}

// get returns the value of the first field called name, and whether there
// was one.
func (r gRecord) get(name string) (string, bool) {
	for _, f := range r.Fields {
		if f.name == name {
			return f.value, true
		}
	}
	return "", false
}

// uid returns the integer value of field name, failing the test when it is
// missing or not a number.
func (r gRecord) uid(t *testing.T, name string) int {
	t.Helper()
	v, ok := r.get(name)
	if !ok {
		t.Fatalf("%s record has no %s", r.Type, name)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s %s = %q: %v", r.Type, name, v, err)
	}
	return n
}

// parseGAbbI splits writer output into records by the <NAME:len[:type]>
// grammar (adif.cpp:614-651). Values are taken by their length prefix, not
// by scanning for the next '<', so a value holding '<' or newlines reads
// back intact. Only '\n' may separate fields. A TQSL_IDENT field outside a
// record is its own record; <Rec_Type> opens a record and <eor> closes it.
// It fails the test on malformed input, printing the offending bytes.
func parseGAbbI(t *testing.T, data []byte) []gRecord {
	t.Helper()
	rs, err := parseGAbbIRecords(data)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// parseGAbbIRecords is parseGAbbI's core. Its errors may quote the input,
// so callers holding sensitive output must not print them.
func parseGAbbIRecords(data []byte) ([]gRecord, error) {
	s := string(data)
	var (
		out []gRecord
		cur *gRecord
	)
	for i := 0; ; {
		for i < len(s) && s[i] == '\n' {
			i++
		}
		if i == len(s) {
			break
		}
		if s[i] != '<' {
			return nil, fmt.Errorf("offset %d: want '<', got %q", i, s[i:min(len(s), i+20)])
		}
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			return nil, fmt.Errorf("offset %d: unterminated field header", i)
		}
		header := s[i+1 : i+end]
		i += end + 1
		parts := strings.SplitN(header, ":", 3)
		f := gField{name: parts[0]}
		if len(parts) > 1 {
			n, err := strconv.Atoi(parts[1])
			if err != nil || n < 0 || i+n > len(s) {
				return nil, fmt.Errorf("field %s: bad length %q", f.name, parts[1])
			}
			if len(parts) > 2 {
				f.typ = parts[2]
			}
			f.value = s[i : i+n]
			i += n
		}
		switch {
		case f.name == "TQSL_IDENT" && cur == nil:
			out = append(out, gRecord{Type: f.name, Fields: []gField{f}})
		case f.name == "Rec_Type":
			if cur != nil {
				return nil, fmt.Errorf("Rec_Type %s inside an open %s record", f.value, cur.Type)
			}
			cur = &gRecord{Type: f.value}
		case f.name == "eor":
			if cur == nil {
				return nil, fmt.Errorf("offset %d: <eor> outside a record", i)
			}
			out = append(out, *cur)
			cur = nil
		default:
			if cur == nil {
				return nil, fmt.Errorf("field %s outside a record", f.name)
			}
			cur.Fields = append(cur.Fields, f)
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("unterminated %s record", cur.Type)
	}
	return out, nil
}

// recordTypes returns the Type of each record.
func recordTypes(rs []gRecord) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Type
	}
	return out
}

func wantTypes(t *testing.T, rs []gRecord, want ...string) {
	t.Helper()
	got := recordTypes(rs)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("records = %v, want %v", got, want)
	}
}

// newTestCredentialWith returns a Credential for a fresh RSA-1024 test
// certificate carrying the ARRL fields f.
func newTestCredentialWith(t *testing.T, f testCertFields) Credential {
	t.Helper()
	p := newTestPKI(t)
	key := newTestKey(t)
	c, err := ParseCertificate(newTestCert(t, p.Inter, p.InterKey, key.Public(), f))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	cred, err := NewCredential(c, key)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return cred
}

// writerQSO is a valid QSO inside the default certificate's QSO date range
// (2020-05-14 to 2029-03-19).
func writerQSO(call string, day int) QSO {
	return QSO{
		Call: call,
		Band: "20M",
		Mode: "SSB",
		Freq: "14.250",
		Time: time.Date(2026, 11, day, 15, 30, 0, 0, time.UTC),
	}
}

func newTestWriter(t *testing.T, w io.Writer) *Writer {
	t.Helper()
	return NewWriter(w, loadTestConfig(t, "config-11.35.xml"), Ident{Program: "test", Version: "1.0"}, NormalizeOptions{})
}

func mustWrite(t *testing.T, wr *Writer, c Credential, st Station, q QSO) {
	t.Helper()
	if err := wr.WriteQSO(c, st, q); err != nil {
		t.Fatalf("WriteQSO: %v", err)
	}
}

func TestWriterRecordSequence(t *testing.T) {
	var buf bytes.Buffer
	wr := newTestWriter(t, &buf)
	cred := newTestCredential(t)
	mustWrite(t, wr, cred, usStation(), writerQSO("W1AW", 1))
	mustWrite(t, wr, cred, usStation(), writerQSO("K1ABC", 2))

	// tqsl_getConverterGABBI returns the ident before the first record
	// (tqslconvert.cpp:1228-1230), then tCERT with CERT_UID next_cert_uid=1
	// for the first cert (tqslconvert.cpp:122, 1571-1576), then tSTATION
	// with loc_uid incremented from 0 to 1 (tqslconvert.cpp:120, 1813-1815)
	// carrying cert_uid (tqslconvert.cpp:924), then the tCONTACT records.
	// Same cert and station: no further tCERT or tSTATION.
	rs := parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT", "tCONTACT")
	if got := rs[1].uid(t, "CERT_UID"); got != 1 {
		t.Errorf("tCERT CERT_UID = %d, want 1", got)
	}
	if got := rs[2].uid(t, "STATION_UID"); got != 1 {
		t.Errorf("tSTATION STATION_UID = %d, want 1", got)
	}
	if got := rs[2].uid(t, "CERT_UID"); got != 1 {
		t.Errorf("tSTATION CERT_UID = %d, want 1", got)
	}
	for _, r := range rs[3:] {
		if got := r.uid(t, "STATION_UID"); got != 1 {
			t.Errorf("tCONTACT STATION_UID = %d, want 1", got)
		}
	}

	// apps/tqsl.cpp:2365-2369 writes each record with "%s\n", and every
	// record already ends in "\n" (get_ident_rec, tqslconvert.cpp:916;
	// location.cpp:3689, 3757, 3897), so each is followed by a blank line.
	out := buf.String()
	if !strings.HasPrefix(out, "<TQSL_IDENT:") {
		t.Errorf("output starts %q, want the ident", out[:min(len(out), 20)])
	}
	if i := strings.Index(out, "\n"); i < 0 || !strings.HasPrefix(out[i:], "\n\n<Rec_Type:5>tCERT\n") {
		t.Errorf("ident is not followed by a blank line and tCERT")
	}
	if n := strings.Count(out, "<eor>\n\n"); n != 4 {
		t.Errorf("%d records end in <eor> and a blank line, want 4", n)
	}
	if strings.Count(out, "<eor>") != 4 || !strings.HasSuffix(out, "<eor>\n\n") {
		t.Errorf("output does not end with <eor>\\n\\n")
	}
}

func TestWriterIdent(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// get_ident_rec (tqslconvert.cpp:904-916) up to AllowDupes, with the
	// config version from tqsl_getConfigVersion (tqslconvert.cpp:900).
	for _, tt := range []struct {
		id   Ident
		want string
	}{
		{Ident{Program: "MyLog", Version: "1.2.3"}, "MyLog 1.2.3 Lib: V1.2.3 Config: V11.35 AllowDupes: false"},
		{Ident{AllowDupes: true}, "go-gabbi 0.0.0 Lib: V0.0.0 Config: V11.35 AllowDupes: true"},
	} {
		var buf bytes.Buffer
		wr := NewWriter(&buf, cfg, tt.id, NormalizeOptions{})
		mustWrite(t, wr, newTestCredential(t), usStation(), writerQSO("W1AW", 1))
		want := "<TQSL_IDENT:" + strconv.Itoa(len(tt.want)) + ">" + tt.want + "\n\n"
		if !strings.HasPrefix(buf.String(), want) {
			t.Errorf("Ident %+v: output starts\n%q\nwant\n%q", tt.id, buf.String()[:min(buf.Len(), len(want))], want)
		}
	}
}

func TestWriterIdentTruncated(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// static char ident[512] holds the whole record "<TQSL_IDENT:%d>%s\n"
	// (tqslconvert.cpp:902, 916-917), so it may be at most 511 bytes. The
	// record must also stay well formed: the length prefix matches the
	// value and the newline is kept. With a 3-digit length that leaves 494
	// bytes of text.
	const tail = " 0.0.0 Lib: V0.0.0 Config: V11.35 AllowDupes: false"
	for _, n := range []int{1, 400, 494 - len(tail), 495 - len(tail), 511 - len(tail), 600} {
		full := strings.Repeat("P", n) + tail
		got := identRecord(Ident{Program: strings.Repeat("P", n)}, cfg)
		if len(got) > 511 {
			t.Errorf("program %d bytes: record is %d bytes, want at most 511", n, len(got))
		}
		head, text, ok := strings.Cut(got, ">")
		if !ok || !strings.HasPrefix(head, "<TQSL_IDENT:") || !strings.HasSuffix(text, "\n") {
			t.Fatalf("program %d bytes: malformed record %q", n, got[:min(len(got), 40)])
		}
		text = strings.TrimSuffix(text, "\n")
		if l, err := strconv.Atoi(strings.TrimPrefix(head, "<TQSL_IDENT:")); err != nil || l != len(text) {
			t.Errorf("program %d bytes: length prefix %q, value is %d bytes", n, head, len(text))
		}
		if !strings.HasPrefix(full, text) {
			t.Errorf("program %d bytes: text is not a prefix of the full ident", n)
		}
		if len(full) <= 494 && text != full {
			t.Errorf("program %d bytes: %d-byte text was cut", n, len(full))
		}
		if len(full) > 494 && len(text) != 494 {
			t.Errorf("program %d bytes: text cut to %d bytes, want 494", n, len(text))
		}
	}
}

func TestWriterSignatureVerifies(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	var buf bytes.Buffer
	wr := NewWriter(&buf, cfg, Ident{}, NormalizeOptions{})
	cred := newTestCredential(t)
	st := usStation()
	// Lowercase and padded input: the writer must sign the normalized QSO.
	raw := QSO{Call: " w1aw ", Band: "20m", Mode: "ssb", Freq: "14.250", Time: time.Date(2026, 11, 1, 15, 30, 0, 0, time.UTC)}
	mustWrite(t, wr, cred, st, raw)

	rs := parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT")
	contact := rs[3]
	sd, ok := contact.get("SIGNDATA")
	if !ok {
		t.Fatal("tCONTACT has no SIGNDATA")
	}
	norm, err := cfg.NormalizeQSO(raw, NormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := SignData(cfg, st, norm)
	if err != nil {
		t.Fatal(err)
	}
	if sd != want {
		t.Errorf("SIGNDATA = %q, want %q", sd, want)
	}
	// The signature field is SIGN_LOTW_V2.0 of type '6' (location.cpp:822-825,
	// 3891-3893).
	var sigText string
	for _, f := range contact.Fields {
		if f.name == "SIGN_LOTW_V2.0" {
			sigText = f.value
			if f.typ != "6" {
				t.Errorf("signature type = %q, want 6", f.typ)
			}
		}
	}
	sig, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(sigText, "\n", ""))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != 128 {
		t.Errorf("signature is %d bytes, want 128", len(sig))
	}
	// EVP_SignInit with EVP_sha1 (openssl_cert.cpp:2215-2217): PKCS#1 v1.5
	// over SHA-1 of the sign data.
	digest := sha1.Sum([]byte(sd))
	pub := cred.Signer.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
	// The tCERT carries this credential's certificate (location.cpp:3667-3691).
	certText, _ := rs[1].get("CERTIFICATE")
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(certText, "\n", ""))
	if err != nil || !bytes.Equal(der, cred.Cert.X509.Raw) {
		t.Errorf("tCERT does not hold the credential's certificate (err %v)", err)
	}
	if c, _ := contact.get("CALL"); c != "W1AW" {
		t.Errorf("tCONTACT CALL = %q, want W1AW", c)
	}
}

func TestWriterStationChange(t *testing.T) {
	var buf bytes.Buffer
	wr := newTestWriter(t, &buf)
	cred := newTestCredential(t)
	other := usStation()
	other.GridSquare = "EM10di"
	mustWrite(t, wr, cred, usStation(), writerQSO("W1AW", 1))
	mustWrite(t, wr, cred, usStation(), writerQSO("W1AW", 2))
	mustWrite(t, wr, cred, other, writerQSO("W1AW", 3))

	// A changed location sets newstation, so loc_uid is incremented and a
	// tSTATION emitted with the current cert_uid (tqslconvert.cpp:1806-1810,
	// 922-928). No new cert, so no tCERT.
	rs := parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT", "tCONTACT", "tSTATION", "tCONTACT")
	if got := rs[5].uid(t, "STATION_UID"); got != 2 {
		t.Errorf("second tSTATION STATION_UID = %d, want 2", got)
	}
	if got := rs[5].uid(t, "CERT_UID"); got != 1 {
		t.Errorf("second tSTATION CERT_UID = %d, want 1", got)
	}
	if g, _ := rs[5].get("GRIDSQUARE"); g != "EM10di" {
		t.Errorf("second tSTATION GRIDSQUARE = %q", g)
	}
	if got := rs[6].uid(t, "STATION_UID"); got != 2 {
		t.Errorf("last tCONTACT STATION_UID = %d, want 2", got)
	}
}

func TestWriterSecondCert(t *testing.T) {
	var buf bytes.Buffer
	wr := newTestWriter(t, &buf)
	// Two certificates for the same call and DXCC, as after a replacement,
	// so the same station is valid for both.
	cred1 := newTestCredential(t)
	cred2 := newTestCredentialWith(t, defaultTestCertFields())
	stA := usStation()
	stB := usStation()
	stB.GridSquare = "EM10di"

	mustWrite(t, wr, cred1, stA, writerQSO("W1AW", 1)) // tCERT 1, tSTATION 1
	mustWrite(t, wr, cred1, stB, writerQSO("W1AW", 2)) // tSTATION 2
	mustWrite(t, wr, cred2, stB, writerQSO("W1AW", 3)) // tCERT 2, tSTATION 3
	mustWrite(t, wr, cred1, stB, writerQSO("W1AW", 4)) // back to cert 1

	rs := parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT",
		"tCERT", "tSTATION", "tCONTACT",
		"tSTATION", "tCONTACT",
		"tCERT", "tSTATION", "tCONTACT",
		"tCONTACT")

	// A cert not seen before gets next_cert_uid (2) and need_station_rec,
	// so loc_uid goes to 3 (tqslconvert.cpp:1571-1576, 1813-1815).
	if got := rs[6].uid(t, "CERT_UID"); got != 2 {
		t.Errorf("second tCERT CERT_UID = %d, want 2", got)
	}
	if got := rs[7].uid(t, "STATION_UID"); got != 3 {
		t.Errorf("third tSTATION STATION_UID = %d, want 3", got)
	}
	if got := rs[7].uid(t, "CERT_UID"); got != 2 {
		t.Errorf("third tSTATION CERT_UID = %d, want 2", got)
	}
	// unverified: fixture phase confirms (knowledge §3.3)
	// Going back to cert 1 takes the else branch (tqslconvert.cpp:1577-1579):
	// cert_uid is reused and need_station_rec stays false, so no tCERT or
	// tSTATION, and the tCONTACT keeps loc_uid 3.
	if got := rs[9].uid(t, "STATION_UID"); got != 3 {
		t.Errorf("last tCONTACT STATION_UID = %d, want 3", got)
	}

	// Writing a new station for cert 1 now emits a tSTATION with CERT_UID 1.
	buf.Reset()
	mustWrite(t, wr, cred1, stA, writerQSO("W1AW", 5))
	rs = parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "tSTATION", "tCONTACT")
	if got := rs[0].uid(t, "STATION_UID"); got != 4 {
		t.Errorf("tSTATION STATION_UID = %d, want 4", got)
	}
	if got := rs[0].uid(t, "CERT_UID"); got != 1 {
		t.Errorf("tSTATION CERT_UID = %d, want 1", got)
	}
}

func TestWriterCertMismatch(t *testing.T) {
	cred := newTestCredential(t) // KF0TST, DXCC 291
	callSt := usStation()
	callSt.Call = "KF0XXX"
	dxccSt := Station{Call: "KF0TST", DXCC: 1} // CANADA, config.xml:296
	for _, tt := range []struct {
		name  string
		st    Station
		field string
	}{
		// strcmp of MY_CALL against the cert call (tqslconvert.cpp:1590-1600)
		// and find_matching_cert's strcasecmp (tqslconvert.cpp:581).
		{"call", callSt, "CALL"},
		// MY_DXCC against the cert DXCC (tqslconvert.cpp:585, 1602-1621).
		{"dxcc", dxccSt, "DXCC"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			wr := newTestWriter(t, &buf)
			err := wr.WriteQSO(cred, tt.st, writerQSO("W1AW", 1))
			if !errors.Is(err, ErrCertMismatch) {
				t.Fatalf("err = %v, want ErrCertMismatch", err)
			}
			var qe *QSOError
			if !errors.As(err, &qe) || qe.Index != -1 || qe.Field != tt.field {
				t.Errorf("err = %#v, want *QSOError Index -1 Field %s", err, tt.field)
			}
			if buf.Len() != 0 {
				t.Errorf("wrote %d bytes", buf.Len())
			}
		})
	}
	// The call comparison ignores case (tqslconvert.cpp:581).
	lower := usStation()
	lower.Call = "kf0tst"
	var buf bytes.Buffer
	mustWrite(t, newTestWriter(t, &buf), cred, lower, writerQSO("W1AW", 1))
}

func TestWriterDateRange(t *testing.T) {
	cred := newTestCredential(t) // QSO dates 2020-05-14 to 2029-03-19
	at := func(y int, m time.Month, d, h int) QSO {
		q := writerQSO("W1AW", 1)
		q.Time = time.Date(y, m, d, h, 0, 0, 0, time.UTC)
		return q
	}
	// find_matching_cert compares dates only, inclusive at both ends
	// (tqslconvert.cpp:588-596).
	for _, tt := range []struct {
		name string
		q    QSO
		ok   bool
	}{
		{"last day", at(2029, 3, 19, 23), true},
		{"first day", at(2020, 5, 14, 0), true},
		{"day after", at(2029, 3, 20, 0), false},
		{"day before", at(2020, 5, 13, 23), false},
		// The date is the UTC date: 2029-03-19 20:00 in UTC-5 is 03-20 UTC.
		{"utc", QSO{Call: "W1AW", Band: "20M", Mode: "SSB",
			Time: time.Date(2029, 3, 19, 20, 0, 0, 0, time.FixedZone("EST", -5*3600))}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := newTestWriter(t, &buf).WriteQSO(cred, usStation(), tt.q)
			if tt.ok {
				if err != nil {
					t.Fatalf("WriteQSO: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrDateRange) {
				t.Fatalf("err = %v, want ErrDateRange", err)
			}
			var qe *QSOError
			if !errors.As(err, &qe) || qe.Index != -1 || qe.Field != "QSO_DATE" {
				t.Errorf("err = %#v, want *QSOError Index -1 Field QSO_DATE", err)
			}
			if buf.Len() != 0 {
				t.Errorf("wrote %d bytes", buf.Len())
			}
		})
	}
}

func TestWriterCertWithoutQSODates(t *testing.T) {
	// find_matching_cert skips a cert whose QSONotAfterDate cannot be read
	// (tqslconvert.cpp:592-593), and likewise QSONotBeforeDate (588-589).
	for _, tt := range []struct {
		name   string
		fields func(*testCertFields)
		detail string
	}{
		{"no end", func(f *testCertFields) { f.QSONotAfter = "" }, "certificate has no QSO end date"},
		{"no start", func(f *testCertFields) { f.QSONotBefore = "" }, "certificate has no QSO start date"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := defaultTestCertFields()
			tt.fields(&f)
			cred := newTestCredentialWith(t, f)
			var buf bytes.Buffer
			err := newTestWriter(t, &buf).WriteQSO(cred, usStation(), writerQSO("W1AW", 1))
			var qe *QSOError
			if !errors.Is(err, ErrDateRange) || !errors.As(err, &qe) || qe.Detail != tt.detail {
				t.Fatalf("err = %v, want ErrDateRange with detail %q", err, tt.detail)
			}
			if buf.Len() != 0 {
				t.Errorf("wrote %d bytes", buf.Len())
			}
		})
	}
}

func TestWriterInvalidInput(t *testing.T) {
	cred := newTestCredential(t)
	t.Run("qso", func(t *testing.T) {
		var buf bytes.Buffer
		q := writerQSO("W1AW", 1)
		q.Mode = "NOSUCHMODE"
		err := newTestWriter(t, &buf).WriteQSO(cred, usStation(), q)
		var qe *QSOError
		if !errors.Is(err, ErrInvalidQSO) || !errors.As(err, &qe) || qe.Index != -1 || qe.Field != "MODE" {
			t.Fatalf("err = %v, want *QSOError MODE wrapping ErrInvalidQSO", err)
		}
		if buf.Len() != 0 {
			t.Errorf("wrote %d bytes", buf.Len())
		}
	})
	t.Run("station", func(t *testing.T) {
		var buf bytes.Buffer
		st := usStation()
		st.Fields = map[string]string{"US_STATE": "XX"}
		err := newTestWriter(t, &buf).WriteQSO(cred, st, writerQSO("W1AW", 1))
		var qe *QSOError
		if !errors.Is(err, ErrInvalidStation) || !errors.As(err, &qe) || qe.Index != -1 || qe.Field != "US_STATE" {
			t.Fatalf("err = %v, want *QSOError US_STATE wrapping ErrInvalidStation", err)
		}
		if buf.Len() != 0 {
			t.Errorf("wrote %d bytes", buf.Len())
		}
	})
}

func TestWriterNoIdentBeforeFirstQSO(t *testing.T) {
	var buf bytes.Buffer
	_ = newTestWriter(t, &buf)
	// The ident is returned only once the first QSO is parsed
	// (tqslconvert.cpp:1212-1230), so an empty log writes nothing.
	if buf.Len() != 0 {
		t.Errorf("fresh writer wrote %d bytes", buf.Len())
	}
	// A rejected first QSO writes nothing either, the ident included.
	q := writerQSO("W1AW", 1)
	q.Band = "NOBAND"
	if err := newTestWriter(t, &buf).WriteQSO(newTestCredential(t), usStation(), q); err == nil {
		t.Fatal("WriteQSO accepted an invalid band")
	}
	if buf.Len() != 0 {
		t.Errorf("rejected QSO wrote %d bytes", buf.Len())
	}
}

// fakeSigner wraps a crypto.Signer and replaces its Sign result.
type fakeSigner struct {
	pub  crypto.PublicKey
	sign func(digest []byte) ([]byte, error)
}

func (s fakeSigner) Public() crypto.PublicKey { return s.pub }

func (s fakeSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.sign(digest)
}

var errTestSigner = errors.New("test signer failure")

func TestWriterSignerError(t *testing.T) {
	cred := newTestCredential(t)
	bad := Credential{Cert: cred.Cert, Signer: fakeSigner{
		pub:  cred.Signer.Public(),
		sign: func([]byte) ([]byte, error) { return nil, errTestSigner },
	}}
	var buf bytes.Buffer
	wr := newTestWriter(t, &buf)
	err := wr.WriteQSO(bad, usStation(), writerQSO("W1AW", 1))
	if !errors.Is(err, errTestSigner) {
		t.Fatalf("err = %v, want it to wrap the signer error", err)
	}
	if buf.Len() != 0 {
		t.Errorf("wrote %d bytes after a signer error", buf.Len())
	}
	// No state changed: the next QSO starts the file afresh.
	mustWrite(t, wr, cred, usStation(), writerQSO("W1AW", 1))
	rs := parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT")
	if got := rs[1].uid(t, "CERT_UID"); got != 1 {
		t.Errorf("CERT_UID = %d, want 1", got)
	}
}

func TestWriterUnsupportedKey(t *testing.T) {
	cred := newTestCredential(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		signer crypto.Signer
	}{
		// TrustedQSL holds the signature in a 129-byte buffer
		// (location.cpp:3826); more than 128 bytes means a key over 1024
		// bits.
		{"long signature", fakeSigner{pub: cred.Signer.Public(), sign: func([]byte) ([]byte, error) {
			return make([]byte, 129), nil
		}}},
		{"not rsa", ec},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			c := Credential{Cert: cred.Cert, Signer: tt.signer}
			err := newTestWriter(t, &buf).WriteQSO(c, usStation(), writerQSO("W1AW", 1))
			if !errors.Is(err, ErrUnsupportedKey) {
				t.Fatalf("err = %v, want ErrUnsupportedKey", err)
			}
			if buf.Len() != 0 {
				t.Errorf("wrote %d bytes", buf.Len())
			}
		})
	}
}

// failWriter fails its first n writes and then appends to buf.
type failWriter struct {
	n   int
	buf bytes.Buffer
}

var errTestWrite = errors.New("test write failure")

func (w *failWriter) Write(p []byte) (int, error) {
	if w.n > 0 {
		w.n--
		return 0, errTestWrite
	}
	return w.buf.Write(p)
}

func TestWriterWriteErrorKeepsState(t *testing.T) {
	fw := &failWriter{n: 1}
	wr := newTestWriter(t, fw)
	cred := newTestCredential(t)
	if err := wr.WriteQSO(cred, usStation(), writerQSO("W1AW", 1)); !errors.Is(err, errTestWrite) {
		t.Fatalf("err = %v, want the write error", err)
	}
	mustWrite(t, wr, cred, usStation(), writerQSO("W1AW", 1))
	rs := parseGAbbI(t, fw.buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT")
	if got := rs[2].uid(t, "STATION_UID"); got != 1 {
		t.Errorf("STATION_UID = %d, want 1", got)
	}
}

// shortWriter accepts one byte less than asked, without an error.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return max(len(p)-1, 0), nil }

func TestWriterShortWrite(t *testing.T) {
	err := newTestWriter(t, shortWriter{}).WriteQSO(newTestCredential(t), usStation(), writerQSO("W1AW", 1))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err = %v, want io.ErrShortWrite", err)
	}
}

func TestWriterNilArguments(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	cred := newTestCredential(t)
	var buf bytes.Buffer
	if err := NewWriter(&buf, nil, Ident{}, NormalizeOptions{}).WriteQSO(cred, usStation(), writerQSO("W1AW", 1)); !errors.Is(err, ErrConfig) {
		t.Errorf("nil config: err = %v, want ErrConfig", err)
	}
	if err := NewWriter(nil, cfg, Ident{}, NormalizeOptions{}).WriteQSO(cred, usStation(), writerQSO("W1AW", 1)); !errors.Is(err, ErrConfig) {
		t.Errorf("nil io.Writer: err = %v, want ErrConfig", err)
	}
	if err := NewWriter(&buf, cfg, Ident{}, NormalizeOptions{}).WriteQSO(Credential{}, usStation(), writerQSO("W1AW", 1)); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("empty credential: err = %v, want ErrNoCertificate", err)
	}
	if err := NewWriter(&buf, cfg, Ident{}, NormalizeOptions{}).WriteQSO(Credential{Cert: cred.Cert}, usStation(), writerQSO("W1AW", 1)); !errors.Is(err, ErrNoKey) {
		t.Errorf("no signer: err = %v, want ErrNoKey", err)
	}
	var nilWriter *Writer
	if err := nilWriter.WriteQSO(cred, usStation(), writerQSO("W1AW", 1)); !errors.Is(err, ErrConfig) {
		t.Errorf("nil *Writer: err = %v, want ErrConfig", err)
	}
	if err := nilWriter.commit(pending{}, false); !errors.Is(err, ErrConfig) {
		t.Errorf("nil *Writer commit: err = %v, want ErrConfig", err)
	}
	if buf.Len() != 0 {
		t.Errorf("wrote %d bytes", buf.Len())
	}
}

func TestWriterPendingFields(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	var buf bytes.Buffer
	wr := NewWriter(&buf, cfg, Ident{}, NormalizeOptions{})
	cred := newTestCredential(t)
	raw := writerQSO("w1aw", 1)
	p, err := wr.prepare(cred, usStation(), raw)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("prepare wrote %d bytes", buf.Len())
	}
	norm, _ := cfg.NormalizeQSO(raw, NormalizeOptions{})
	sd, _ := SignData(cfg, usStation(), norm)
	if p.QSO != norm || p.SignData != sd || p.Cert != cred.Cert ||
		p.StationDetails != StationDetails(cfg, usStation()) {
		t.Errorf("pending = %+v", p)
	}
	if err := wr.commit(p, true); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// A pending from before the last commit is stale.
	p2, err := wr.prepare(cred, usStation(), raw)
	if err != nil {
		t.Fatal(err)
	}
	p3, err := wr.prepare(cred, usStation(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := wr.commit(p2, true); err != nil {
		t.Fatalf("commit: %v", err)
	}
	n := buf.Len()
	if err := wr.commit(p3, true); err == nil {
		t.Error("commit of a stale pending succeeded")
	}
	if buf.Len() != n {
		t.Error("stale commit wrote bytes")
	}
}

func TestWriterDuplicateKeepsPreamble(t *testing.T) {
	// unverified: fixture phase confirms
	// tqsl_getConverterGABBI returns tCERT (tqslconvert.cpp:1562-1580) and
	// tSTATION (1813-1816) as separate records, and apps/tqsl.cpp:2363-2373
	// writes each as soon as it is returned. The duplicate check comes after
	// signing (tqslconvert.cpp:1842-1849), so a duplicate under -a compliant
	// leaves its tCERT and tSTATION in the file and the UIDs advanced. This
	// is how Sign (Task 7) drives prepare and commit.
	var buf bytes.Buffer
	wr := newTestWriter(t, &buf)
	credA := newTestCredential(t)
	credB := newTestCredentialWith(t, defaultTestCertFields())

	p1, err := wr.prepare(credA, usStation(), writerQSO("W1AW", 1))
	if err != nil {
		t.Fatalf("prepare QSO1: %v", err)
	}
	if err := wr.commit(p1, false); err != nil { // rejected as a duplicate
		t.Fatalf("commit QSO1: %v", err)
	}
	p2, err := wr.prepare(credB, usStation(), writerQSO("W1AW", 2))
	if err != nil {
		t.Fatalf("prepare QSO2: %v", err)
	}
	if err := wr.commit(p2, true); err != nil {
		t.Fatalf("commit QSO2: %v", err)
	}

	rs := parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCERT", "tSTATION", "tCONTACT")
	for _, c := range []struct {
		rec         int
		field       string
		want        int
		description string
	}{
		{1, "CERT_UID", 1, "tCERT A"},
		{2, "STATION_UID", 1, "tSTATION for A"},
		{2, "CERT_UID", 1, "tSTATION for A"},
		{3, "CERT_UID", 2, "tCERT B"},
		{4, "STATION_UID", 2, "tSTATION for B"},
		{4, "CERT_UID", 2, "tSTATION for B"},
		{5, "STATION_UID", 2, "tCONTACT"},
	} {
		if got := rs[c.rec].uid(t, c.field); got != c.want {
			t.Errorf("%s %s = %d, want %d", c.description, c.field, got, c.want)
		}
	}
	certA, _ := rs[1].get("CERTIFICATE")
	if der, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(certA, "\n", "")); !bytes.Equal(der, credA.Cert.X509.Raw) {
		t.Error("first tCERT is not certificate A")
	}
	// Each record is still followed by a blank line (apps/tqsl.cpp:2365-2369).
	if n := strings.Count(buf.String(), "<eor>\n\n"); n != 5 {
		t.Errorf("%d records end in <eor> and a blank line, want 5", n)
	}
}

func TestWriterSignFailureKeepsPreamble(t *testing.T) {
	cred := newTestCredential(t)
	bad := Credential{Cert: cred.Cert, Signer: fakeSigner{
		pub:  cred.Signer.Public(),
		sign: func([]byte) ([]byte, error) { return nil, errTestSigner },
	}}

	// prepare gives the error and a pending holding the ident, tCERT and
	// tSTATION, which tqsl has already written by the time it signs
	// (tqslconvert.cpp:1576, 1813-1816, 1820; apps/tqsl.cpp:2363-2373).
	var buf bytes.Buffer
	wr := newTestWriter(t, &buf)
	p, err := wr.prepare(bad, usStation(), writerQSO("W1AW", 1))
	if !errors.Is(err, errTestSigner) {
		t.Fatalf("prepare err = %v, want the signer error", err)
	}
	if p.contact != nil {
		t.Error("pending has a tCONTACT after a signing failure")
	}
	if err := wr.commit(p, true); err == nil {
		t.Error("commit with contact succeeded without a tCONTACT")
	}
	if buf.Len() != 0 {
		t.Fatalf("failed commit wrote %d bytes", buf.Len())
	}
	if err := wr.commit(p, false); err != nil {
		t.Fatalf("commit preamble: %v", err)
	}
	wantTypes(t, parseGAbbI(t, buf.Bytes()), "TQSL_IDENT", "tCERT", "tSTATION")

	// The next QSO reuses the cert and station already written.
	mustWrite(t, wr, cred, usStation(), writerQSO("W1AW", 2))
	rs := parseGAbbI(t, buf.Bytes())
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT")
	if got := rs[3].uid(t, "STATION_UID"); got != 1 {
		t.Errorf("tCONTACT STATION_UID = %d, want 1", got)
	}

	// WriteQSO in the same situation writes nothing.
	var buf2 bytes.Buffer
	if err := newTestWriter(t, &buf2).WriteQSO(bad, usStation(), writerQSO("W1AW", 1)); !errors.Is(err, errTestSigner) {
		t.Fatalf("WriteQSO err = %v, want the signer error", err)
	}
	if buf2.Len() != 0 {
		t.Errorf("WriteQSO wrote %d bytes after a signing failure", buf2.Len())
	}
}

func TestWriterPreambleOnlyEmpty(t *testing.T) {
	// With the cert and station already written, a rejected QSO has an
	// empty preamble, and commit(p, false) makes no Write at all.
	fw := &failWriter{}
	wr := newTestWriter(t, fw)
	cred := newTestCredential(t)
	mustWrite(t, wr, cred, usStation(), writerQSO("W1AW", 1))
	p, err := wr.prepare(cred, usStation(), writerQSO("W1AW", 2))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.preamble) != 0 {
		t.Fatalf("preamble = %q, want empty", p.preamble)
	}
	fw.n = 1 // a Write would fail
	if err := wr.commit(p, false); err != nil {
		t.Errorf("commit of an empty preamble: %v", err)
	}
}

func TestWriterNoPreambleOnEarlyError(t *testing.T) {
	// Normalization, station and certificate failures give a zero pending,
	// which commit refuses.
	var buf bytes.Buffer
	wr := newTestWriter(t, &buf)
	st := usStation()
	st.Call = "KF0XXX"
	p, err := wr.prepare(newTestCredential(t), st, writerQSO("W1AW", 1))
	if !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("err = %v, want ErrCertMismatch", err)
	}
	if p.valid || p.preamble != nil {
		t.Errorf("pending = %+v, want zero", p)
	}
	if err := wr.commit(p, false); err == nil || buf.Len() != 0 {
		t.Errorf("commit of a zero pending: err %v, %d bytes", err, buf.Len())
	}
}

func TestStationErrorField(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := usStation()
	st.Fields = map[string]string{"US_STATE": "XX"}
	err := cfg.ValidateStation(st)
	// ValidateStation's contract: wraps ErrInvalidStation and names the
	// field in the message.
	if !errors.Is(err, ErrInvalidStation) || !strings.Contains(err.Error(), "US_STATE") {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(err.Error(), "gabbi: invalid station: US_STATE: ") {
		t.Errorf("message = %q", err.Error())
	}
	var se *stationError
	if !errors.As(err, &se) || se.field != "US_STATE" {
		t.Errorf("err = %#v, want *stationError for US_STATE", err)
	}
}
