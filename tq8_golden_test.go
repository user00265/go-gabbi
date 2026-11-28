package gabbi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSignTrustedQSLGolden(t *testing.T) {
	fixture := func(name string) []byte {
		t.Helper()
		if dir := os.Getenv("GABBI_TQ8_FIXTURE_DIR"); dir != "" {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		return readTestdata(t, "tq8/"+name)
	}

	goldenStation := Station{
		Call:       "KF0TST",
		DXCC:       291,
		GridSquare: "em10dh",
		CQZ:        4,
		ITUZ:       7,
		IOTA:       "na-001",
		Fields: map[string]string{
			"US_STATE":  "TX",
			"US_COUNTY": "Travis",
		},
	}

	qso := func(call string, year int, month time.Month, day int) QSO {
		return QSO{
			Call: call,
			Band: "20M",
			Mode: "CW",
			Freq: "14.250",
			Time: time.Date(year, month, day, 15, 30, 0, 0, time.UTC),
		}
	}

	newCred := func(t *testing.T, notBefore, notAfter string) Credential {
		t.Helper()
		return newTestCredentialWith(t, testCertFields{
			Callsign:     "KF0TST",
			QSONotBefore: notBefore,
			QSONotAfter:  notAfter,
			DXCC:         "291",
		})
	}

	singleContacts := []QSO{
		qso("W1AW", 2026, time.November, 1),
		qso("K1ABC", 2026, time.November, 2),
	}
	switchContacts := []QSO{
		qso("W1AW", 2025, time.November, 1),
		qso("K1ABC", 2025, time.November, 2),
		qso("N1TST", 2026, time.November, 1),
		qso("W2XYZ", 2025, time.November, 3),
	}
	dupeSeed := []QSO{
		qso("W1AW", 2026, time.November, 1),
	}
	dupeContacts := []QSO{
		qso("W1AW", 2026, time.November, 1),
		qso("K1NEW", 2025, time.November, 1),
	}

	type goldenCase struct {
		file       string
		chained    bool
		twoCerts   bool
		seedDupes  bool
		qsos       []QSO
		wantSigned int
		wantDupes  int
	}

	cases := []goldenCase{
		{
			file:       "normal.gabbi",
			qsos:       singleContacts,
			wantSigned: 2,
		},
		{
			file:       "chained.gabbi",
			chained:    true,
			qsos:       singleContacts,
			wantSigned: 2,
		},
		{
			file:       "switch.gabbi",
			twoCerts:   true,
			qsos:       switchContacts,
			wantSigned: 4,
		},
		{
			file:       "switch-chained.gabbi",
			chained:    true,
			twoCerts:   true,
			qsos:       switchContacts,
			wantSigned: 4,
		},
		{
			file:       "dupe-preamble.gabbi",
			twoCerts:   true,
			seedDupes:  true,
			qsos:       dupeContacts,
			wantSigned: 1,
			wantDupes:  1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			goldBytes := fixture(tc.file)
			goldRecs := parseGAbbI(t, goldBytes)

			// Verify every golden tCERT record matches recCert(cert, uid) byte-for-byte,
			// and extract the public certificates for signature verification.
			goldCerts := verifyGoldenCerts(t, goldBytes, goldRecs)
			if len(goldCerts) == 0 {
				t.Fatal("golden fixture has no tCERT records")
			}

			// Verify every golden tCONTACT RSA-1024 SHA-1 signature against the
			// matching public certificate extracted from the golden tCERT records.
			verifyContactSignatures(t, "golden", goldRecs, goldCerts)

			// Build matching ephemeral in-memory RSA-1024 credentials and run Sign.
			cfg := loadTestConfig(t, "config-11.35.xml")
			if tc.chained {
				cfg.adifMap["CW"] = "SSB"
				cfg.adifMap["SSB"] = "DATA"
			}

			var creds []Credential
			if tc.twoCerts {
				creds = []Credential{
					newCred(t, "2020-01-01", "2025-12-31"),
					newCred(t, "2026-01-01", "2035-12-31"),
				}
			} else {
				creds = []Credential{
					newCred(t, "2020-01-01", "2035-12-31"),
				}
			}

			opt := SignOptions{
				Action: Compliant,
				Ident:  Ident{Program: "go-gabbi-fixture", Version: "2.8.7"},
			}
			if tc.seedDupes {
				store := newMapStore()
				var seedOut bytes.Buffer
				seedRep, err := Sign(context.Background(), &seedOut, cfg, creds, goldenStation, slices.Values(dupeSeed), SignOptions{
					Action: Compliant,
					Dupes:  store,
					Ident:  opt.Ident,
				})
				if err != nil || seedRep.Signed != 1 || !seedRep.Commit {
					t.Fatalf("seed Sign = %v, report %+v", err, seedRep)
				}
				opt.Dupes = store
			}

			var gotOut bytes.Buffer
			rep, err := Sign(context.Background(), &gotOut, cfg, creds, goldenStation, slices.Values(tc.qsos), opt)
			if err != nil {
				t.Fatalf("Sign error: %v (report %+v)", err, rep)
			}
			if rep.Signed != tc.wantSigned || rep.Duplicates != tc.wantDupes {
				t.Fatalf("report Signed=%d Duplicates=%d, want %d and %d", rep.Signed, rep.Duplicates, tc.wantSigned, tc.wantDupes)
			}

			gotRecs := parseGAbbI(t, gotOut.Bytes())

			// Compare Go output against TrustedQSL golden records.
			compareGAbbIRecords(t, gotRecs, goldRecs)

			// Parse the emitted tCERT records from Go's output, confirm their count,
			// order, and ARRL metadata match the golden tCERT records, and verify
			// Go's emitted signatures against those parsed certificates.
			gotCerts := parseRecordCerts(t, "go-gabbi", gotRecs)
			if len(gotCerts) != len(goldCerts) {
				t.Fatalf("go-gabbi emitted %d tCERT records, want %d", len(gotCerts), len(goldCerts))
			}
			for i := range goldCerts {
				gc, wc := gotCerts[i], goldCerts[i]
				if gc.Callsign != wc.Callsign || gc.DXCC != wc.DXCC ||
					gc.QSONotBefore != wc.QSONotBefore || gc.QSONotAfter != wc.QSONotAfter {
					t.Errorf("go-gabbi tCERT %d = (%s, DXCC %d, %s..%s), want (%s, DXCC %d, %s..%s)",
						i+1, gc.Callsign, gc.DXCC, gc.QSONotBefore, gc.QSONotAfter,
						wc.Callsign, wc.DXCC, wc.QSONotBefore, wc.QSONotAfter)
				}
			}
			verifyContactSignatures(t, "go-gabbi", gotRecs, gotCerts)
		})
	}
}

// parseRecordCerts decodes every tCERT record's CERTIFICATE field into a
// parsed ARRL Certificate, preserving document order.
func parseRecordCerts(t *testing.T, label string, recs []gRecord) []*Certificate {
	t.Helper()
	var certs []*Certificate
	for _, r := range recs {
		if r.Type != "tCERT" {
			continue
		}
		uid := r.uid(t, "CERT_UID")
		b64, ok := r.get("CERTIFICATE")
		if !ok {
			t.Fatalf("%s tCERT %d has no CERTIFICATE field", label, uid)
		}
		der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(b64, "\n", ""))
		if err != nil {
			t.Fatalf("%s decode tCERT %d base64: %v", label, uid, err)
		}
		x509Cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%s parse tCERT %d x509: %v", label, uid, err)
		}
		parsed, err := ParseCertificate(x509Cert)
		if err != nil {
			t.Fatalf("%s ParseCertificate tCERT %d: %v", label, uid, err)
		}
		certs = append(certs, parsed)
	}
	return certs
}

// verifyGoldenCerts parses every tCERT in goldRecs, checks that recCert(cert, uid)
// reproduces the exact raw tCERT bytes in goldBytes, and returns the parsed certificates.
func verifyGoldenCerts(t *testing.T, goldBytes []byte, goldRecs []gRecord) []*Certificate {
	t.Helper()
	rawCerts := extractRawCertRecords(t, goldBytes)
	certs := parseRecordCerts(t, "golden", goldRecs)
	if len(certs) != len(rawCerts) {
		t.Fatalf("parsed %d tCERT records, extracted %d raw tCERT records", len(certs), len(rawCerts))
	}
	certIdx := 0
	for _, r := range goldRecs {
		if r.Type != "tCERT" {
			continue
		}
		uid := r.uid(t, "CERT_UID")
		wantRaw := rawCerts[certIdx]
		gotRaw := recCert(certs[certIdx], uid)
		if gotRaw != wantRaw {
			t.Errorf("tCERT %d: recCert differs from golden bytes\ngot:\n%q\nwant:\n%q", uid, gotRaw, wantRaw)
		}
		certIdx++
	}
	return certs
}

// extractRawCertRecords slices each "<Rec_Type:5>tCERT\n...<eor>\n" block verbatim
// from raw GAbbI output so recCert can be compared byte-for-byte.
func extractRawCertRecords(t *testing.T, data []byte) []string {
	t.Helper()
	const startMarker = "<Rec_Type:5>tCERT\n"
	const endMarker = "<eor>\n"
	s := string(data)
	var out []string
	for {
		i := strings.Index(s, startMarker)
		if i < 0 {
			break
		}
		s = s[i:]
		j := strings.Index(s, endMarker)
		if j < 0 {
			t.Fatal("unterminated tCERT record in golden bytes")
		}
		end := j + len(endMarker)
		out = append(out, s[:end])
		s = s[end:]
	}
	return out
}

// verifyContactSignatures verifies every tCONTACT record's RSA-1024 SHA-1 signature
// against the public certificate in certs whose QSO date range covers QSO_DATE.
func verifyContactSignatures(t *testing.T, label string, recs []gRecord, certs []*Certificate) {
	t.Helper()
	contacts := 0
	for idx, r := range recs {
		if r.Type != "tCONTACT" {
			continue
		}
		contacts++
		qsoDateStr, ok := r.get("QSO_DATE")
		if !ok {
			t.Fatalf("%s record %d: tCONTACT has no QSO_DATE", label, idx)
		}
		qsoDate, err := ParseDate(qsoDateStr)
		if err != nil {
			t.Fatalf("%s record %d: bad QSO_DATE %q: %v", label, idx, qsoDateStr, err)
		}
		signData, ok := r.get("SIGNDATA")
		if !ok {
			t.Fatalf("%s record %d: tCONTACT has no SIGNDATA", label, idx)
		}
		sigB64, ok := r.get("SIGN_LOTW_V2.0")
		if !ok {
			t.Fatalf("%s record %d: tCONTACT has no SIGN_LOTW_V2.0", label, idx)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(sigB64, "\n", ""))
		if err != nil {
			t.Fatalf("%s record %d: decode signature base64: %v", label, idx, err)
		}
		var signer *Certificate
		for _, c := range certs {
			if qsoDate.Compare(c.QSONotBefore) >= 0 && qsoDate.Compare(c.QSONotAfter) <= 0 {
				signer = c
				break
			}
		}
		if signer == nil {
			t.Fatalf("%s record %d: no certificate covers QSO_DATE %s", label, idx, qsoDateStr)
		}
		pub, ok := signer.X509.PublicKey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("%s record %d: certificate key is not RSA", label, idx)
		}
		if pub.N.BitLen() != 1024 {
			t.Fatalf("%s record %d: RSA key is %d bits, want 1024", label, idx, pub.N.BitLen())
		}
		digest := sha1.Sum([]byte(signData))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest[:], sigBytes); err != nil {
			t.Errorf("%s record %d (CALL=%s, QSO_DATE=%s): RSA-SHA1 signature verification failed: %v",
				label, idx, fieldVal(r, "CALL"), qsoDateStr, err)
		}
	}
	if contacts == 0 {
		t.Fatalf("%s: no tCONTACT records found", label)
	}
}

func fieldVal(r gRecord, name string) string {
	v, _ := r.get(name)
	return v
}

// compareGAbbIRecords compares got against want for record types, order, UIDs,
// field names, types, lengths, MODE, and SIGNDATA. It excludes only the
// intentionally different TQSL_IDENT tail, dynamic CERTIFICATE bytes, and
// dynamic signature bytes (while still checking signature field name, type,
// and encoded length).
func compareGAbbIRecords(t *testing.T, got, want []gRecord) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("record count = %d (%v), want %d (%v)",
			len(got), recordTypes(got), len(want), recordTypes(want))
	}
	for i := range want {
		gr, wr := got[i], want[i]
		if gr.Type != wr.Type {
			t.Fatalf("record %d: type = %q, want %q (all got=%v want=%v)",
				i, gr.Type, wr.Type, recordTypes(got), recordTypes(want))
		}
		if len(gr.Fields) != len(wr.Fields) {
			t.Fatalf("record %d (%s): field count = %d, want %d\ngot:  %v\nwant: %v",
				i, wr.Type, len(gr.Fields), len(wr.Fields), gr.Fields, wr.Fields)
		}
		for j := range wr.Fields {
			gf, wf := gr.Fields[j], wr.Fields[j]
			if gf.name != wf.name {
				t.Fatalf("record %d (%s) field %d: name = %q, want %q",
					i, wr.Type, j, gf.name, wf.name)
			}
			if gf.typ != wf.typ {
				t.Errorf("record %d (%s) field %s: type = %q, want %q",
					i, wr.Type, wf.name, gf.typ, wf.typ)
			}
			switch wf.name {
			case "TQSL_IDENT":
				// Intentionally different tail (no "Source: ... Writer: ...").
				if !strings.Contains(gf.value, "Config: V11.35") || !strings.Contains(gf.value, "AllowDupes: false") {
					t.Errorf("record %d TQSL_IDENT = %q, missing expected config/dupes fields", i, gf.value)
				}
			case "CERTIFICATE":
				// Dynamic per-run certificate bytes; parsed and checked by parseRecordCerts.
				if len(gf.value) == 0 {
					t.Errorf("record %d CERTIFICATE is empty", i)
				}
			case "SIGN_LOTW_V2.0":
				// Dynamic per-key signature bytes, but RSA-1024 BIO_f_base64 length must match.
				if len(gf.value) != len(wf.value) {
					t.Errorf("record %d (%s) %s: length = %d, want %d",
						i, wr.Type, wf.name, len(gf.value), len(wf.value))
				}
			default:
				if len(gf.value) != len(wf.value) || gf.value != wf.value {
					t.Errorf("record %d (%s) field %s: got %q (len %d), want %q (len %d)",
						i, wr.Type, wf.name, gf.value, len(gf.value), wf.value, len(wf.value))
				}
			}
		}
	}
}
