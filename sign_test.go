package gabbi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// Line numbers in comments refer to TrustedQSL at HEAD 9b30153 (excerpts in
// .superpowers/sdd/2026-11-24-signing-path-plan/tqsl-excerpts-task6.txt):
// src/tqslconvert.cpp, src/openssl_cert.cpp and apps/tqsl.cpp.

// mapStore is an in-memory DupeStore that logs every call.
type mapStore struct {
	m      map[string]string
	calls  []string
	getErr error
	putErr error
	delErr error
}

func newMapStore() *mapStore { return &mapStore{m: map[string]string{}} }

func (s *mapStore) Get(_ context.Context, key string) (string, bool, error) {
	s.calls = append(s.calls, "get "+key)
	if s.getErr != nil {
		return "", false, s.getErr
	}
	v, ok := s.m[key]
	return v, ok, nil
}

func (s *mapStore) Put(_ context.Context, key, details string) error {
	s.calls = append(s.calls, "put "+key+"="+details)
	if s.putErr != nil {
		return s.putErr
	}
	s.m[key] = details
	return nil
}

func (s *mapStore) Delete(_ context.Context, key string) error {
	s.calls = append(s.calls, "del "+key)
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.m, key)
	return nil
}

// Expected values for usStation and writerQSO("W1AW", 1), built by hand
// from the sources rather than from this package's functions.
const (
	// StationDetails: "NAME: value" for each non-empty tSTATION sigspec
	// field, joined by ", " (location.cpp:880-883).
	testDetails = "CQZ: 4, GRIDSQUARE: EM10dh, ITUZ: 7, US_COUNTY: Travis, US_STATE: TX"
	// Dupe key: certificate callsign + trimmed tCONTACT values, not
	// uppercased (tqslconvert.cpp:1836-1839).
	testKey1 = "KF0TST20MW1AW14.250SSB2026-11-0115:30:00Z"
	// Sign data: uppercased station then contact values
	// (location.cpp:754-886, 3762-3829).
	testSignData1 = "4EM10DH7TRAVISTX20MW1AW14.250SSB2026-11-0115:30:00Z"
)

// testLegacyKey is the old-style key: sign data + BN_bn2hex of the serial
// (tqslconvert.cpp:1833-1835).
func testLegacyKey(c Credential) string {
	return testSignData1 + strings.ToUpper(hex.EncodeToString(c.Cert.X509.SerialNumber.Bytes()))
}

func runSign(t *testing.T, creds []Credential, st Station, qsos []QSO, opt SignOptions) ([]byte, Report, error) {
	t.Helper()
	var buf bytes.Buffer
	rep, err := Sign(context.Background(), &buf, loadTestConfig(t, "config-11.35.xml"), creds, st, slices.Values(qsos), opt)
	return buf.Bytes(), rep, err
}

func testIdent() Ident { return Ident{Program: "test", Version: "1.0"} }

func countType(rs []gRecord, typ string) int {
	n := 0
	for _, r := range rs {
		if r.Type == typ {
			n++
		}
	}
	return n
}

// certsIn returns the DER of every tCERT in the output.
func certsIn(t *testing.T, rs []gRecord) [][]byte {
	t.Helper()
	var out [][]byte
	for _, r := range rs {
		if r.Type != "tCERT" {
			continue
		}
		v, _ := r.get("CERTIFICATE")
		der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(v, "\n", ""))
		if err != nil {
			t.Fatalf("tCERT CERTIFICATE: %v", err)
		}
		out = append(out, der)
	}
	return out
}

func wantOutcomes(t *testing.T, rep Report, want ...Outcome) {
	t.Helper()
	var got []Outcome
	for i, r := range rep.Results {
		if r.Index != i {
			t.Errorf("Results[%d].Index = %d", i, r.Index)
		}
		got = append(got, r.Outcome)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("outcomes = %v, want %v", got, want)
	}
}

func dayQSO(y int, m time.Month, d int) QSO {
	q := writerQSO("W1AW", 1)
	q.Time = time.Date(y, m, d, 12, 0, 0, 0, time.UTC)
	return q
}

func TestSignSelectsCert(t *testing.T) {
	// find_matching_cert (tqslconvert.cpp:571-599): call ignoring case,
	// DXCC exact, then the first cert whose QSO range holds the date,
	// inclusive at both ends.
	f1 := defaultTestCertFields()
	f1.QSONotBefore, f1.QSONotAfter = "2020-01-01", "2024-12-31"
	f2 := defaultTestCertFields()
	f2.QSONotBefore, f2.QSONotAfter = "2024-06-01", "2029-12-31"
	c1, c2 := newTestCredentialWith(t, f1), newTestCredentialWith(t, f2)

	for _, tt := range []struct {
		name string
		q    QSO
		want Credential
	}{
		{"2025 QSO uses cred 2", dayQSO(2025, 3, 1), c2},
		{"2023 QSO uses cred 1", dayQSO(2023, 3, 1), c1},
		{"overlap picks the first in order", dayQSO(2024, 7, 1), c1},
		{"last day of cred 1 is inclusive", dayQSO(2024, 12, 31), c1},
		{"first day of cred 2 is inclusive", dayQSO(2025, 1, 1), c2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, rep, err := runSign(t, []Credential{c1, c2}, usStation(), []QSO{tt.q}, SignOptions{Ident: testIdent()})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			wantOutcomes(t, rep, Signed)
			certs := certsIn(t, parseGAbbI(t, out))
			if len(certs) != 1 || !bytes.Equal(certs[0], tt.want.Cert.X509.Raw) {
				t.Errorf("signed with the wrong certificate")
			}
		})
	}

	t.Run("lower-case station call matches", func(t *testing.T) {
		st := usStation()
		st.Call = "kf0tst" // strcasecmp, tqslconvert.cpp:581
		_, rep, err := runSign(t, []Credential{c1, c2}, st, []QSO{dayQSO(2025, 3, 1)}, SignOptions{})
		if err != nil {
			t.Fatalf("Sign: %v (%v)", err, rep.Results)
		}
	})

	t.Run("no QSONotAfter is skipped", func(t *testing.T) {
		// tqslconvert.cpp:592-593: continue when the date is missing.
		f := defaultTestCertFields()
		f.QSONotAfter = ""
		open := newTestCredentialWith(t, f)
		out, rep, err := runSign(t, []Credential{open, c2}, usStation(), []QSO{dayQSO(2025, 3, 1)}, SignOptions{})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		wantOutcomes(t, rep, Signed)
		if certs := certsIn(t, parseGAbbI(t, out)); !bytes.Equal(certs[0], c2.Cert.X509.Raw) {
			t.Error("cert without QSONotAfter was used")
		}
		// Alone, it counts as found, so the error is a date mismatch
		// (anyfound is set before the date checks, 587-593, 1551-1554).
		_, rep, err = runSign(t, []Credential{open}, usStation(), []QSO{dayQSO(2025, 3, 1)}, SignOptions{})
		if !errors.Is(err, ErrNoQSOs) {
			t.Fatalf("err = %v, want ErrNoQSOs", err)
		}
		if !errors.Is(rep.Results[0].Err, ErrDateRange) {
			t.Errorf("Result.Err = %v, want ErrDateRange", rep.Results[0].Err)
		}
	})

	t.Run("call matches but no date gives ErrDateRange", func(t *testing.T) {
		// TQSL_CERT_DATE_MISMATCH (tqslconvert.cpp:1551-1554).
		_, rep, err := runSign(t, []Credential{c1, c2}, usStation(), []QSO{dayQSO(2019, 1, 1)}, SignOptions{})
		if !errors.Is(err, ErrNoQSOs) {
			t.Fatalf("err = %v, want ErrNoQSOs", err)
		}
		wantOutcomes(t, rep, Failed)
		var qe *QSOError
		if !errors.As(rep.Results[0].Err, &qe) || !errors.Is(qe, ErrDateRange) || qe.Index != 0 || qe.Field != "QSO_DATE" {
			t.Errorf("Result.Err = %#v, want a QSOError at index 0, QSO_DATE, ErrDateRange", rep.Results[0].Err)
		}
	})

	t.Run("no call match gives ErrCertMismatch", func(t *testing.T) {
		// TQSL_CERT_NOT_FOUND (tqslconvert.cpp:1550).
		for _, st := range []Station{
			func() Station { s := usStation(); s.Call = "W1XYZ"; return s }(),
			func() Station { s := usStation(); s.DXCC = 1; return s }(),
		} {
			_, rep, _ := runSign(t, []Credential{c1, c2}, st, []QSO{dayQSO(2025, 3, 1)}, SignOptions{})
			wantOutcomes(t, rep, Failed)
			if err := rep.Results[0].Err; !errors.Is(err, ErrCertMismatch) || errors.Is(err, ErrDateRange) {
				t.Errorf("Result.Err = %v, want ErrCertMismatch only", err)
			}
		}
	})
}

// newARRLNamedCA returns a self-signed CA whose subject, written in
// OpenSSL's one-line form, is the issuer in the owner's real .5 value
// (knowledge.md §8.1), with emailAddress where ARRL writes Email.
func newARRLNamedCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := newTestKeyBits(t, 2048)
	atv := func(oid asn1.ObjectIdentifier, tag int, v string) []pkix.AttributeTypeAndValue {
		return []pkix.AttributeTypeAndValue{{Type: oid, Value: asn1.RawValue{Tag: tag, Bytes: []byte(v)}}}
	}
	rdns := pkix.RDNSequence{
		atv(asn1.ObjectIdentifier{2, 5, 4, 6}, asn1.TagPrintableString, "US"),
		atv(asn1.ObjectIdentifier{2, 5, 4, 8}, asn1.TagPrintableString, "CT"),
		atv(asn1.ObjectIdentifier{2, 5, 4, 7}, asn1.TagPrintableString, "Newington"),
		atv(asn1.ObjectIdentifier{2, 5, 4, 10}, asn1.TagPrintableString, "American Radio Relay League"),
		atv(asn1.ObjectIdentifier{2, 5, 4, 11}, asn1.TagPrintableString, "Logbook of the World"),
		atv(asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.TagPrintableString, "Logbook of the World Production CA"),
		atv(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, asn1.TagIA5String, "arrl.org"),
		atv(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, asn1.TagIA5String, "lotw@arrl.org"),
	}
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		RawSubject:            raw,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func credFromCA(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, f testCertFields) Credential {
	t.Helper()
	key := newTestKey(t)
	c, err := ParseCertificate(newTestCert(t, ca, caKey, key.Public(), f))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	cred, err := NewCredential(c, key)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func TestSignSupersededSkipped(t *testing.T) {
	// get_certlist drops a cert another cert's supercededCertificate
	// names (openssl_cert.cpp:3843-3846, 1034-1071). ARRL writes
	// "/Email=", and TQSL also tries "/emailAddress=" (1042-1052) against
	// X509_NAME_oneline of the issuer (1057).
	ca, caKey := newARRLNamedCA(t)
	f := defaultTestCertFields()
	f.Supersedes = ""
	old := credFromCA(t, ca, caKey, f)
	serial := old.Cert.X509.SerialNumber.String()

	for _, tt := range []struct {
		name       string
		supersedes string
		wantOld    bool
	}{
		{"named with ARRL's Email form", testSupersededIssuer + ";" + serial, false},
		{"other issuer", "/C=US/O=Someone Else/CN=Other CA;" + serial, true},
		{"other serial", testSupersededIssuer + ";1" + serial, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nf := defaultTestCertFields()
			nf.Supersedes = tt.supersedes
			newer := credFromCA(t, ca, caKey, nf)
			out, _, err := runSign(t, []Credential{old, newer}, usStation(), []QSO{writerQSO("W1AW", 1)}, SignOptions{})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			want := newer
			if tt.wantOld {
				want = old
			}
			if certs := certsIn(t, parseGAbbI(t, out)); !bytes.Equal(certs[0], want.Cert.X509.Raw) {
				t.Errorf("signed with the wrong certificate (want old = %v)", tt.wantOld)
			}
		})
	}
}

func TestSignExpiredSkipped(t *testing.T) {
	// tqsl_isCertificateExpired: expired when the notAfter date is before
	// today's UTC date, by date alone (openssl_cert.cpp:878-904).
	today := time.Now().UTC().Truncate(24 * time.Hour)
	good := newTestCredential(t)
	for _, tt := range []struct {
		name     string
		notAfter time.Time
		now      time.Time
		expired  bool
	}{
		{"expired yesterday", today.Add(-time.Minute), today.Add(time.Minute), true},
		{"expires later today", today.Add(time.Minute), today.Add(23 * time.Hour), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := defaultTestCertFields()
			f.NotAfter = tt.notAfter
			cand := newTestCredentialWith(t, f)
			out, _, err := runSign(t, []Credential{cand, good}, usStation(), []QSO{writerQSO("W1AW", 1)}, SignOptions{Now: tt.now})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			want := cand
			if tt.expired {
				want = good
			}
			if certs := certsIn(t, parseGAbbI(t, out)); !bytes.Equal(certs[0], want.Cert.X509.Raw) {
				t.Errorf("signed with the wrong certificate (expired = %v)", tt.expired)
			}
		})
	}

	t.Run("only an expired cert", func(t *testing.T) {
		// get_certlist leaves it out, so nothing is found:
		// TQSL_CERT_NOT_FOUND (tqslconvert.cpp:1550).
		f := defaultTestCertFields()
		f.NotAfter = today.Add(-time.Minute)
		_, rep, err := runSign(t, []Credential{newTestCredentialWith(t, f)}, usStation(),
			[]QSO{writerQSO("W1AW", 1)}, SignOptions{Now: today.Add(time.Minute)})
		if !errors.Is(err, ErrNoQSOs) {
			t.Fatalf("err = %v, want ErrNoQSOs", err)
		}
		e := rep.Results[0].Err
		if !errors.Is(e, ErrCertMismatch) || !errors.Is(e, ErrExpired) {
			t.Errorf("Result.Err = %v, want ErrCertMismatch and ErrExpired", e)
		}
	})
}

func TestSignDateFilter(t *testing.T) {
	// User date filter (tqslconvert.cpp:1374-1388), inclusive, counted
	// as out of range and skipped silently (apps/tqsl.cpp:2433-2437).
	cred := newTestCredential(t)
	d := Date{2026, time.November, 1}
	for _, tt := range []struct {
		name     string
		from, to Date
		want     Outcome
	}{
		{"no filter", Date{}, Date{}, Signed},
		{"from = to = QSO date", d, d, Signed},
		{"before from", Date{2026, time.November, 2}, Date{}, OutOfRange},
		{"after to", Date{}, Date{2026, time.October, 31}, OutOfRange},
		{"from only, inside", Date{2026, time.October, 31}, Date{}, Signed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, rep, _ := runSign(t, []Credential{cred}, usStation(), []QSO{writerQSO("W1AW", 1)},
				SignOptions{From: tt.from, To: tt.to, Action: Abort})
			wantOutcomes(t, rep, tt.want)
			if tt.want == OutOfRange {
				if rep.OutOfRange != 1 || !errors.Is(rep.Results[0].Err, ErrDateRange) {
					t.Errorf("report = %+v", rep)
				}
			}
		})
	}
}

func TestSignOutOfRangeEmitsNothing(t *testing.T) {
	cred := newTestCredential(t)
	store := newMapStore()
	bad := writerQSO("W1AW", 1)
	bad.Band = "99M" // invalid, but the band check (1438) comes after the filter (1374)
	noCall := writerQSO("", 1)
	opt := SignOptions{From: Date{2027, time.January, 1}, Dupes: store, Action: Abort}
	out, rep, err := runSign(t, []Credential{cred}, usStation(), []QSO{writerQSO("W1AW", 1), bad}, opt)
	if !errors.Is(err, ErrNoQSOs) {
		t.Fatalf("err = %v, want ErrNoQSOs", err)
	}
	if len(out) != 0 {
		t.Errorf("wrote %d bytes for out-of-range QSOs", len(out))
	}
	wantOutcomes(t, rep, OutOfRange, OutOfRange)
	if len(store.calls) != 0 {
		t.Errorf("store calls = %v, want none", store.calls)
	}
	// tqsl counts out-of-range QSOs in processed (apps/tqsl.cpp:2434) and
	// rolls back only when processed is 0 (2634).
	if !rep.Commit {
		t.Error("Commit = false, want true")
	}

	// A missing CALL is checked before the filter (tqslconvert.cpp:1343),
	// so it is an error even out of range, and Abort stops on it.
	_, rep, err = runSign(t, []Credential{cred}, usStation(), []QSO{noCall}, opt)
	var qe *QSOError
	if !errors.As(err, &qe) || !errors.Is(err, ErrInvalidQSO) || qe.Field != "CALL" {
		t.Fatalf("err = %v, want an ErrInvalidQSO QSOError on CALL", err)
	}
	if rep.Commit {
		t.Error("Commit = true after Abort")
	}
}

// Station details with a park added, as location.cpp:880-883 builds them.
const testDetailsPark = "CQZ: 4, GRIDSQUARE: EM10dh, ITUZ: 7, US_COUNTY: Travis, US_PARK: NP04, US_STATE: TX"

func parkStation() Station {
	st := usStation()
	st.Fields["US_PARK"] = "NP04" // TX park, config.xml:7289-7292
	return st
}

func TestSignDupes(t *testing.T) {
	cred := newTestCredential(t)
	serial := strings.ToUpper(hex.EncodeToString(cred.Cert.X509.SerialNumber.Bytes()))
	legacy := testLegacyKey(cred)
	// With US_PARK the sign data, and so the legacy key, changes.
	legacyPark := strings.Replace(testSignData1, "TRAVISTX", "TRAVISNP04TX", 1) + serial
	get := func(k string) string { return "get " + k }
	put := func(k, v string) string { return "put " + k + "=" + v }
	del := func(k string) string { return "del " + k }
	for _, tt := range []struct {
		name      string
		st        Station
		seed      map[string]string
		want      Outcome
		old, new  string
		wantStore map[string]string
		wantCalls []string
	}{
		{
			// Not found under either key: put(dupekey, stnloc)
			// (tqslconvert.cpp:1955-1966).
			name: "a new QSO", st: usStation(), seed: map[string]string{},
			want:      Signed,
			wantStore: map[string]string{testKey1: testDetails},
			wantCalls: []string{get(legacy), get(testKey1), put(testKey1, testDetails)},
		},
		{
			// The station gained US_PARK: the loop over the old fields
			// finds no change (1917-1933), so the old entry is deleted
			// and the QSO is new (1940-1941, 1955-1966).
			name: "c station gains a field", st: parkStation(),
			seed:      map[string]string{testKey1: testDetails},
			want:      Signed,
			wantStore: map[string]string{testKey1: testDetailsPark},
			wantCalls: []string{get(legacyPark), get(testKey1), del(testKey1), put(testKey1, testDetailsPark)},
		},
		{
			// A field in both with a new value: duplicate with both
			// details reported (1924-1937).
			name: "d gridsquare changed", st: usStation(),
			seed: map[string]string{testKey1: strings.Replace(testDetails, "EM10dh", "EM10dg", 1)},
			want: Duplicate,
			old:  strings.Replace(testDetails, "EM10dh", "EM10dg", 1), new: testDetails,
			wantStore: map[string]string{testKey1: strings.Replace(testDetails, "EM10dh", "EM10dg", 1)},
			wantCalls: []string{get(legacy), get(testKey1)},
		},
		{
			// strcasecmp(dupedata, stnloc) == 0: duplicate (1892-1895).
			// All lower case, so the NAME: keys differ too and only the
			// case-insensitive comparison can call it a duplicate; the
			// field loop alone would find no common key and re-sign.
			name: "e case-only difference", st: usStation(),
			seed: map[string]string{testKey1: strings.ToLower(testDetails)},
			want: Duplicate, old: strings.ToLower(testDetails), new: testDetails,
			wantStore: map[string]string{testKey1: strings.ToLower(testDetails)},
			wantCalls: []string{get(legacy), get(testKey1)},
		},
		{
			// The station lost US_PARK. Only old fields are looked up in
			// the new list (1917-1930), and a missing one is not a
			// change, so the QSO is signed again (knowledge.md §6).
			name: "f station loses a field", st: usStation(),
			seed:      map[string]string{testKey1: testDetailsPark},
			want:      Signed,
			wantStore: map[string]string{testKey1: testDetails},
			wantCalls: []string{get(legacy), get(testKey1), del(testKey1), put(testKey1, testDetails)},
		},
		{
			// Legacy key found: duplicate, legacy deleted, current key
			// put, and no details reported (1842-1868).
			name: "g legacy key", st: usStation(),
			seed:      map[string]string{legacy: "whatever"},
			want:      Duplicate,
			wantStore: map[string]string{testKey1: testDetails},
			wantCalls: []string{get(legacy), del(legacy), put(testKey1, testDetails)},
		},
		{
			// An old entry that is only "NAME:" never counts as changed
			// (key != oldstn[i], 1925).
			name: "old field empty", st: usStation(),
			seed:      map[string]string{testKey1: "CQZ: , GRIDSQUARE: EM10dh, ITUZ: 7, US_COUNTY: Travis, US_STATE: TX"},
			want:      Signed,
			wantStore: map[string]string{testKey1: testDetails},
			wantCalls: []string{get(legacy), get(testKey1), del(testKey1), put(testKey1, testDetails)},
		},
		{
			// Spaces are stripped before comparing (1897-1909), so a
			// spacing-only difference is not a change and the QSO is
			// signed again.
			name: "spacing only", st: usStation(),
			seed:      map[string]string{testKey1: "CQZ:4,GRIDSQUARE:EM10dh,ITUZ:7,US_COUNTY:Travis,US_STATE:TX"},
			want:      Signed,
			wantStore: map[string]string{testKey1: testDetails},
			wantCalls: []string{get(legacy), get(testKey1), del(testKey1), put(testKey1, testDetails)},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newMapStore()
			for k, v := range tt.seed {
				store.m[k] = v
			}
			out, rep, _ := runSign(t, []Credential{cred}, tt.st, []QSO{writerQSO("W1AW", 1)}, SignOptions{Dupes: store})
			wantOutcomes(t, rep, tt.want)
			r := rep.Results[0]
			if r.OldDetails != tt.old || r.NewDetails != tt.new {
				t.Errorf("details = %q / %q, want %q / %q", r.OldDetails, r.NewDetails, tt.old, tt.new)
			}
			if !mapsEqual(store.m, tt.wantStore) {
				t.Errorf("store = %v, want %v", store.m, tt.wantStore)
			}
			if !slices.Equal(store.calls, tt.wantCalls) {
				t.Errorf("calls = %q\nwant    %q", store.calls, tt.wantCalls)
			}
			rs := parseGAbbI(t, out)
			wantContacts := 0
			if tt.want == Signed {
				wantContacts = 1
			} else {
				var qe *QSOError
				if !errors.As(r.Err, &qe) || !errors.Is(qe, ErrDuplicate) || qe.Index != 0 {
					t.Errorf("Result.Err = %v, want a QSOError at index 0 wrapping ErrDuplicate", r.Err)
				}
			}
			if n := countType(rs, "tCONTACT"); n != wantContacts {
				t.Errorf("%d tCONTACT records, want %d", n, wantContacts)
			}
		})
	}

	t.Run("b the same QSO twice", func(t *testing.T) {
		store := newMapStore()
		out, rep, err := runSign(t, []Credential{cred}, usStation(),
			[]QSO{writerQSO("W1AW", 1), writerQSO("w1aw ", 1)}, SignOptions{Dupes: store})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		wantOutcomes(t, rep, Signed, Duplicate)
		if r := rep.Results[1]; r.OldDetails != testDetails || r.NewDetails != testDetails {
			t.Errorf("details = %q / %q", r.OldDetails, r.NewDetails)
		}
		if n := countType(parseGAbbI(t, out), "tCONTACT"); n != 1 {
			t.Errorf("%d tCONTACT records, want 1", n)
		}
	})
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func TestSignDupeKeepsPreamble(t *testing.T) {
	// tqsl writes tCERT and tSTATION as they are returned
	// (apps/tqsl.cpp:2363-2373), before signing and the dupe check
	// (tqslconvert.cpp:1820-1849), so a duplicate on a cert not yet seen
	// leaves them in the file.
	cred := newTestCredential(t)
	store := newMapStore()
	store.m[testKey1] = testDetails
	out, rep, err := runSign(t, []Credential{cred}, usStation(),
		[]QSO{writerQSO("W1AW", 1), writerQSO("W1AW", 2)}, SignOptions{Dupes: store})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wantOutcomes(t, rep, Duplicate, Signed)
	rs := parseGAbbI(t, out)
	wantTypes(t, rs, "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT")
	if d, _ := rs[3].get("QSO_DATE"); d != "2026-11-02" {
		t.Errorf("tCONTACT QSO_DATE = %q, want the second QSO", d)
	}

	// Nothing else: the preamble alone, and ErrNoQSOs.
	store = newMapStore()
	store.m[testKey1] = testDetails
	out, _, err = runSign(t, []Credential{cred}, usStation(), []QSO{writerQSO("W1AW", 1)}, SignOptions{Dupes: store})
	if !errors.Is(err, ErrNoQSOs) {
		t.Fatalf("err = %v, want ErrNoQSOs", err)
	}
	wantTypes(t, parseGAbbI(t, out), "TQSL_IDENT", "tCERT", "tSTATION")
}

func TestSignSignFailureKeepsPreamble(t *testing.T) {
	// Signing happens after tCERT and tSTATION were returned
	// (tqslconvert.cpp:1576, 1813-1820), so they stay in the file.
	cred := newTestCredential(t)
	bad := Credential{Cert: cred.Cert, Signer: fakeSigner{
		pub:  cred.Signer.Public(),
		sign: func([]byte) ([]byte, error) { return nil, errTestSigner },
	}}
	out, rep, err := runSign(t, []Credential{bad}, usStation(), []QSO{writerQSO("W1AW", 1)}, SignOptions{})
	if !errors.Is(err, ErrNoQSOs) {
		t.Fatalf("err = %v, want ErrNoQSOs", err)
	}
	wantOutcomes(t, rep, Failed)
	if !errors.Is(rep.Results[0].Err, errTestSigner) {
		t.Errorf("Result.Err = %v, want the signer error", rep.Results[0].Err)
	}
	wantTypes(t, parseGAbbI(t, out), "TQSL_IDENT", "tCERT", "tSTATION")
}

func badQSO() QSO {
	q := writerQSO("W1AW", 3)
	q.Band = "99M" // Invalid BAND, tqslconvert.cpp:1438-1451
	return q
}

func TestSignCompliant(t *testing.T) {
	// Errors and duplicates are reported and skipped
	// (apps/tqsl.cpp:2491-2494); tqsl exits 9 (2644-2645), which is nil
	// with nonzero counts.
	cred := newTestCredential(t)
	out, rep, err := runSign(t, []Credential{cred}, usStation(),
		[]QSO{writerQSO("W1AW", 1), writerQSO("W1AW", 1), badQSO()},
		SignOptions{Action: Compliant, Dupes: newMapStore()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wantOutcomes(t, rep, Signed, Duplicate, Failed)
	if rep.Signed != 1 || rep.Duplicates != 1 || rep.Failed != 1 || rep.OutOfRange != 0 || !rep.Commit {
		t.Errorf("report = %+v", rep)
	}
	var qe *QSOError
	if !errors.As(rep.Results[2].Err, &qe) || qe.Index != 2 || qe.Field != "BAND" || !errors.Is(qe, ErrInvalidQSO) {
		t.Errorf("Results[2].Err = %v, want an ErrInvalidQSO QSOError on BAND at index 2", rep.Results[2].Err)
	}
	wantTypes(t, parseGAbbI(t, out), "TQSL_IDENT", "tCERT", "tSTATION", "tCONTACT")
}

func TestSignCompliantNothingSigned(t *testing.T) {
	// Everything a duplicate: tqsl exits 8 (apps/tqsl.cpp:2642-2643).
	// Commit follows the controller ruling: processed > 0, as tqsl rolls
	// back in SignLogFile only when processed == 0 (2634-2638).
	cred := newTestCredential(t)
	store := newMapStore()
	store.m[testLegacyKey(cred)] = "x"
	_, rep, err := runSign(t, []Credential{cred}, usStation(), []QSO{writerQSO("W1AW", 1)},
		SignOptions{Action: Compliant, Dupes: store})
	if !errors.Is(err, ErrNoQSOs) {
		t.Fatalf("err = %v, want ErrNoQSOs", err)
	}
	if rep.Duplicates != 1 || !rep.Commit {
		t.Errorf("report = %+v, want 1 duplicate and Commit", rep)
	}
	// The legacy entry was migrated (tqslconvert.cpp:1853-1856).
	if !mapsEqual(store.m, map[string]string{testKey1: testDetails}) {
		t.Errorf("store = %v", store.m)
	}
}

func TestSignAbort(t *testing.T) {
	// The first error or duplicate stops the run (apps/tqsl.cpp:2487-2490)
	// and the store is rolled back (2566-2571, 2598-2614).
	cred := newTestCredential(t)

	t.Run("duplicate", func(t *testing.T) {
		store := newMapStore()
		store.m[testKey1] = testDetails
		_, rep, err := runSign(t, []Credential{cred}, usStation(),
			[]QSO{writerQSO("W1AW", 1), writerQSO("W1AW", 2)}, SignOptions{Action: Abort, Dupes: store})
		var qe *QSOError
		if !errors.As(err, &qe) || !errors.Is(err, ErrDuplicate) || qe.Index != 0 {
			t.Fatalf("err = %v, want a QSOError at index 0 wrapping ErrDuplicate", err)
		}
		if rep.Commit || len(rep.Results) != 1 || rep.Duplicates != 1 {
			t.Errorf("report = %+v", rep)
		}
		for _, c := range store.calls {
			if strings.Contains(c, "2026-11-02") {
				t.Errorf("QSO 1 reached the store: %s", c)
			}
		}
	})

	t.Run("bad QSO", func(t *testing.T) {
		_, rep, err := runSign(t, []Credential{cred}, usStation(),
			[]QSO{writerQSO("W1AW", 1), badQSO(), writerQSO("W1AW", 2)}, SignOptions{Action: Abort, Dupes: newMapStore()})
		var qe *QSOError
		if !errors.As(err, &qe) || !errors.Is(err, ErrInvalidQSO) || qe.Index != 1 {
			t.Fatalf("err = %v, want a QSOError at index 1 wrapping ErrInvalidQSO", err)
		}
		if rep.Commit || len(rep.Results) != 2 || rep.Signed != 1 || rep.Failed != 1 {
			t.Errorf("report = %+v", rep)
		}
	})

	t.Run("no certificate", func(t *testing.T) {
		st := usStation()
		st.Call = "W1XYZ"
		_, _, err := runSign(t, []Credential{cred}, st, []QSO{writerQSO("W1AW", 1)}, SignOptions{Action: Abort})
		var qe *QSOError
		if !errors.As(err, &qe) || !errors.Is(err, ErrCertMismatch) || qe.Index != 0 {
			t.Fatalf("err = %v, want a QSOError at index 0 wrapping ErrCertMismatch", err)
		}
	})
}

func identText(t *testing.T, out []byte) string {
	t.Helper()
	rs := parseGAbbI(t, out)
	if len(rs) == 0 || rs[0].Type != "TQSL_IDENT" {
		t.Fatalf("output does not start with TQSL_IDENT: %v", recordTypes(rs))
	}
	v, _ := rs[0].get("TQSL_IDENT")
	return v
}

func TestSignAllNoDupes(t *testing.T) {
	// No duplicates: the first pass stands, with AllowDupes false
	// (apps/tqsl.cpp:2095, 2616-2619 not taken, 2646).
	cred := newTestCredential(t)
	out, rep, err := runSign(t, []Credential{cred}, usStation(),
		[]QSO{writerQSO("W1AW", 1), writerQSO("W1AW", 2)}, SignOptions{Action: All, Dupes: newMapStore(), Ident: testIdent()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !rep.Commit || rep.Signed != 2 {
		t.Errorf("report = %+v", rep)
	}
	if id := identText(t, out); !strings.HasSuffix(id, "AllowDupes: false") {
		t.Errorf("ident = %q", id)
	}
}

func TestSignAllContinuesPastErrors(t *testing.T) {
	// Under All errors are ignored (apps/tqsl.cpp:2491-2494).
	cred := newTestCredential(t)
	out, rep, err := runSign(t, []Credential{cred}, usStation(),
		[]QSO{badQSO(), writerQSO("W1AW", 1)}, SignOptions{Action: All, Dupes: newMapStore()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wantOutcomes(t, rep, Failed, Signed)
	if !rep.Commit {
		t.Error("Commit = false")
	}
	if n := countType(parseGAbbI(t, out), "tCONTACT"); n != 1 {
		t.Errorf("%d tCONTACT records, want 1", n)
	}
}

func TestSignAllWithDupes(t *testing.T) {
	// Duplicates under All: roll back and sign again with allow_dupes
	// (apps/tqsl.cpp:2616-2619, 2712-2727, 2104-2107).
	cred := newTestCredential(t)
	qsos := []QSO{writerQSO("W1AW", 1), writerQSO("W1AW", 2)}
	store := newMapStore()
	store.m[testKey1] = testDetails
	_, rep, err := runSign(t, []Credential{cred}, usStation(), qsos, SignOptions{Action: All, Dupes: store})
	if !errors.Is(err, ErrRestart) {
		t.Fatalf("err = %v, want ErrRestart", err)
	}
	if rep.Commit || rep.Duplicates != 1 || rep.Signed != 1 {
		t.Errorf("report = %+v", rep)
	}

	spy := newMapStore()
	out, rep, err := runSign(t, []Credential{cred}, usStation(), qsos,
		SignOptions{Action: All, Dupes: spy, Restart: true, Ident: testIdent()})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if len(spy.calls) != 0 {
		t.Errorf("restart made store calls: %v", spy.calls) // tqslconvert.cpp:1824
	}
	if !rep.Commit || rep.Signed != 2 {
		t.Errorf("restart report = %+v", rep)
	}
	if id := identText(t, out); !strings.HasSuffix(id, "AllowDupes: true") {
		t.Errorf("ident = %q", id)
	}
	if n := countType(parseGAbbI(t, out), "tCONTACT"); n != 2 {
		t.Errorf("%d tCONTACT records, want 2", n)
	}

	t.Run("restart suppresses errors", func(t *testing.T) {
		_, rep, err := runSign(t, []Credential{cred}, usStation(), []QSO{badQSO(), writerQSO("W1AW", 1)},
			SignOptions{Action: Abort, Restart: true})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		wantOutcomes(t, rep, Failed, Signed)
	})
}

func TestSignAllRestartAfterFullPass(t *testing.T) {
	// The restart decision comes after the whole log was read
	// (apps/tqsl.cpp:2338-2526, then 2616), so QSO 1 still reaches the
	// store after the duplicate at index 0.
	cred := newTestCredential(t)
	store := newMapStore()
	store.m[testKey1] = testDetails
	const key2 = "KF0TST20MW1AW14.250SSB2026-11-0215:30:00Z"
	_, rep, err := runSign(t, []Credential{cred}, usStation(),
		[]QSO{writerQSO("W1AW", 1), writerQSO("W1AW", 2)}, SignOptions{Action: All, Dupes: store})
	if !errors.Is(err, ErrRestart) {
		t.Fatalf("err = %v, want ErrRestart", err)
	}
	wantOutcomes(t, rep, Duplicate, Signed)
	if !slices.Contains(store.calls, "put "+key2+"="+testDetails) {
		t.Errorf("calls = %q, want the second QSO's put", store.calls)
	}
}

func TestSignEmpty(t *testing.T) {
	// numrecs == 0 gives exit 8 (apps/tqsl.cpp:2642-2643); processed == 0
	// rolls back (2634-2638).
	cred := newTestCredential(t)
	for _, seq := range []func(func(QSO) bool){slices.Values([]QSO(nil)), nil} {
		var buf bytes.Buffer
		store := newMapStore()
		rep, err := Sign(context.Background(), &buf, loadTestConfig(t, "config-11.35.xml"), []Credential{cred},
			usStation(), seq, SignOptions{Dupes: store})
		if !errors.Is(err, ErrNoQSOs) {
			t.Fatalf("err = %v, want ErrNoQSOs", err)
		}
		if buf.Len() != 0 || rep.Commit || len(store.calls) != 0 {
			t.Errorf("wrote %d bytes, report %+v, calls %v", buf.Len(), rep, store.calls)
		}
	}
}

var errTestStore = errors.New("test store failure")

func TestSignStoreError(t *testing.T) {
	// A database error stops the run and rolls back
	// (tqslconvert.cpp:1857-1866, 1869-1879, 1942-1952, 1957-1965;
	// apps/tqsl.cpp:2508-2510).
	cred := newTestCredential(t)
	for _, tt := range []struct {
		name string
		set  func(*mapStore)
		st   Station
	}{
		{"get", func(s *mapStore) { s.getErr = errTestStore }, usStation()},
		{"put", func(s *mapStore) { s.putErr = errTestStore }, usStation()},
		{"delete", func(s *mapStore) { s.m[testKey1] = testDetails; s.delErr = errTestStore }, parkStation()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newMapStore()
			tt.set(store)
			_, rep, err := runSign(t, []Credential{cred}, tt.st, []QSO{writerQSO("W1AW", 1)},
				SignOptions{Action: Compliant, Dupes: store})
			if !errors.Is(err, errTestStore) {
				t.Fatalf("err = %v, want the store error", err)
			}
			if rep.Commit {
				t.Error("Commit = true after a store error")
			}
		})
	}
}

func TestSignWriteError(t *testing.T) {
	// A write error aborts and rolls back (apps/tqsl.cpp:2365-2372,
	// 2546-2560).
	fw := &failWriter{n: 1}
	rep, err := Sign(context.Background(), fw, loadTestConfig(t, "config-11.35.xml"), []Credential{newTestCredential(t)},
		usStation(), slices.Values([]QSO{writerQSO("W1AW", 1)}), SignOptions{})
	if !errors.Is(err, errTestWrite) {
		t.Fatalf("err = %v, want the write error", err)
	}
	if rep.Commit {
		t.Error("Commit = true after a write error")
	}
}

func TestSignContextCancel(t *testing.T) {
	cred := newTestCredential(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newMapStore()
	seq := func(yield func(QSO) bool) {
		if !yield(writerQSO("W1AW", 1)) {
			return
		}
		cancel()
		yield(writerQSO("W1AW", 2))
	}
	var buf bytes.Buffer
	rep, err := Sign(ctx, &buf, loadTestConfig(t, "config-11.35.xml"), []Credential{cred}, usStation(), seq,
		SignOptions{Dupes: store})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if rep.Commit || len(rep.Results) != 1 {
		t.Errorf("report = %+v", rep)
	}
	for _, c := range store.calls {
		if strings.Contains(c, "2026-11-02") {
			t.Errorf("cancelled QSO reached the store: %s", c)
		}
	}
}

func TestSignNilArguments(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	qs := slices.Values([]QSO{writerQSO("W1AW", 1)})
	if _, err := Sign(context.Background(), &bytes.Buffer{}, nil, nil, usStation(), qs, SignOptions{}); !errors.Is(err, ErrConfig) {
		t.Errorf("nil cfg: err = %v, want ErrConfig", err)
	}
	if _, err := Sign(context.Background(), nil, cfg, nil, usStation(), qs, SignOptions{}); err == nil {
		t.Error("nil writer: no error")
	}
	// A nil Credential is never chosen.
	_, rep, _ := runSign(t, []Credential{{}}, usStation(), []QSO{writerQSO("W1AW", 1)}, SignOptions{})
	if !errors.Is(rep.Results[0].Err, ErrCertMismatch) {
		t.Errorf("nil credential: Result.Err = %v", rep.Results[0].Err)
	}
}

func TestOnelineName(t *testing.T) {
	// X509_NAME_oneline: "/SN=value" per entry, bytes outside ' '..'~'
	// as \xHH.
	ca, _ := newARRLNamedCA(t)
	const want = "/C=US/ST=CT/L=Newington/O=American Radio Relay League/OU=Logbook of the World/" +
		"CN=Logbook of the World Production CA/DC=arrl.org/emailAddress=lotw@arrl.org"
	if got := onelineName(ca.RawSubject); got != want {
		t.Errorf("onelineName = %q\nwant          %q", got, want)
	}
	raw, _ := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{1, 2, 3}, Value: "a\u00e9"}}})
	if got := onelineName(raw); got != `/1.2.3=a\xC3\xA9` {
		t.Errorf("onelineName = %q", got)
	}
	if got := onelineName([]byte{0xff}); got != "" {
		t.Errorf("onelineName(garbage) = %q, want empty", got)
	}
}
