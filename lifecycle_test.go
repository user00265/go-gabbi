package gabbi_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // TrustedQSL signs requests and QSOs with SHA-1.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gabbi "github.com/user00265/go-gabbi"
	"github.com/user00265/go-gabbi/service"
)

func TestLocalCALifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	configXML, err := os.ReadFile("testdata/config-11.35.xml")
	if err != nil {
		t.Fatalf("read config xml: %v", err)
	}
	cfg, err := gabbi.ParseConfig(bytes.NewReader(configXML))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	// Build a disposable in-memory 3-tier CA: Root CA -> Intermediate CA.
	rootKey := generateRSAKey(t, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Local Test CA"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Local Test Root CA"},
			},
		},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	rootCert := issueCert(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	interKey := generateRSAKey(t, 2048)
	interSubject := pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Local Test CA"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Local Test Production CA"},
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte("ca@example.test")}},
		},
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               interSubject,
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          []byte{5, 6, 7, 8},
	}
	interCert := issueCert(t, interTemplate, rootCert, &interKey.PublicKey, rootKey)

	const (
		interIssuerOneline = "/C=US/O=Local Test CA/CN=Local Test Production CA/emailAddress=ca@example.test"
		interIssuerARRL    = "/C=US/O=Local Test CA/CN=Local Test Production CA/Email=ca@example.test"
		testCallsign       = "KF0TST"
		testName           = "Test Operator"
		testEmail          = "kf0tst@example.test"
		testUserAgent      = "go-gabbi-lifecycle-test"
	)

	// Local httptest server for uploading .tq5 and .tq8 payloads.
	var (
		uploadMu           sync.Mutex
		wantUploadBytes    []byte
		wantUploadFilename string
		uploadResponse     string
	)
	setUploadExpectation := func(wantBytes []byte, wantFilename, resp string) {
		uploadMu.Lock()
		defer uploadMu.Unlock()
		wantUploadBytes = wantBytes
		wantUploadFilename = wantFilename
		uploadResponse = resp
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadMu.Lock()
		expectedBytes := wantUploadBytes
		expectedFilename := wantUploadFilename
		respBody := uploadResponse
		uploadMu.Unlock()

		if r.Method != http.MethodPost || r.URL.Path != "/lotw/upload" {
			t.Errorf("unexpected upload request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if gotUA := r.UserAgent(); gotUA != testUserAgent {
			t.Errorf("User-Agent = %q, want %q", gotUA, testUserAgent)
		}
		mr, err := r.MultipartReader()
		if err != nil {
			t.Errorf("MultipartReader: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		part, err := mr.NextPart()
		if err != nil {
			t.Errorf("NextPart: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if part.FormName() != "upfile" {
			t.Errorf("form field = %q, want upfile", part.FormName())
		}
		if gotFilename := part.FileName(); gotFilename != expectedFilename {
			t.Errorf("filename = %q, want %q", gotFilename, expectedFilename)
		}
		got, err := io.ReadAll(part)
		if err != nil {
			t.Errorf("read upload part: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !bytes.Equal(got, expectedBytes) {
			t.Errorf("uploaded %d bytes, want exact match with %d expected bytes", len(got), len(expectedBytes))
		}
		_, _ = io.WriteString(w, respBody)
	}))
	defer srv.Close()

	client := service.Client{
		HTTP:      srv.Client(),
		BaseURL:   srv.URL,
		UserAgent: testUserAgent,
	}

	// Step 1: New .tq5 -> Upload -> CSR verification -> Sign User Cert 1 -> .tq6 -> VerifyChain -> Pair -> PKCS#12 round-trip.
	qsoStart := gabbi.Date{Year: 2020, Month: time.January, Day: 1}
	qsoEnd := gabbi.Date{Year: 2035, Month: time.December, Day: 31}
	baseReq := gabbi.Request{
		Kind:         gabbi.NewRequest,
		Callsign:     testCallsign,
		Name:         testName,
		Email:        testEmail,
		Address1:     "123 Main St",
		City:         "Austin",
		State:        "TX",
		Postal:       "78701",
		Country:      "USA",
		DXCC:         291,
		QSONotBefore: qsoStart,
		QSONotAfter:  qsoEnd,
	}
	tq5New, key1, err := gabbi.BuildRequest(cfg, baseReq, gabbi.Ident{Program: "LifecycleTest", Version: "1.0.0"}, rand.Reader)
	if err != nil {
		t.Fatalf("BuildRequest(NewRequest): %v", err)
	}
	clearRSAKey(t, key1)

	setUploadExpectation(tq5New, "kf0tst-new.tq5", "<!-- .UPL. accepted --><!-- .UPLMESSAGE. Your certificate request has been received -->")
	res, err := client.Upload(ctx, bytes.NewReader(tq5New), "kf0tst-new.tq5")
	if err != nil {
		t.Fatalf("Upload(.tq5): %v", err)
	}
	if res.Message != "Your certificate request has been received" {
		t.Fatalf("Upload(.tq5) message = %q, want %q", res.Message, "Your certificate request has been received")
	}

	fields1 := parseTQ5Fields(t, tq5New)
	if _, ok := fields1["TQSL_CRQ_NEW"]; !ok {
		t.Fatal("missing TQSL_CRQ_NEW marker in new .tq5")
	}
	wantTQ5Fields := map[string]string{
		"TQSL_IDENT":              "LifecycleTest: 1.0.0, Lib: V1.0.0, Config: 11.35",
		"TQSL_CRQ_DXCC_ENTITY":    "291",
		"TQSL_CRQ_QSO_NOT_BEFORE": "2020-01-01",
		"TQSL_CRQ_QSO_NOT_AFTER":  "2035-12-31",
		"TQSL_CRQ_NAME":           testName,
		"TQSL_CRQ_EMAIL":          testEmail,
		"TQSL_CRQ_ADDRESS2":       "",
	}
	for name, want := range wantTQ5Fields {
		got, ok := fields1[name]
		if !ok {
			t.Errorf("new .tq5 missing field %s", name)
		} else if got != want {
			t.Errorf("new .tq5 %s = %q, want %q", name, got, want)
		}
	}
	csr1, _ := parseAndVerifyCSR(t, fields1["TQSL_CRQ_REQUEST"], testCallsign, testName, testEmail)

	userCert1Template := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		RawSubject:   csr1.RawSubject,
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(3, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: arrlOID(2), Value: []byte("2020-01-01")},
			{Id: arrlOID(3), Value: []byte("2035-12-31")},
			{Id: arrlOID(4), Value: []byte("291")},
		},
	}
	userCert1 := issueCert(t, userCert1Template, interCert, csr1.PublicKey, interKey)

	tq6Bytes1 := buildGzippedTQ6(t, rootCert, interCert, userCert1, configXML)
	tq6, err := gabbi.ParseTQ6(bytes.NewReader(tq6Bytes1))
	if err != nil {
		t.Fatalf("ParseTQ6(1): %v", err)
	}
	if len(tq6.Roots) != 1 || len(tq6.CAs) != 1 || len(tq6.Users) != 1 || tq6.Config == nil {
		t.Fatalf("ParseTQ6(1) populated Roots=%d CAs=%d Users=%d Config=%v", len(tq6.Roots), len(tq6.CAs), len(tq6.Users), tq6.Config != nil)
	}

	chain1, err := gabbi.VerifyChain(tq6.Users[0], tq6.CAs, tq6.Roots, gabbi.VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("VerifyChain(1): %v", err)
	}
	if len(chain1) != 3 {
		t.Fatalf("VerifyChain(1) len = %d, want 3", len(chain1))
	}

	cred1, err := gabbi.Pair(tq6.Users, key1)
	if err != nil {
		t.Fatalf("Pair(1): %v", err)
	}

	for _, password := range []string{"", "testpass"} {
		p12, err := gabbi.ExportPKCS12(cred1, []*x509.Certificate{tq6.CAs[0], tq6.Roots[0]}, password)
		if err != nil {
			t.Fatalf("ExportPKCS12(password=%q): %v", password, err)
		}
		loadedCred, loadedChain, err := gabbi.LoadPKCS12(p12, password)
		if err != nil {
			t.Fatalf("LoadPKCS12(password=%q): %v", password, err)
		}
		if rk, ok := loadedCred.Signer.(*rsa.PrivateKey); ok {
			clearRSAKey(t, rk)
		}
		if !bytes.Equal(loadedCred.Cert.X509.Raw, userCert1.Raw) {
			t.Errorf("LoadPKCS12(password=%q) certificate DER mismatch", password)
		}
		if loadedCred.Cert.Callsign != testCallsign {
			t.Errorf("LoadPKCS12(password=%q) callsign = %q, want %q", password, loadedCred.Cert.Callsign, testCallsign)
		}
		if loadedCred.Cert.DXCC != 291 {
			t.Errorf("LoadPKCS12(password=%q) DXCC = %d, want 291", password, loadedCred.Cert.DXCC)
		}
		if len(loadedChain) != 2 {
			t.Errorf("LoadPKCS12(password=%q) chain len = %d, want 2", password, len(loadedChain))
		}
		if password != "" {
			if _, _, err := gabbi.LoadPKCS12(p12, "wrongpass"); !errors.Is(err, gabbi.ErrPassword) {
				t.Errorf("LoadPKCS12(wrong password) err = %v, want ErrPassword", err)
			}
		}
	}

	// Step 2: Expired Intermediate CA with a still-valid leaf.
	shortInterKey := generateRSAKey(t, 2048)
	shortInterTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Local Test CA"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Local Short-Lived CA"},
			},
		},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          []byte{9, 10, 11, 12},
	}
	shortInterCert := issueCert(t, shortInterTemplate, rootCert, &shortInterKey.PublicKey, rootKey)

	longLeafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2001),
		RawSubject:   csr1.RawSubject,
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(3, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: arrlOID(2), Value: []byte("2020-01-01")},
			{Id: arrlOID(3), Value: []byte("2035-12-31")},
			{Id: arrlOID(4), Value: []byte("291")},
		},
	}
	longLeafCert := issueCert(t, longLeafTemplate, shortInterCert, csr1.PublicKey, shortInterKey)

	between := now.AddDate(2, 0, 0)
	if _, err := gabbi.VerifyChain(longLeafCert, []*x509.Certificate{shortInterCert}, []*x509.Certificate{rootCert}, gabbi.VerifyOptions{Now: between}); !errors.Is(err, gabbi.ErrChain) {
		t.Fatalf("VerifyChain(strict expired CA) err = %v, want ErrChain", err)
	}
	relaxedChain, err := gabbi.VerifyChain(longLeafCert, []*x509.Certificate{shortInterCert}, []*x509.Certificate{rootCert}, gabbi.VerifyOptions{Now: between, AllowExpiredCA: true})
	if err != nil {
		t.Fatalf("VerifyChain(AllowExpiredCA) err = %v", err)
	}
	if len(relaxedChain) != 3 {
		t.Fatalf("VerifyChain(AllowExpiredCA) len = %d, want 3", len(relaxedChain))
	}

	// Step 3: Renewal .tq5 signed by Credential 1 + User Cert 2 with Supersession (.5).
	renewReq := baseReq
	renewReq.Kind = gabbi.Renewal
	renewReq.Signer = &cred1
	tq5Renew, key2, err := gabbi.BuildRequest(cfg, renewReq, gabbi.Ident{Program: "LifecycleTest", Version: "1.0.0"}, rand.Reader)
	if err != nil {
		t.Fatalf("BuildRequest(Renewal): %v", err)
	}
	clearRSAKey(t, key2)

	fields2 := parseTQ5Fields(t, tq5Renew)
	if _, ok := fields2["TQSL_CRQ_RENEWAL"]; !ok {
		t.Fatal("missing TQSL_CRQ_RENEWAL marker in renewal .tq5")
	}
	csr2, csr2DER := parseAndVerifyCSR(t, fields2["TQSL_CRQ_REQUEST"], testCallsign, testName, testEmail)

	sigBytes, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fields2["TQSL_CRQ_SIGNATURE"], "\n", ""))
	if err != nil {
		t.Fatalf("decode TQSL_CRQ_SIGNATURE: %v", err)
	}
	csrDigest := sha1.Sum(csr2DER)
	if err := rsa.VerifyPKCS1v15(&key1.PublicKey, crypto.SHA1, csrDigest[:], sigBytes); err != nil {
		t.Fatalf("verify TQSL_CRQ_SIGNATURE: %v", err)
	}
	if got := fields2["TQSL_CRQ_SIGNATURE_CERT_ISSUER"]; got != interIssuerOneline {
		t.Fatalf("TQSL_CRQ_SIGNATURE_CERT_ISSUER = %q, want %q", got, interIssuerOneline)
	}
	if got := fields2["TQSL_CRQ_SIGNATURE_CERT_SERIAL"]; got != "1001" {
		t.Fatalf("TQSL_CRQ_SIGNATURE_CERT_SERIAL = %q, want %q", got, "1001")
	}

	userCert2Template := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		RawSubject:   csr2.RawSubject,
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(3, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: arrlOID(2), Value: []byte("2020-01-01")},
			{Id: arrlOID(3), Value: []byte("2035-12-31")},
			{Id: arrlOID(4), Value: []byte("291")},
			{Id: arrlOID(5), Value: []byte(interIssuerARRL + ";1001")},
		},
	}
	userCert2 := issueCert(t, userCert2Template, interCert, csr2.PublicKey, interKey)

	tq6Bytes2 := buildGzippedTQ6(t, rootCert, interCert, userCert2, nil)
	tq6Renew, err := gabbi.ParseTQ6(bytes.NewReader(tq6Bytes2))
	if err != nil {
		t.Fatalf("ParseTQ6(2): %v", err)
	}
	if _, err := gabbi.VerifyChain(tq6Renew.Users[0], tq6Renew.CAs, tq6Renew.Roots, gabbi.VerifyOptions{Now: now}); err != nil {
		t.Fatalf("VerifyChain(2): %v", err)
	}
	cred2, err := gabbi.Pair(tq6Renew.Users, key2)
	if err != nil {
		t.Fatalf("Pair(2): %v", err)
	}
	if cred2.Cert.Supersedes == nil || cred2.Cert.Supersedes.Serial.Cmp(big.NewInt(1001)) != 0 {
		t.Fatalf("cred2.Cert.Supersedes = %+v, want serial 1001", cred2.Cert.Supersedes)
	}

	// Step 4: Sign .tq8 with [cred1, cred2] (superseded cred1 first), verify emitted tCERT and tCONTACT signatures, and upload.
	station := gabbi.Station{
		Call:       testCallsign,
		DXCC:       291,
		GridSquare: "EM10dh",
		ITUZ:       7,
		CQZ:        4,
		Fields: map[string]string{
			"US_STATE":  "TX",
			"US_COUNTY": "Travis",
		},
	}
	qsos := []gabbi.QSO{
		{
			Call: "W1AW",
			Band: "20M",
			Mode: "SSB",
			Freq: "14.250",
			Time: time.Date(2026, time.November, 1, 15, 30, 0, 0, time.UTC),
		},
		{
			Call:    "K1JT",
			Band:    "40M",
			Mode:    "MFSK",
			Submode: "FT4",
			Freq:    "7.0475",
			Time:    time.Date(2026, time.November, 2, 18, 45, 10, 0, time.UTC),
		},
	}

	var tq8Buf bytes.Buffer
	zw := gzip.NewWriter(&tq8Buf)
	rep, err := gabbi.Sign(ctx, zw, cfg, []gabbi.Credential{cred1, cred2}, station, slices.Values(qsos), gabbi.SignOptions{
		Action: gabbi.Abort,
		Now:    now,
		Ident:  gabbi.Ident{Program: "LifecycleTest", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if rep.Signed != 2 || !rep.Commit {
		t.Fatalf("Sign report: Signed=%d Commit=%v, want Signed=2 Commit=true", rep.Signed, rep.Commit)
	}

	zr, err := gzip.NewReader(bytes.NewReader(tq8Buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	plainTQ8, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompress .tq8: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("gzip reader close: %v", err)
	}

	ident, recs := parseGABBI(t, plainTQ8)
	const wantTQ8Ident = "LifecycleTest 1.0.0 Lib: V1.0.0 Config: V11.35 AllowDupes: false"
	if ident != wantTQ8Ident {
		t.Errorf("TQSL_IDENT = %q, want %q", ident, wantTQ8Ident)
	}
	var certRecs, stationRecs, contactRecs []map[string]string
	for _, rec := range recs {
		switch rec["Rec_Type"] {
		case "tCERT":
			certRecs = append(certRecs, rec)
		case "tSTATION":
			stationRecs = append(stationRecs, rec)
		case "tCONTACT":
			contactRecs = append(contactRecs, rec)
		}
	}
	if len(certRecs) != 1 {
		t.Fatalf("tCERT count = %d, want 1", len(certRecs))
	}
	if got := certRecs[0]["CERT_UID"]; got != "1" {
		t.Errorf("tCERT CERT_UID = %q, want %q", got, "1")
	}
	emittedDER, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(certRecs[0]["CERTIFICATE"], "\n", ""))
	if err != nil {
		t.Fatalf("decode tCERT CERTIFICATE: %v", err)
	}
	emittedCert, err := x509.ParseCertificate(emittedDER)
	if err != nil {
		t.Fatalf("parse tCERT certificate: %v", err)
	}
	if !bytes.Equal(emittedCert.Raw, userCert2.Raw) {
		t.Fatal("emitted tCERT DER does not match User Cert 2")
	}
	if emittedCert.SerialNumber.Cmp(big.NewInt(1002)) != 0 {
		t.Fatalf("emitted tCERT serial = %s, want 1002 (non-superseded cert)", emittedCert.SerialNumber)
	}
	emittedPub, ok := emittedCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("emitted tCERT public key type = %T, want *rsa.PublicKey", emittedCert.PublicKey)
	}

	if len(stationRecs) != 1 {
		t.Fatalf("tSTATION count = %d, want 1", len(stationRecs))
	}
	wantStationFields := map[string]string{
		"STATION_UID": "1",
		"CERT_UID":    "1",
		"CALL":        testCallsign,
		"DXCC":        "291",
		"GRIDSQUARE":  "EM10dh",
		"ITUZ":        "7",
		"CQZ":         "4",
		"US_STATE":    "TX",
		"US_COUNTY":   "Travis",
	}
	for name, want := range wantStationFields {
		if got := stationRecs[0][name]; got != want {
			t.Errorf("tSTATION %s = %q, want %q", name, got, want)
		}
	}

	if len(contactRecs) != 2 {
		t.Fatalf("tCONTACT count = %d, want 2", len(contactRecs))
	}
	// LOTW 2.0 sigspec alphabetical order:
	// tSTATION: CQZ, GRIDSQUARE, ITUZ, US_COUNTY, US_STATE -> "4EM10DH7TRAVISTX"
	// tCONTACT: BAND, CALL, FREQ, MODE, QSO_DATE, QSO_TIME
	wantContacts := []map[string]string{
		{
			"STATION_UID": "1",
			"CALL":        "W1AW",
			"BAND":        "20M",
			"MODE":        "SSB",
			"FREQ":        "14.250",
			"QSO_DATE":    "2026-11-01",
			"QSO_TIME":    "15:30:00Z",
			"SIGNDATA":    "4EM10DH7TRAVISTX20MW1AW14.250SSB2026-11-0115:30:00Z",
		},
		{
			"STATION_UID": "1",
			"CALL":        "K1JT",
			"BAND":        "40M",
			"MODE":        "FT4",
			"FREQ":        "7.0475",
			"QSO_DATE":    "2026-11-02",
			"QSO_TIME":    "18:45:10Z",
			"SIGNDATA":    "4EM10DH7TRAVISTX40MK1JT7.0475FT42026-11-0218:45:10Z",
		},
	}
	for i, rec := range contactRecs {
		for name, want := range wantContacts[i] {
			if got := rec[name]; got != want {
				t.Errorf("tCONTACT[%d] %s = %q, want %q", i, name, got, want)
			}
		}
		sigB64 := rec["SIGN_LOTW_V2.0"]
		if sigB64 == "" {
			t.Fatalf("tCONTACT[%d] missing SIGN_LOTW_V2.0", i)
		}
		sig, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(sigB64, "\n", ""))
		if err != nil {
			t.Fatalf("tCONTACT[%d] decode signature: %v", i, err)
		}
		digest := sha1.Sum([]byte(wantContacts[i]["SIGNDATA"]))
		if err := rsa.VerifyPKCS1v15(emittedPub, crypto.SHA1, digest[:], sig); err != nil {
			t.Fatalf("tCONTACT[%d] verify signature against User Cert 2: %v", i, err)
		}
	}

	// Upload the gzipped .tq8 and verify exact bytes and accepted message.
	tq8Bytes := tq8Buf.Bytes()
	setUploadExpectation(tq8Bytes, "kf0tst.tq8", "<!-- .UPL. accepted --><!-- .UPLMESSAGE. File queued for processing -->")
	res, err = client.Upload(ctx, bytes.NewReader(tq8Bytes), "kf0tst.tq8")
	if err != nil {
		t.Fatalf("Upload(.tq8): %v", err)
	}
	if res.Message != "File queued for processing" {
		t.Fatalf("Upload(.tq8) message = %q, want %q", res.Message, "File queued for processing")
	}
}

func arrlOID(n int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, n}
}

func generateRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	clearRSAKey(t, key)
	return key
}

func clearRSAKey(t *testing.T, key *rsa.PrivateKey) {
	t.Helper()
	if key == nil {
		return
	}
	t.Cleanup(func() {
		// Best effort: clear accessible private integers. Go and crypto packages
		// can retain internal copies that cannot be explicitly erased.
		clearInt := func(n *big.Int) {
			if n != nil {
				clear(n.Bits())
				n.SetInt64(0)
			}
		}
		clearInt(key.D)
		for _, prime := range key.Primes {
			clearInt(prime)
		}
		clearInt(key.Precomputed.Dp)
		clearInt(key.Precomputed.Dq)
		clearInt(key.Precomputed.Qinv)
		*key = rsa.PrivateKey{}
	})
}

func issueCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate(serial=%v): %v", tmpl.SerialNumber, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(serial=%v): %v", tmpl.SerialNumber, err)
	}
	return cert
}

func buildGzippedTQ6(t *testing.T, root, inter, user *x509.Certificate, configXML []byte) []byte {
	t.Helper()
	pemCert := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	var xmlBuf bytes.Buffer
	xmlBuf.WriteString("<tqsldata>\n<tqslcerts>\n")
	xmlBuf.WriteString("<rootcert>\n" + pemCert(root) + "</rootcert>\n")
	xmlBuf.WriteString("<cacert>\n" + pemCert(inter) + "</cacert>\n")
	xmlBuf.WriteString("<usercert>\n" + pemCert(user) + "</usercert>\n")
	xmlBuf.WriteString("</tqslcerts>\n")
	if len(configXML) > 0 {
		xmlBuf.Write(configXML)
		xmlBuf.WriteByte('\n')
	}
	xmlBuf.WriteString("</tqsldata>\n")

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	if _, err := zw.Write(xmlBuf.Bytes()); err != nil {
		t.Fatalf("gzip write tq6: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close tq6: %v", err)
	}
	return gzBuf.Bytes()
}

func parseTQ5Fields(t *testing.T, data []byte) map[string]string {
	t.Helper()
	const prefix = "\ntQSL certificate request\n\n<eoh>\n\n"
	if !bytes.HasPrefix(data, []byte(prefix)) {
		t.Fatal("missing .tq5 header")
	}
	s := string(data[len(prefix):])
	out := map[string]string{}
	sawEOR := false
	for len(s) > 0 {
		if s[0] != '<' {
			t.Fatalf("unexpected .tq5 token: %q", s)
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			t.Fatal("unterminated .tq5 tag")
		}
		name, sizeStr, sized := strings.Cut(s[1:end], ":")
		n := 0
		if sized {
			var err error
			n, err = strconv.Atoi(sizeStr)
			if err != nil || n < 0 {
				t.Fatalf("invalid .tq5 length %q for %s", sizeStr, name)
			}
		}
		s = s[end+1:]
		if len(s) < n+2 || s[n:n+2] != "\n\n" {
			t.Fatalf("bad length or terminator for .tq5 field %s", name)
		}
		val := s[:n]
		s = s[n+2:]
		if name == "eor" {
			if len(s) != 0 {
				t.Fatalf("trailing data after <eor> in .tq5: %q", s)
			}
			sawEOR = true
			break
		}
		out[name] = val
	}
	if !sawEOR {
		t.Fatal("missing <eor> in .tq5")
	}
	return out
}

func parseAndVerifyCSR(t *testing.T, pemText, wantCall, wantName, wantEmail string) (*x509.CertificateRequest, []byte) {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("invalid CSR PEM block: %v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR CheckSignature: %v", err)
	}
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("CSR public key type = %T, want *rsa.PublicKey", csr.PublicKey)
	}
	if bits := pub.N.BitLen(); bits != 1024 {
		t.Errorf("CSR RSA key bits = %d, want 1024", bits)
	}
	if csr.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("CSR SignatureAlgorithm = %v, want %v", csr.SignatureAlgorithm, x509.SHA256WithRSA)
	}
	if len(csr.Extensions) != 0 {
		t.Errorf("CSR Extensions count = %d, want 0", len(csr.Extensions))
	}
	var gotCall, gotName, gotEmail string
	for _, n := range csr.Subject.Names {
		switch n.Type.String() {
		case arrlOID(1).String():
			gotCall, _ = n.Value.(string)
		case "2.5.4.3":
			gotName, _ = n.Value.(string)
		case "1.2.840.113549.1.9.1":
			gotEmail, _ = n.Value.(string)
		}
	}
	if gotCall != wantCall {
		t.Errorf("CSR AROcallsign = %q, want %q", gotCall, wantCall)
	}
	if gotName != wantName {
		t.Errorf("CSR CN = %q, want %q", gotName, wantName)
	}
	if gotEmail != wantEmail {
		t.Errorf("CSR emailAddress = %q, want %q", gotEmail, wantEmail)
	}
	return csr, block.Bytes
}

func parseGABBI(t *testing.T, data []byte) (string, []map[string]string) {
	t.Helper()
	s := string(data)
	var ident string
	var sawIdent bool
	var records []map[string]string
	cur := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, "\r\n")
		if len(s) == 0 {
			break
		}
		if s[0] != '<' {
			t.Fatalf("unexpected GAbbI byte %q at %q", s[0], s[:min(len(s), 40)])
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			t.Fatal("unterminated GAbbI tag")
		}
		tag := s[1:end]
		s = s[end+1:]
		if tag == "eor" {
			records = append(records, cur)
			cur = map[string]string{}
			continue
		}
		parts := strings.Split(tag, ":")
		name := parts[0]
		n := 0
		if len(parts) >= 2 {
			var err error
			n, err = strconv.Atoi(parts[1])
			if err != nil || n < 0 {
				t.Fatalf("invalid GAbbI field length in <%s>", tag)
			}
		}
		if len(s) < n {
			t.Fatalf("truncated GAbbI value for %s", name)
		}
		val := s[:n]
		s = s[n:]
		if name == "TQSL_IDENT" {
			if sawIdent {
				t.Fatal("duplicate TQSL_IDENT in GAbbI")
			}
			ident = val
			sawIdent = true
			continue
		}
		cur[name] = val
	}
	if !sawIdent || ident == "" {
		t.Fatal("missing TQSL_IDENT in GAbbI")
	}
	if len(cur) != 0 {
		t.Fatalf("trailing fields after final <eor> in GAbbI: %v", cur)
	}
	return ident, records
}
