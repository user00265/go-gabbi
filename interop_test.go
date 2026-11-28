package gabbi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const interopDirEnv = "GABBI_INTEROP_DIR"

var interopStation = Station{
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

func interopQSOs() []QSO {
	return []QSO{
		{
			Call: "W1AW",
			Band: "20M",
			Mode: "CW",
			Freq: "14.250",
			Time: time.Date(2026, time.November, 1, 15, 30, 0, 0, time.UTC),
		},
		{
			Call:    "K1ABC",
			Band:    "40M",
			Mode:    "MFSK",
			Submode: "FT4",
			Freq:    "7.0475",
			Time:    time.Date(2026, time.November, 2, 16, 0, 0, 0, time.UTC),
		},
	}
}

func requireInteropDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv(interopDirEnv)
	if dir == "" {
		t.Skip("set GABBI_INTEROP_DIR or run 'just interop'")
	}
	return dir
}

// clearRSAKey clears accessible RSA private integers best-effort.
func clearRSAKey(k *rsa.PrivateKey) {
	if k == nil {
		return
	}
	clearBig := func(n *big.Int) {
		if n == nil {
			return
		}
		clear(n.Bits())
		n.SetInt64(0)
	}
	clearBig(k.D)
	for _, p := range k.Primes {
		clearBig(p)
	}
	clearBig(k.Precomputed.Dp)
	clearBig(k.Precomputed.Dq)
	clearBig(k.Precomputed.Qinv)
}

func newInteropCA(t *testing.T, subject pkix.Name, serial int64, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := newTestKeyBits(t, 2048)
	t.Cleanup(func() { clearRSAKey(key) })

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               subject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create CA %q: %v", subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA %q: %v", subject.CommonName, err)
	}
	return cert, key
}

func newInteropUserCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, serial int64, supersedes string) (Credential, *rsa.PrivateKey) {
	t.Helper()
	key := newTestKey(t)
	t.Cleanup(func() { clearRSAKey(key) })

	subject := pkix.Name{
		CommonName: "Interop Test Operator",
		ExtraNames: []pkix.AttributeTypeAndValue{{
			Type:  testOIDCallsign,
			Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("KF0TST")},
		}},
	}
	exts := []pkix.Extension{
		{Id: testOIDQSONotBefore, Value: []byte("2020-01-01")},
		{Id: testOIDQSONotAfter, Value: []byte("2035-12-31")},
		{Id: testOIDDXCC, Value: []byte("291")},
	}
	if supersedes != "" {
		exts = append(exts, pkix.Extension{Id: testOIDSupersedes, Value: []byte(supersedes)})
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               subject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatalf("create user cert %d: %v", serial, err)
	}
	x509Cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse user cert %d: %v", serial, err)
	}
	parsed, err := ParseCertificate(x509Cert)
	if err != nil {
		t.Fatalf("ParseCertificate %d: %v", serial, err)
	}
	cred, err := NewCredential(parsed, key)
	if err != nil {
		t.Fatalf("NewCredential %d: %v", serial, err)
	}
	return cred, key
}

func TestInteropGenerate(t *testing.T) {
	dir := requireInteropDir(t)

	oidEmail := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	root, rootKey := newInteropCA(t, pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"go-gabbi Interop Test"},
		CommonName:   "go-gabbi Interop Root CA",
	}, 1, nil, nil)
	inter, interKey := newInteropCA(t, pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"go-gabbi Interop Test"},
		OrganizationalUnit: []string{"Interop CA"},
		CommonName:         "go-gabbi Interop Intermediate CA",
		ExtraNames: []pkix.AttributeTypeAndValue{{
			Type:  oidEmail,
			Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte("ca@example.org")},
		}},
	}, 2, root, rootKey)

	cred1, _ := newInteropUserCert(t, inter, interKey, 1001, "")

	// Build Cert 2's supercededCertificate extension using ARRL's /Email=
	// spelling for Cert 1's issuer plus ";1001".
	issuerOneline := onelineName(cred1.Cert.X509.RawIssuer)
	if !strings.Contains(issuerOneline, "/emailAddress=ca@example.org") {
		t.Fatalf("unexpected issuer oneline: %q", issuerOneline)
	}
	supersedes := strings.Replace(issuerOneline, "/emailAddress=", "/Email=", 1) + ";1001"
	cred2, _ := newInteropUserCert(t, inter, interKey, 1002, supersedes)

	chain := []*x509.Certificate{inter, root}

	writeFile := func(name string, data []byte, perm os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, perm); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	p12Cert1, err := ExportPKCS12(cred1, chain, "")
	if err != nil {
		t.Fatalf("ExportPKCS12 cert1: %v", err)
	}
	writeFile("cert1.p12", p12Cert1, 0o600)

	p12Cert1Pass, err := ExportPKCS12(cred1, chain, "testpass")
	if err != nil {
		t.Fatalf("ExportPKCS12 cert1-pass: %v", err)
	}
	writeFile("cert1-pass.p12", p12Cert1Pass, 0o600)

	p12Cert2, err := ExportPKCS12(cred2, chain, "")
	if err != nil {
		t.Fatalf("ExportPKCS12 cert2: %v", err)
	}
	writeFile("cert2.p12", p12Cert2, 0o600)

	// Build gzipped ca-update.tq6 carrying root, intermediate, and Cert 2.
	pemOf := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	tq6XML := fmt.Sprintf("<tqsldata>\n<tqslcerts>\n<rootcert>\n%s</rootcert>\n<cacert>\n%s</cacert>\n<usercert>\n%s</usercert>\n</tqslcerts>\n</tqsldata>\n",
		pemOf(root), pemOf(inter), pemOf(cred2.Cert.X509))
	var tq6Buf bytes.Buffer
	gzTQ6 := gzip.NewWriter(&tq6Buf)
	if _, err := gzTQ6.Write([]byte(tq6XML)); err != nil {
		t.Fatalf("gzip ca-update.tq6: %v", err)
	}
	if err := gzTQ6.Close(); err != nil {
		t.Fatalf("close gzip ca-update.tq6: %v", err)
	}
	writeFile("ca-update.tq6", tq6Buf.Bytes(), 0o644)

	// Write contacts.adi matching interopQSOs().
	adif := "<EOH>\n" +
		"<CALL:4>W1AW<BAND:3>20M<MODE:2>CW<FREQ:6>14.250<QSO_DATE:8>20261101<TIME_ON:6>153000<EOR>\n" +
		"<CALL:5>K1ABC<BAND:3>40M<MODE:4>MFSK<SUBMODE:3>FT4<FREQ:6>7.0475<QSO_DATE:8>20261102<TIME_ON:6>160000<EOR>\n"
	writeFile("contacts.adi", []byte(adif), 0o644)

	// Sign with superseded cred1 listed BEFORE cred2 to verify supersession exclusion.
	cfg := loadTestConfig(t, "config-11.35.xml")
	var tq8Buf bytes.Buffer
	gzTQ8 := gzip.NewWriter(&tq8Buf)
	rep, err := Sign(context.Background(), gzTQ8, cfg, []Credential{cred1, cred2}, interopStation, slices.Values(interopQSOs()), SignOptions{
		Action: Compliant,
		Ident:  Ident{Program: "go-gabbi-interop", Version: "2.8.7"},
	})
	if err != nil {
		t.Fatalf("Sign: %v (report %+v)", err, rep)
	}
	if rep.Signed != 2 || !rep.Commit {
		t.Fatalf("Sign report = %+v, want Signed=2 Commit=true", rep)
	}
	if err := gzTQ8.Close(); err != nil {
		t.Fatalf("close gzip go.tq8: %v", err)
	}
	writeFile("go.tq8", tq8Buf.Bytes(), 0o644)
}

func TestInteropVerify(t *testing.T) {
	dir := requireInteropDir(t)

	tq8Raw, err := os.ReadFile(filepath.Join(dir, "go.tq8"))
	if err != nil {
		t.Fatalf("read go.tq8: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(tq8Raw))
	if err != nil {
		t.Fatalf("gzip.NewReader(go.tq8): %v", err)
	}
	goBytes, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("decompress go.tq8: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip reader: %v", err)
	}

	tqslBytes, err := os.ReadFile(filepath.Join(dir, "tqsl.gabbi"))
	if err != nil {
		t.Fatalf("read tqsl.gabbi: %v", err)
	}

	goRecs := parseGAbbI(t, goBytes)
	tqslRecs := parseGAbbI(t, tqslBytes)

	if len(goRecs) != len(tqslRecs) {
		t.Fatalf("record count = %d (%v), want %d (%v)",
			len(goRecs), recordTypes(goRecs), len(tqslRecs), recordTypes(tqslRecs))
	}

	certCount := 0
	var contactModes []string
	for i := range tqslRecs {
		gr, wr := goRecs[i], tqslRecs[i]
		if gr.Type != wr.Type {
			t.Fatalf("record %d: type = %q, want %q (all go=%v tqsl=%v)",
				i, gr.Type, wr.Type, recordTypes(goRecs), recordTypes(tqslRecs))
		}
		if len(gr.Fields) != len(wr.Fields) {
			t.Fatalf("record %d (%s): field count = %d, want %d\ngo:   %v\ntqsl: %v",
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
			if wf.name == "TQSL_IDENT" {
				if !strings.Contains(gf.value, "Config: V11.35") || !strings.Contains(gf.value, "AllowDupes: false") {
					t.Errorf("record %d TQSL_IDENT = %q, missing expected config/dupes fields", i, gf.value)
				}
				continue
			}
			if len(gf.value) != len(wf.value) || gf.value != wf.value {
				t.Errorf("record %d (%s) field %s mismatch:\ngo   (len %d): %q\ntqsl (len %d): %q",
					i, wr.Type, wf.name, len(gf.value), gf.value, len(wf.value), wf.value)
			}
		}

		switch gr.Type {
		case "tCERT":
			certCount++
			b64, ok := gr.get("CERTIFICATE")
			if !ok {
				t.Fatalf("record %d: tCERT missing CERTIFICATE", i)
			}
			der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(b64, "\n", ""))
			if err != nil {
				t.Fatalf("record %d: decode CERTIFICATE: %v", i, err)
			}
			x509Cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("record %d: parse CERTIFICATE: %v", i, err)
			}
			if x509Cert.SerialNumber.Cmp(big.NewInt(1002)) != 0 {
				t.Errorf("record %d: tCERT serial = %s, want 1002 (Cert 2)", i, x509Cert.SerialNumber)
			}
		case "tCONTACT":
			mode, _ := gr.get("MODE")
			contactModes = append(contactModes, mode)
		}
	}

	if certCount != 1 {
		t.Errorf("tCERT count = %d, want 1", certCount)
	}
	wantModes := []string{"CW", "FT4"}
	if !slices.Equal(contactModes, wantModes) {
		t.Errorf("tCONTACT modes = %v, want %v", contactModes, wantModes)
	}
}
