package gabbi

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// errClass names the gabbi sentinel err wraps, so a failure can be reported
// without printing the error text. Some error messages name the callsign,
// and an OS error names the file path.
func errClass(err error) string {
	for _, s := range []struct {
		err  error
		name string
	}{
		{ErrPassword, "ErrPassword"},
		{ErrNoCertificate, "ErrNoCertificate"},
		{ErrNoKey, "ErrNoKey"},
		{ErrCertMismatch, "ErrCertMismatch"},
		{ErrUnsupportedKey, "ErrUnsupportedKey"},
		{ErrDateRange, "ErrDateRange"},
		{ErrInvalidDate, "ErrInvalidDate"},
		{ErrExpired, "ErrExpired"},
		{ErrInvalidQSO, "ErrInvalidQSO"},
		{ErrInvalidStation, "ErrInvalidStation"},
		{ErrConfigOutdated, "ErrConfigOutdated"},
		{ErrConfig, "ErrConfig"},
	} {
		if errors.Is(err, s.err) {
			return s.name
		}
	}
	return "no gabbi sentinel"
}

// TestRealPKCS12 loads a real TrustedQSL export and signs one QSO with it.
// It runs only when GABBI_REAL_P12 names a .p12 file, and never in CI. The
// expected values are those of the owner's certificate, checked with
// openssl. The test prints nothing that identifies the owner: no callsign,
// name, e-mail, serial or path, and no error text or output bytes that
// could hold them. It writes no files.
//
// The expected DXCC, QSO dates and superseded serial come from the current
// certificate. After the certificate is renewed this test fails by design
// until the constants are updated.
func TestRealPKCS12(t *testing.T) {
	path := os.Getenv("GABBI_REAL_P12")
	if path == "" {
		t.Skip("GABBI_REAL_P12 not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read the GABBI_REAL_P12 file")
	}
	// TrustedQSL exports without a password.
	cred, chain, err := LoadPKCS12(data, "")
	clear(data)
	if err != nil {
		t.Fatalf("LoadPKCS12 failed (%s)", errClass(err))
	}
	c := cred.Cert

	if c.Callsign == "" {
		t.Error("callsign empty")
	}
	if c.DXCC != 291 {
		t.Error("unexpected DXCC")
	}
	if c.QSONotBefore.String() != "2020-05-14" {
		t.Error("unexpected QSONotBefore")
	}
	if c.QSONotAfter.String() != "2029-03-19" {
		t.Error("unexpected QSONotAfter")
	}
	if c.Supersedes == nil {
		t.Error("Supersedes is nil")
	} else if c.Supersedes.Serial == nil || c.Supersedes.Serial.Cmp(big.NewInt(724071)) != 0 {
		t.Error("unexpected Supersedes serial")
	}

	// Three cert bags: the leaf, the Production CA and the Root CA.
	if len(chain) != 2 {
		t.Error("chain does not have 2 certificates")
	}
	for _, ca := range chain {
		if !ca.IsCA {
			t.Error("chain certificate is not a CA")
		}
	}

	leafPub, ok := c.X509.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("leaf key is not RSA")
	}
	if leafPub.N.BitLen() != 1024 {
		t.Error("leaf key is not 1024 bits")
	}

	// Sign one synthetic QSO into memory.
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := Station{Call: c.Callsign, DXCC: 291, GridSquare: "EM10"}
	q := QSO{Call: "W1AW", Band: "20M", Mode: "CW", Time: time.Date(2026, 11, 1, 15, 30, 0, 0, time.UTC)}
	var buf bytes.Buffer
	defer buf.Reset()
	wr := NewWriter(&buf, cfg, Ident{Program: "test", Version: "1.0"}, NormalizeOptions{})
	if err := wr.WriteQSO(cred, st, q); err != nil {
		t.Fatalf("WriteQSO failed (%s)", errClass(err))
	}

	// The buffer holds the callsign and the leaf certificate, so failures
	// here report fixed strings only: no parser error, record type or value.
	rs, err := parseGAbbIRecords(buf.Bytes())
	if err != nil {
		t.Fatal("writer output is malformed")
	}
	if strings.Join(recordTypes(rs), " ") != "TQSL_IDENT tCERT tSTATION tCONTACT" {
		t.Fatal("writer output has unexpected records")
	}
	certText, _ := rs[1].get("CERTIFICATE")
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(certText, "\n", ""))
	if err != nil || !bytes.Equal(der, c.X509.Raw) {
		t.Error("tCERT does not hold the leaf certificate")
	}
	contact := rs[3]
	sd, ok := contact.get("SIGNDATA")
	if !ok || sd == "" {
		t.Fatal("tCONTACT has no SIGNDATA")
	}
	sigText, ok := contact.get("SIGN_LOTW_V2.0")
	if !ok {
		t.Fatal("tCONTACT has no SIGN_LOTW_V2.0")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(sigText, "\n", ""))
	if err != nil {
		t.Fatal("signature is not base64")
	}
	if len(sig) != 128 {
		t.Error("signature is not 128 bytes")
	}
	digest := sha1.Sum([]byte(sd))
	if err := rsa.VerifyPKCS1v15(leafPub, crypto.SHA1, digest[:], sig); err != nil {
		t.Error("signature does not verify against the leaf public key")
	}
}
