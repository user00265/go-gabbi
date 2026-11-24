package gabbi_test

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	gabbi "github.com/user00265/go-gabbi"
)

// exampleCredential builds a throwaway self-signed callsign certificate for
// KF0TST with an in-memory RSA-1024 key. Real callers load theirs with
// gabbi.LoadPKCS12.
func exampleCredential() (gabbi.Credential, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return gabbi.Credential{}, err
	}
	arrl := func(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, n} }
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "Example Operator", ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: arrl(1), Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("KF0TST")}},
		}},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: arrl(2), Value: []byte("2020-05-14")},
			{Id: arrl(3), Value: []byte("2029-03-19")},
			{Id: arrl(4), Value: []byte("291")},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return gabbi.Credential{}, err
	}
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return gabbi.Credential{}, err
	}
	cert, err := gabbi.ParseCertificate(x)
	if err != nil {
		return gabbi.Credential{}, err
	}
	return gabbi.NewCredential(cert, key)
}

func ExampleWriter() {
	data, err := os.ReadFile("testdata/config-11.35.xml")
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := gabbi.ParseConfig(bytes.NewReader(data))
	if err != nil {
		log.Fatal(err)
	}
	cred, err := exampleCredential()
	if err != nil {
		log.Fatal(err)
	}

	// The .tq8 file is the GAbbI text, gzipped.
	var tq8 bytes.Buffer
	zw := gzip.NewWriter(&tq8)
	w := gabbi.NewWriter(zw, cfg, gabbi.Ident{Program: "ExampleLog", Version: "1.0"}, gabbi.NormalizeOptions{})
	st := gabbi.Station{
		Call:       "KF0TST",
		DXCC:       291,
		GridSquare: "EM10dh",
		Fields:     map[string]string{"US_STATE": "TX", "US_COUNTY": "Travis"},
	}
	q := gabbi.QSO{
		Call: "W1AW",
		Band: "20M",
		Mode: "SSB",
		Freq: "14.250",
		Time: time.Date(2026, 11, 1, 15, 30, 0, 0, time.UTC),
	}
	if err := w.WriteQSO(cred, st, q); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}

	// Read it back and show the stable lines. The certificate and the
	// signature change with every generated key.
	zr, err := gzip.NewReader(&tq8)
	if err != nil {
		log.Fatal(err)
	}
	text, err := io.ReadAll(zr)
	if err != nil {
		log.Fatal(err)
	}
	for _, line := range strings.Split(string(text), "\n") {
		if strings.HasPrefix(line, "<TQSL_IDENT") || strings.HasPrefix(line, "<Rec_Type") ||
			strings.HasPrefix(line, "<SIGNDATA") {
			fmt.Println(line)
		}
	}
	// Output:
	// <TQSL_IDENT:57>ExampleLog 1.0 Lib: V1.0 Config: V11.35 AllowDupes: false
	// <Rec_Type:5>tCERT
	// <Rec_Type:8>tSTATION
	// <Rec_Type:8>tCONTACT
	// <SIGNDATA:49>EM10DHTRAVISTX20MW1AW14.250SSB2026-11-0115:30:00Z
}
