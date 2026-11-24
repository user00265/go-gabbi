package gabbi_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"os"
	"slices"
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

// memStore is a DupeStore in memory with a simple transaction: Begin
// snapshots the map and Rollback restores it. Real callers use a database
// transaction.
type memStore struct {
	m, saved map[string]string
}

func (s *memStore) Get(_ context.Context, k string) (string, bool, error) {
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *memStore) Put(_ context.Context, k, v string) error { s.m[k] = v; return nil }

func (s *memStore) Delete(_ context.Context, k string) error { delete(s.m, k); return nil }

func (s *memStore) Begin() { s.saved = maps.Clone(s.m) }

func (s *memStore) Rollback() { s.m = s.saved }

func ExampleSign_all() {
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
	st := gabbi.Station{
		Call:       "KF0TST",
		DXCC:       291,
		GridSquare: "EM10dh",
		Fields:     map[string]string{"US_STATE": "TX", "US_COUNTY": "Travis"},
	}
	qso := func(call string, day int) gabbi.QSO {
		return gabbi.QSO{Call: call, Band: "20M", Mode: "SSB", Freq: "14.250",
			Time: time.Date(2026, 11, day, 15, 30, 0, 0, time.UTC)}
	}
	log1 := []gabbi.QSO{qso("W1AW", 1)}
	log2 := []gabbi.QSO{qso("W1AW", 1), qso("K1JT", 2)} // W1AW again

	store := &memStore{m: map[string]string{}}
	sign := func(qsos []gabbi.QSO) {
		ctx := context.Background()
		opt := gabbi.SignOptions{Action: gabbi.All, Dupes: store, Ident: gabbi.Ident{Program: "ExampleLog", Version: "1.0"}}
		for {
			var out bytes.Buffer // a gzip.Writer over a file, in real use
			store.Begin()
			rep, err := gabbi.Sign(ctx, &out, cfg, []gabbi.Credential{cred}, st, slices.Values(qsos), opt)
			if !rep.Commit {
				store.Rollback()
			}
			if errors.Is(err, gabbi.ErrRestart) {
				// Discard out and sign everything again, duplicates
				// included, without the store.
				fmt.Printf("restart after %d duplicate(s)\n", rep.Duplicates)
				opt.Restart = true
				continue
			}
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("signed %d, duplicates %d\n", rep.Signed, rep.Duplicates)
			for _, line := range strings.Split(out.String(), "\n") {
				if strings.HasPrefix(line, "<TQSL_IDENT") || strings.HasPrefix(line, "<Rec_Type") {
					fmt.Println(line)
				}
			}
			return
		}
	}
	sign(log1)
	sign(log2)
	fmt.Println("store entries:", len(store.m))
	// Output:
	// signed 1, duplicates 0
	// <TQSL_IDENT:57>ExampleLog 1.0 Lib: V1.0 Config: V11.35 AllowDupes: false
	// <Rec_Type:5>tCERT
	// <Rec_Type:8>tSTATION
	// <Rec_Type:8>tCONTACT
	// restart after 1 duplicate(s)
	// signed 2, duplicates 0
	// <TQSL_IDENT:56>ExampleLog 1.0 Lib: V1.0 Config: V11.35 AllowDupes: true
	// <Rec_Type:5>tCERT
	// <Rec_Type:8>tSTATION
	// <Rec_Type:8>tCONTACT
	// <Rec_Type:8>tCONTACT
	// store entries: 1
}
