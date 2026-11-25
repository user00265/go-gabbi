package gabbi

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func findExtension(c *x509.Certificate, oid []int) ([]byte, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

// TestTestCertRawExtensions proves the test helper writes ARRL's raw
// encoding: the extension's OCTET STRING holds the ASCII bytes directly, not
// a DER-wrapped string (knowledge.md §8).
func TestTestCertRawExtensions(t *testing.T) {
	p := newTestPKI(t)
	f := defaultTestCertFields()
	for _, tt := range []struct {
		oid  []int
		want string
	}{
		{testOIDQSONotBefore, f.QSONotBefore},
		{testOIDQSONotAfter, f.QSONotAfter},
		{testOIDDXCC, f.DXCC},
		{testOIDSupersedes, f.Supersedes},
	} {
		v, ok := findExtension(p.Leaf, tt.oid)
		if !ok {
			t.Fatalf("extension %v missing", tt.oid)
		}
		if string(v) != tt.want {
			t.Errorf("extension %v = %q, want %q", tt.oid, v, tt.want)
		}
		// OCTET STRING tag, short length, then the ASCII bytes.
		if len(tt.want) < 128 {
			der := append([]byte{0x04, byte(len(tt.want))}, tt.want...)
			if !bytes.Contains(p.Leaf.Raw, der) {
				t.Errorf("extension %v: DER does not hold 04 %02x %q", tt.oid, len(tt.want), tt.want)
			}
		}
	}
}

func TestParseCertificate(t *testing.T) {
	p := newTestPKI(t)
	c, err := ParseCertificate(p.Leaf)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if c.X509 != p.Leaf {
		t.Error("X509 is not the input certificate")
	}
	if c.Callsign != "KF0TST" {
		t.Errorf("Callsign = %q, want KF0TST", c.Callsign)
	}
	if c.DXCC != 291 {
		t.Errorf("DXCC = %d, want 291", c.DXCC)
	}
	if want := (Date{2020, time.May, 14}); c.QSONotBefore != want {
		t.Errorf("QSONotBefore = %v, want %v", c.QSONotBefore, want)
	}
	if want := (Date{2029, time.March, 19}); c.QSONotAfter != want {
		t.Errorf("QSONotAfter = %v, want %v", c.QSONotAfter, want)
	}
	if c.Supersedes == nil {
		t.Fatal("Supersedes = nil")
	}
	if c.Supersedes.Issuer != testSupersededIssuer {
		t.Errorf("Supersedes.Issuer = %q, want %q", c.Supersedes.Issuer, testSupersededIssuer)
	}
	if c.Supersedes.Serial == nil || c.Supersedes.Serial.Cmp(big.NewInt(724071)) != 0 {
		t.Errorf("Supersedes.Serial = %v, want 724071", c.Supersedes.Serial)
	}
}

func TestParseCertificateMissingNotAfter(t *testing.T) {
	p := newTestPKI(t)
	f := defaultTestCertFields()
	f.QSONotAfter = ""
	leaf := newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), f)
	c, err := ParseCertificate(leaf)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !c.QSONotAfter.IsZero() {
		t.Errorf("QSONotAfter = %v, want zero", c.QSONotAfter)
	}
	if c.QSONotBefore.IsZero() {
		t.Error("QSONotBefore is zero")
	}
}

func TestParseCertificateOptionalFields(t *testing.T) {
	p := newTestPKI(t)
	leaf := newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), testCertFields{Callsign: "KF0TST"})
	c, err := ParseCertificate(leaf)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !c.QSONotBefore.IsZero() || !c.QSONotAfter.IsZero() {
		t.Errorf("dates = %v, %v, want zero", c.QSONotBefore, c.QSONotAfter)
	}
	if c.DXCC != 0 {
		t.Errorf("DXCC = %d, want 0", c.DXCC)
	}
	if c.Supersedes != nil {
		t.Errorf("Supersedes = %+v, want nil", c.Supersedes)
	}
}

func TestParseCertificateNoCallsign(t *testing.T) {
	p := newTestPKI(t)
	f := defaultTestCertFields()
	f.Callsign = ""
	leaf := newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), f)
	_, err := ParseCertificate(leaf)
	if !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v, want ErrNoCertificate", err)
	}
	if !strings.Contains(err.Error(), "no AROcallsign") {
		t.Errorf("err = %q, want it to mention %q", err, "no AROcallsign")
	}
}

func TestParseCertificateDXCC(t *testing.T) {
	// TQSL reads the value with strtol(buf, NULL, 10)
	// (openssl_cert.cpp:2083-2088).
	tests := []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{raw: "291", want: 291},
		{raw: "0", want: 0},
		{raw: " 291", want: 291},
		{raw: "+291", want: 291},
		{raw: "291x", want: 291},
		{raw: "x291", wantErr: true},
		{raw: "-1", wantErr: true},
		{raw: " ", wantErr: true},
		{raw: "99999999999999999999", wantErr: true},
	}
	p := newTestPKI(t)
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			f := defaultTestCertFields()
			f.DXCC = tt.raw
			c, err := ParseCertificate(newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), f))
			if tt.wantErr {
				if !errors.Is(err, ErrNoCertificate) {
					t.Fatalf("err = %v, want ErrNoCertificate", err)
				}
				if !strings.Contains(err.Error(), "1.3.6.1.4.1.12348.1.4") {
					t.Errorf("err = %q, want it to name the OID", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if c.DXCC != tt.want {
				t.Errorf("DXCC = %d, want %d", c.DXCC, tt.want)
			}
		})
	}
}

func TestParseCertificateMalformed(t *testing.T) {
	p := newTestPKI(t)
	tests := []struct {
		name          string
		mod           func(*testCertFields)
		oid           string
		wantDateError bool
	}{
		{"bad not-before", func(f *testCertFields) { f.QSONotBefore = "2020-02-30" }, "1.3.6.1.4.1.12348.1.2", true},
		{"bad not-after", func(f *testCertFields) { f.QSONotAfter = "garbage" }, "1.3.6.1.4.1.12348.1.3", true},
		{"bad dxcc", func(f *testCertFields) { f.DXCC = "abc" }, "1.3.6.1.4.1.12348.1.4", false},
		{"supersedes without ;", func(f *testCertFields) { f.Supersedes = "/CN=x" }, "1.3.6.1.4.1.12348.1.5", false},
		{"supersedes bad serial", func(f *testCertFields) { f.Supersedes = "/CN=x;12a" }, "1.3.6.1.4.1.12348.1.5", false},
		{"supersedes empty serial", func(f *testCertFields) { f.Supersedes = "/CN=x;" }, "1.3.6.1.4.1.12348.1.5", false},
		{"supersedes signed serial", func(f *testCertFields) { f.Supersedes = "/CN=x;-5" }, "1.3.6.1.4.1.12348.1.5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := defaultTestCertFields()
			tt.mod(&f)
			_, err := ParseCertificate(newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), f))
			if !errors.Is(err, ErrNoCertificate) {
				t.Fatalf("err = %v, want ErrNoCertificate", err)
			}
			if !strings.Contains(err.Error(), tt.oid) {
				t.Errorf("err = %q, want it to name %s", err, tt.oid)
			}
			if tt.wantDateError && !errors.Is(err, ErrInvalidDate) {
				t.Errorf("err = %v, want it to wrap ErrInvalidDate too", err)
			}
		})
	}
}

func TestParseCertificateSupersedesLastSemicolon(t *testing.T) {
	p := newTestPKI(t)
	f := defaultTestCertFields()
	f.Supersedes = "/O=A;B/CN=C;42"
	c, err := ParseCertificate(newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), f))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if c.Supersedes.Issuer != "/O=A;B/CN=C" || c.Supersedes.Serial.Int64() != 42 {
		t.Errorf("Supersedes = %q;%v, want /O=A;B/CN=C;42", c.Supersedes.Issuer, c.Supersedes.Serial)
	}
}

func TestParseCertificateNil(t *testing.T) {
	if _, err := ParseCertificate(nil); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v, want ErrNoCertificate", err)
	}
}

func encodeP12(t testing.TB, enc *pkcs12.Encoder, key any, leaf *x509.Certificate, cas []*x509.Certificate, password string) []byte {
	t.Helper()
	b, err := enc.Encode(key, leaf, cas, password)
	if err != nil {
		t.Fatalf("pkcs12 Encode: %v", err)
	}
	return b
}

func TestLoadPKCS12Variants(t *testing.T) {
	p := newTestPKI(t)
	tests := []struct {
		name      string
		enc       *pkcs12.Encoder
		encPass   string
		loadPass  string
		first     *x509.Certificate
		cas       []*x509.Certificate
		wantChain []*x509.Certificate
	}{
		{"Modern2023 empty", pkcs12.Modern2023, "", "", p.Leaf, []*x509.Certificate{p.Inter, p.Root}, []*x509.Certificate{p.Inter, p.Root}},
		{"Modern2023 non-ASCII", pkcs12.Modern2023, "pässwörd", "pässwörd", p.Leaf, []*x509.Certificate{p.Inter, p.Root}, []*x509.Certificate{p.Inter, p.Root}},
		{"LegacyDES empty", pkcs12.LegacyDES, "", "", p.Leaf, []*x509.Certificate{p.Inter, p.Root}, []*x509.Certificate{p.Inter, p.Root}},
		{"LegacyDES password", pkcs12.LegacyDES, "pässwörd", "pässwörd", p.Leaf, []*x509.Certificate{p.Inter, p.Root}, []*x509.Certificate{p.Inter, p.Root}},
		{"Passwordless", pkcs12.Passwordless, "", "", p.Leaf, []*x509.Certificate{p.Inter, p.Root}, []*x509.Certificate{p.Inter, p.Root}},
		{"Passwordless spare password", pkcs12.Passwordless, "", "spare", p.Leaf, []*x509.Certificate{p.Inter, p.Root}, []*x509.Certificate{p.Inter, p.Root}},
		{"CA certs first", pkcs12.Modern2023, "", "", p.Root, []*x509.Certificate{p.Inter, p.Leaf}, []*x509.Certificate{p.Root, p.Inter}},
		{"leaf in the middle", pkcs12.Modern2023, "", "", p.Inter, []*x509.Certificate{p.Leaf, p.Root}, []*x509.Certificate{p.Inter, p.Root}},
		{"no chain", pkcs12.Modern2023, "", "", p.Leaf, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := encodeP12(t, tt.enc, p.Key, tt.first, tt.cas, tt.encPass)
			cred, chain, err := LoadPKCS12(data, tt.loadPass)
			if err != nil {
				t.Fatalf("LoadPKCS12: %v", err)
			}
			if cred.Cert == nil || cred.Cert.Callsign != "KF0TST" {
				t.Fatalf("Cert = %+v, want callsign KF0TST", cred.Cert)
			}
			if !cred.Cert.X509.Equal(p.Leaf) {
				t.Error("leaf is not the user certificate")
			}
			if !p.Key.PublicKey.Equal(cred.Signer.Public()) {
				t.Error("Signer does not hold the user key")
			}
			if len(chain) != len(tt.wantChain) {
				t.Fatalf("chain has %d certs, want %d", len(chain), len(tt.wantChain))
			}
			for i := range chain {
				if !chain[i].Equal(tt.wantChain[i]) {
					t.Errorf("chain[%d] = %q, want %q", i, chain[i].Subject.CommonName, tt.wantChain[i].Subject.CommonName)
				}
			}
		})
	}
}

func TestLoadPKCS12WrongPassword(t *testing.T) {
	p := newTestPKI(t)
	data := encodeP12(t, pkcs12.Modern2023, p.Key, p.Leaf, []*x509.Certificate{p.Inter, p.Root}, "right")
	for _, pw := range []string{"wrong", ""} {
		_, _, err := LoadPKCS12(data, pw)
		if !errors.Is(err, ErrPassword) {
			t.Fatalf("LoadPKCS12(%q): err = %v, want ErrPassword", pw, err)
		}
		msg := err.Error()
		if strings.Contains(msg, "right") || (pw != "" && strings.Contains(msg, pw)) {
			t.Errorf("error message %q contains a password", msg)
		}
	}
}

func TestLoadPKCS12KeyOnly(t *testing.T) {
	t.Skip("fixture phase: key-only .p12 from tqsl")
}

func TestLoadPKCS12ErrorMapping(t *testing.T) {
	notImpl := pkcs12.NotImplementedError("only password-protected PFX is implemented")
	other := errors.New("pkcs12: error reading P12 data: asn1: syntax error")
	tests := []struct {
		name string
		in   error
		want error
		keep error
	}{
		{"incorrect password", pkcs12.ErrIncorrectPassword, ErrPassword, pkcs12.ErrIncorrectPassword},
		{"wrapped incorrect password", fmt.Errorf("x: %w", pkcs12.ErrIncorrectPassword), ErrPassword, pkcs12.ErrIncorrectPassword},
		{"certificate missing", errors.New("pkcs12: certificate missing"), ErrNoCertificate, nil},
		{"private key missing", errors.New("pkcs12: private key missing"), ErrNoKey, nil},
		// Unmatched errors keep go-pkcs12's error and wrap no gabbi sentinel.
		{"decryption", pkcs12.ErrDecryption, nil, pkcs12.ErrDecryption},
		{"not implemented", notImpl, nil, notImpl},
		{"other", other, nil, other},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapPKCS12Error(tt.in)
			if tt.want != nil && !errors.Is(got, tt.want) {
				t.Errorf("mapPKCS12Error(%v) = %v, want it to wrap %v", tt.in, got, tt.want)
			}
			if tt.want == nil {
				for _, s := range certSentinels {
					if errors.Is(got, s) {
						t.Errorf("mapPKCS12Error(%v) = %v, wraps sentinel %v, want none", tt.in, got, s)
					}
				}
			}
			if tt.keep != nil && !errors.Is(got, tt.keep) {
				t.Errorf("mapPKCS12Error(%v) = %v, want it to keep %v", tt.in, got, tt.keep)
			}
			if !strings.Contains(got.Error(), tt.in.Error()) {
				t.Errorf("mapPKCS12Error(%v) = %q, want it to include the original message", tt.in, got)
			}
		})
	}
	var ni pkcs12.NotImplementedError
	if !errors.As(mapPKCS12Error(notImpl), &ni) {
		t.Error("errors.As cannot recover pkcs12.NotImplementedError")
	}
}

func TestLoadPKCS12KeyErrors(t *testing.T) {
	p := newTestPKI(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecLeaf := newTestCert(t, p.Inter, p.InterKey, ecKey.Public(), defaultTestCertFields())
	bigKey := newTestKeyBits(t, 2048)
	bigLeaf := newTestCert(t, p.Inter, p.InterKey, bigKey.Public(), defaultTestCertFields())
	other := newTestKey(t)
	f := defaultTestCertFields()
	f.Callsign = ""
	noCall := newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), f)

	tests := []struct {
		name string
		key  any
		leaf *x509.Certificate
		want error
	}{
		{"ECDSA key", ecKey, ecLeaf, ErrUnsupportedKey},
		{"RSA-2048 key", bigKey, bigLeaf, ErrUnsupportedKey},
		{"key matches no cert", other, p.Leaf, ErrCertMismatch},
		{"no AROcallsign", p.Key, noCall, ErrNoCertificate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := encodeP12(t, pkcs12.Modern2023, tt.key, tt.leaf, []*x509.Certificate{p.Inter, p.Root}, "")
			_, chain, err := LoadPKCS12(data, "")
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if chain != nil {
				t.Error("chain returned with an error")
			}
		})
	}
}

func TestLoadPKCS12Garbage(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte("not a pfx"), {0x30, 0x03, 0x02, 0x01, 0x03}} {
		_, _, err := LoadPKCS12(data, "")
		if err == nil {
			t.Errorf("LoadPKCS12(%x): err = nil, want an error", data)
			continue
		}
		if errors.Is(err, ErrNoCertificate) {
			t.Errorf("LoadPKCS12(%x): err = %v, want a decode error, not ErrNoCertificate", data, err)
		}
	}
}

// certSentinels are the gabbi sentinels LoadPKCS12 can return.
var certSentinels = []error{ErrPassword, ErrNoCertificate, ErrNoKey, ErrUnsupportedKey, ErrCertMismatch}

// otherSigner is a crypto.Signer whose public key is not RSA.
type otherSigner struct{ crypto.Signer }

func TestNewCredentialKeyChecks(t *testing.T) {
	p := newTestPKI(t)
	cert, err := ParseCertificate(p.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bigKey := newTestKeyBits(t, 2048)
	bigCert, err := ParseCertificate(newTestCert(t, p.Inter, p.InterKey, bigKey.Public(), defaultTestCertFields()))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		cert   *Certificate
		signer crypto.Signer
		want   error
	}{
		{"ECDSA signer", cert, otherSigner{ecKey}, ErrUnsupportedKey},
		{"RSA-2048 signer", bigCert, bigKey, ErrUnsupportedKey},
		{"RSA-2048 signer, RSA-1024 cert", cert, bigKey, ErrUnsupportedKey},
		{"mismatched RSA-1024", cert, newTestKey(t), ErrCertMismatch},
		{"nil signer", cert, nil, ErrNoKey},
		{"nil cert", nil, p.Key, ErrNoCertificate},
		{"cert without X509", &Certificate{}, p.Key, ErrNoCertificate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCredential(tt.cert, tt.signer)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}

	cred, err := NewCredential(cert, p.Key)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	if cred.Cert != cert || cred.Signer != crypto.Signer(p.Key) {
		t.Error("Credential does not hold the inputs")
	}
}

// TestNewTestCredential checks the shared helper that later tests build on.
func TestNewTestCredential(t *testing.T) {
	cred := newTestCredential(t)
	if cred.Cert.Callsign != "KF0TST" || cred.Cert.DXCC != 291 {
		t.Fatalf("Cert = %+v", cred.Cert)
	}
	if !cred.Cert.X509.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(cred.Signer.Public()) {
		t.Fatal("Signer does not match the certificate")
	}
}

func FuzzLoadPKCS12(f *testing.F) {
	p := newTestPKI(f)
	cas := []*x509.Certificate{p.Inter, p.Root}
	f.Add(encodeP12(f, pkcs12.Modern2023, p.Key, p.Leaf, cas, ""), "")
	f.Add(encodeP12(f, pkcs12.Modern2023, p.Key, p.Leaf, cas, "pässwörd"), "pässwörd")
	f.Add(encodeP12(f, pkcs12.LegacyDES, p.Key, p.Leaf, cas, ""), "")
	f.Add(encodeP12(f, pkcs12.Passwordless, p.Key, p.Leaf, cas, ""), "")
	f.Add(encodeP12(f, pkcs12.Passwordless, p.Key, p.Leaf, cas, ""), "spare")
	// Invariant: no panic, and either a non-nil error or a complete
	// credential. Errors need not wrap a gabbi sentinel (Ruling L).
	f.Fuzz(func(t *testing.T, data []byte, password string) {
		cred, chain, err := LoadPKCS12(data, password)
		if err != nil {
			if chain != nil || cred.Cert != nil || cred.Signer != nil {
				t.Fatalf("error %v returned with non-zero results", err)
			}
			return
		}
		if cred.Cert == nil || cred.Signer == nil || cred.Cert.Callsign == "" {
			t.Fatalf("success with incomplete credential: %+v", cred)
		}
		for _, c := range chain {
			if c == nil {
				t.Fatal("nil certificate in chain")
			}
		}
	})
}
