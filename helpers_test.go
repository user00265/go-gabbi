package gabbi

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readTestdata returns the bytes of testdata/name.
func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return b
}

// loadTestConfig parses testdata/name with ParseConfig and fails the test on
// any error.
func loadTestConfig(t testing.TB, name string) *Config {
	t.Helper()
	cfg, err := ParseConfig(bytes.NewReader(readTestdata(t, name)))
	if err != nil {
		t.Fatalf("ParseConfig(testdata/%s): %v", name, err)
	}
	return cfg
}

// ARRL OIDs under 1.3.6.1.4.1.12348.1 (tqsllib.cpp:64-96).
var (
	testOIDCallsign     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 1}
	testOIDQSONotBefore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 2}
	testOIDQSONotAfter  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 3}
	testOIDDXCC         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 4}
	testOIDSupersedes   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 5}
)

// testSupersededIssuer is the issuer part of the owner's real .5 value
// (knowledge.md §8.1).
const testSupersededIssuer = "/C=US/ST=CT/L=Newington/O=American Radio Relay League/" +
	"OU=Logbook of the World/CN=Logbook of the World Production CA/DC=arrl.org/Email=lotw@arrl.org"

// testCertFields holds the ARRL fields of a test user certificate. Each
// extension value is written raw into the OCTET STRING, the way ARRL issues
// them. An empty string leaves that field out.
type testCertFields struct {
	Callsign     string
	QSONotBefore string
	QSONotAfter  string
	DXCC         string
	Supersedes   string
}

// defaultTestCertFields returns the field values verified on the owner's
// real certificate (knowledge.md §8.1), with the callsign KF0TST.
func defaultTestCertFields() testCertFields {
	return testCertFields{
		Callsign:     "KF0TST",
		QSONotBefore: "2020-05-14",
		QSONotAfter:  "2029-03-19",
		DXCC:         "291",
		Supersedes:   testSupersededIssuer + ";724071",
	}
}

// newTestKey generates a throwaway RSA-1024 key, the size TQSL issues.
func newTestKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	return newTestKeyBits(t, 1024)
}

func newTestKeyBits(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	return k
}

func testSerial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

// newTestCA creates a CA certificate with a fresh RSA-2048 key. It is
// self-signed when parent is nil, otherwise signed by parent and parentKey.
func newTestCA(t testing.TB, cn string, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := newTestKeyBits(t, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{Organization: []string{"go-gabbi test"}, CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create CA %q: %v", cn, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// newTestCert issues a user certificate for pub, signed by ca and caKey,
// carrying the ARRL fields in f. The callsign is a UTF8String subject
// attribute; the other fields are extensions with raw ASCII values.
func newTestCert(t testing.TB, ca *x509.Certificate, caKey crypto.Signer, pub crypto.PublicKey, f testCertFields) *x509.Certificate {
	t.Helper()
	subject := pkix.Name{CommonName: "Test Operator"}
	if f.Callsign != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{
			Type:  testOIDCallsign,
			Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(f.Callsign)},
		}}
	}
	var exts []pkix.Extension
	for _, e := range []struct {
		oid asn1.ObjectIdentifier
		val string
	}{
		{testOIDQSONotBefore, f.QSONotBefore},
		{testOIDQSONotAfter, f.QSONotAfter},
		{testOIDDXCC, f.DXCC},
		{testOIDSupersedes, f.Supersedes},
	} {
		if e.val != "" {
			// x509.CreateCertificate writes Value verbatim as the OCTET
			// STRING contents, which is ARRL's raw encoding.
			exts = append(exts, pkix.Extension{Id: e.oid, Value: []byte(e.val)})
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatalf("create user cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testPKI is a throwaway two-level CA and an RSA-1024 user certificate.
type testPKI struct {
	Root, Inter       *x509.Certificate
	RootKey, InterKey *rsa.PrivateKey
	Key               *rsa.PrivateKey
	Leaf              *x509.Certificate
}

// newTestPKI builds a root, an intermediate and a user certificate with the
// default ARRL fields.
func newTestPKI(t testing.TB) *testPKI {
	t.Helper()
	p := &testPKI{}
	p.Root, p.RootKey = newTestCA(t, "go-gabbi Test Root CA", nil, nil)
	p.Inter, p.InterKey = newTestCA(t, "go-gabbi Test Production CA", p.Root, p.RootKey)
	p.Key = newTestKey(t)
	p.Leaf = newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), defaultTestCertFields())
	return p
}

// newTestCredential returns a Credential for a fresh test certificate.
func newTestCredential(t testing.TB) Credential {
	t.Helper()
	p := newTestPKI(t)
	c, err := ParseCertificate(p.Leaf)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	cred, err := NewCredential(c, p.Key)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return cred
}
