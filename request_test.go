package gabbi

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Expected layout: TrustedQSL 9b30153 src/openssl_cert.cpp:614-717,
// field encoding :4257-4283; provider values src/config.xml:7694-7700.
type requestField struct{ name, value string }

// normalizeRequestGolden keeps the exact reference bytes, including every
// field header and length. Only the two random cryptographic values are
// replaced; their declared lengths and field boundaries must still be valid.
func normalizeRequestGolden(data []byte) ([]byte, error) {
	const prefix = "\ntQSL certificate request\n\n<eoh>\n\n"
	if !bytes.HasPrefix(data, []byte(prefix)) {
		return nil, errors.New("bad request header")
	}
	var out bytes.Buffer
	out.WriteString(prefix)
	pos, csrCount, sigCount := len(prefix), 0, 0
	for pos < len(data) {
		if data[pos] != '<' {
			return nil, fmt.Errorf("bad field at byte %d", pos)
		}
		end := bytes.IndexByte(data[pos:], '>')
		if end < 0 {
			return nil, errors.New("unterminated field")
		}
		end += pos
		name, size, sized := strings.Cut(string(data[pos+1:end]), ":")
		n := 0
		if sized {
			var err error
			n, err = strconv.Atoi(size)
			if err != nil || n < 0 || size != strconv.Itoa(n) {
				return nil, fmt.Errorf("invalid field length %q", size)
			}
		}
		start := end + 1
		if n > len(data)-start || len(data)-start-n < 2 || !bytes.Equal(data[start+n:start+n+2], []byte("\n\n")) {
			return nil, fmt.Errorf("bad length or separator for %s", name)
		}
		out.Write(data[pos:start])
		switch name {
		case "TQSL_CRQ_REQUEST":
			csrCount++
			out.WriteString("[CSR]")
		case "TQSL_CRQ_SIGNATURE":
			sigCount++
			out.WriteString("[SIGNATURE]")
		default:
			out.Write(data[start : start+n])
		}
		out.WriteString("\n\n")
		pos = start + n + 2
	}
	if csrCount != 1 || sigCount > 1 {
		return nil, fmt.Errorf("unexpected CSR/signature counts %d/%d", csrCount, sigCount)
	}
	return out.Bytes(), nil
}

func TestRequestGoldenComparisonRejectsMarkerEncoding(t *testing.T) {
	for _, tc := range []struct{ file, marker string }{
		{"new.tq5", "TQSL_CRQ_NEW"},
		{"additional.tq5", "TQSL_CRQ_ADDITIONAL"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			fixture := readTestdata(t, "tq5/"+tc.file)
			want, err := normalizeRequestGolden(fixture)
			if err != nil {
				t.Fatal(err)
			}
			altered := bytes.Replace(fixture, []byte("<"+tc.marker+">"), []byte("<"+tc.marker+":0>"), 1)
			if bytes.Equal(altered, fixture) {
				t.Fatal("fixture marker not found")
			}
			got, err := normalizeRequestGolden(altered)
			if err == nil && bytes.Equal(got, want) {
				t.Fatal("comparison ignored changed marker encoding")
			}
		})
	}
}

func readRequestFields(t testing.TB, data []byte) []requestField {
	t.Helper()
	const prefix = "\ntQSL certificate request\n\n<eoh>\n\n"
	if !bytes.HasPrefix(data, []byte(prefix)) {
		t.Fatal("incorrect request header")
	}
	s := string(data[len(prefix):])
	var fields []requestField
	for len(s) > 0 {
		if s[0] != '<' {
			t.Fatalf("missing field: %q", s)
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			t.Fatal("unterminated field")
		}
		name, size, hasSize := strings.Cut(s[1:end], ":")
		n := 0
		if hasSize {
			var err error
			n, err = strconv.Atoi(size)
			if err != nil || n < 0 {
				t.Fatalf("invalid length %q", size)
			}
		}
		s = s[end+1:]
		if n > len(s) || len(s)-n < 2 || s[n:n+2] != "\n\n" {
			t.Fatalf("bad field length or separator %s", name)
		}
		fields = append(fields, requestField{name, s[:n]})
		s = s[n+2:]
	}
	return fields
}

func TestBuildRequestTrustedQSLGolden(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	fixture := func(name string) []byte {
		t.Helper()
		if dir := os.Getenv("GABBI_TQ5_FIXTURE_DIR"); dir != "" {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		return readTestdata(t, "tq5/"+name)
	}
	block, _ := pem.Decode(fixture("signer.pem"))
	if block == nil {
		t.Fatal("invalid fixture certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fixtureKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("fixture certificate key is not RSA")
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
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
	signerCert := *cert
	signerCert.PublicKey = &key.PublicKey
	c, err := ParseCertificate(&signerCert)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewCredential(c, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file string
		kind RequestKind
	}{{"new.tq5", NewRequest}, {"additional.tq5", Additional}} {
		t.Run(tc.file, func(t *testing.T) {
			goldenBytes := fixture(tc.file)
			gold := readRequestFields(t, goldenBytes)
			r := sampleRequest()
			r.City = "Dona Ana"
			r.Kind = tc.kind
			if tc.kind == Additional {
				r.Signer = &cred
			}
			gotBytes, _, err := BuildRequest(cfg, r, Ident{Program: "TQSL", Version: "2.8.7"}, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			got := readRequestFields(t, gotBytes)
			wantNormalized, err := normalizeRequestGolden(goldenBytes)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			gotNormalized, err := normalizeRequestGolden(gotBytes)
			if err != nil {
				t.Fatalf("generated request: %v", err)
			}
			if !bytes.Equal(gotNormalized, wantNormalized) {
				t.Fatalf("normalized request differs from TrustedQSL\ngot: %q\nwant: %q", gotNormalized, wantNormalized)
			}
			if len(got) != len(gold) {
				t.Fatalf("field counts: got %d want %d", len(got), len(gold))
			}
			for i := range gold {
				if got[i].name != gold[i].name {
					t.Fatalf("field %d: %s vs %s", i, got[i].name, gold[i].name)
				}
				if got[i].name != "TQSL_CRQ_REQUEST" && got[i].name != "TQSL_CRQ_SIGNATURE" && got[i].value != gold[i].value {
					t.Fatalf("%s: %q vs %q", got[i].name, got[i].value, gold[i].value)
				}
			}
			if !bytes.Contains(gotBytes, []byte("<TQSL_CRQ_ADDRESS2:0>\n\n")) || !bytes.Contains(goldenBytes, []byte("<TQSL_CRQ_ADDRESS2:0>\n\n")) {
				t.Fatal("empty field differs from TrustedQSL")
			}
			fixtureCSR, fixtureDER := parseRequestCSR(t, gold)
			builtCSR, builtDER := parseRequestCSR(t, got)
			for _, csr := range []*x509.CertificateRequest{fixtureCSR, builtCSR} {
				if err := csr.CheckSignature(); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(fixtureCSR.RawSubject, builtCSR.RawSubject) || fixtureCSR.SignatureAlgorithm != builtCSR.SignatureAlgorithm || len(fixtureCSR.Extensions) != len(builtCSR.Extensions) {
				t.Fatal("CSR subject or algorithm differs")
			}
			if tc.kind == Additional {
				// Verify the TrustedQSL signature against the public certificate.
				h := sha1.Sum(fixtureDER)
				goldSig, err := base64.StdEncoding.DecodeString(fieldValue(t, gold, "TQSL_CRQ_SIGNATURE"))
				if err != nil {
					t.Fatal(err)
				}
				if err := rsa.VerifyPKCS1v15(fixtureKey, crypto.SHA1, h[:], goldSig); err != nil {
					t.Fatalf("TrustedQSL signature: %v", err)
				}
				sig, err := base64.StdEncoding.DecodeString(fieldValue(t, got, "TQSL_CRQ_SIGNATURE"))
				if err != nil {
					t.Fatal(err)
				}
				builtHash := sha1.Sum(builtDER)
				expected, err := rsa.SignPKCS1v15(nil, key, crypto.SHA1, builtHash[:])
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(sig, expected) {
					t.Fatal("signature differs from RSA PKCS#1 v1.5")
				}
			}
		})
	}
}

func sampleRequest() Request {
	return Request{Callsign: "KF0TST", Name: "John Q Public", Email: "john@example.org", Address1: "1 Main Street", City: "Doña Ana", State: "NM", Postal: "88001", Country: "USA", DXCC: 291, QSONotBefore: Date{2020, 5, 14}, QSONotAfter: Date{2029, 3, 19}}
}

func buildTestRequest(t testing.TB, cfg *Config, req Request) ([]requestField, *rsa.PrivateKey) {
	t.Helper()
	b, k, err := BuildRequest(cfg, req, Ident{Program: "Logger", Version: "1.2"}, rand.Reader)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	return readRequestFields(t, b), k
}

func fieldValue(t testing.TB, fields []requestField, name string) string {
	t.Helper()
	for _, f := range fields {
		if f.name == name {
			return f.value
		}
	}
	t.Fatalf("missing field %s", name)
	return ""
}

func TestBuildRequestLayoutNew(t *testing.T) {
	f, _ := buildTestRequest(t, loadTestConfig(t, "config-11.35.xml"), sampleRequest())
	// openssl_cert.cpp:627-656 and :700-717; REQUEST is checked separately.
	want := []requestField{{"TQSL_IDENT", "Logger: 1.2, Lib: V1.2, Config: 11.35"}, {"TQSL_CRQ_NEW", ""}, {"TQSL_CRQ_PROVIDER", "American Radio Relay League"}, {"TQSL_CRQ_PROVIDER_UNIT", "Logbook of the World"}, {"TQSL_CRQ_EMAIL", "john@example.org"}, {"TQSL_CRQ_NAME", "John Q Public"}, {"TQSL_CRQ_ADDRESS1", "1 Main Street"}, {"TQSL_CRQ_ADDRESS2", ""}, {"TQSL_CRQ_CITY", "Doña Ana"}, {"TQSL_CRQ_STATE", "NM"}, {"TQSL_CRQ_POSTAL", "88001"}, {"TQSL_CRQ_COUNTRY", "USA"}, {"TQSL_CRQ_DXCC_ENTITY", "291"}, {"TQSL_CRQ_QSO_NOT_BEFORE", "2020-05-14"}, {"TQSL_CRQ_QSO_NOT_AFTER", "2029-03-19"}, {"TQSL_CRQ_REQUEST", fieldValue(t, f, "TQSL_CRQ_REQUEST")}, {"eor", ""}}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("fields:\n%#v\nwant:\n%#v", f, want)
	}
}

func TestBuildRequestOpenEnded(t *testing.T) {
	r := sampleRequest()
	r.QSONotAfter = Date{}
	f, _ := buildTestRequest(t, loadTestConfig(t, "config-11.35.xml"), r)
	for _, v := range f {
		if v.name == "TQSL_CRQ_QSO_NOT_AFTER" {
			t.Fatal("unexpected end date")
		}
	}
	if len(f) != 16 {
		t.Fatalf("got %d fields", len(f))
	}
}

func TestBuildRequestIdent(t *testing.T) {
	f, _ := buildTestRequest(t, loadTestConfig(t, "config-11.35.xml"), sampleRequest())
	if got := fieldValue(t, f, "TQSL_IDENT"); got != "Logger: 1.2, Lib: V1.2, Config: 11.35" {
		t.Fatal(got)
	}
}

func parseRequestCSR(t testing.TB, f []requestField) (*x509.CertificateRequest, []byte) {
	t.Helper()
	p, rest := pem.Decode([]byte(fieldValue(t, f, "TQSL_CRQ_REQUEST")))
	if p == nil || p.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatal("bad CSR PEM")
	}
	c, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c, p.Bytes
}

func TestBuildRequestCSR(t *testing.T) {
	f, key := buildTestRequest(t, loadTestConfig(t, "config-11.35.xml"), sampleRequest())
	c, _ := parseRequestCSR(t, f)
	if err := c.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if c.Version != 0 || c.SignatureAlgorithm != x509.SHA256WithRSA || len(c.Extensions) != 0 {
		t.Fatalf("bad CSR: %#v", c)
	}
	var info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes asn1.RawValue
	}
	if rest, err := asn1.Unmarshal(c.RawTBSCertificateRequest, &info); err != nil || len(rest) != 0 || info.Attributes.Class != asn1.ClassContextSpecific || info.Attributes.Tag != 0 || len(info.Attributes.Bytes) != 0 {
		t.Fatalf("CSR attributes: %#v, %v", info.Attributes, err)
	}
	if key.N.BitLen() != 1024 || key.E != 65537 || !key.Public().(*rsa.PublicKey).Equal(c.PublicKey) {
		t.Fatal("bad CSR public key")
	}
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(c.RawSubject, &seq); err != nil || len(rest) != 0 {
		t.Fatal("bad subject")
	}
	data := seq.Bytes
	for i, expected := range []struct {
		oid   string
		tag   int
		value string
	}{{"1.3.6.1.4.1.12348.1.1", 12, "KF0TST"}, {"2.5.4.3", 12, "John Q Public"}, {"1.2.840.113549.1.9.1", 22, "john@example.org"}} {
		var set asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &set)
		if err != nil || set.Tag != asn1.TagSet {
			t.Fatalf("RDN %d: %v", i, err)
		}
		var atv struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if rest, err := asn1.Unmarshal(set.Bytes, &atv); err != nil || len(rest) != 0 || atv.OID.String() != expected.oid || atv.Value.Tag != expected.tag || string(atv.Value.Bytes) != expected.value {
			t.Fatalf("RDN %d: %#v %v", i, atv, err)
		}
	}
	if len(data) != 0 {
		t.Fatal("extra subject RDN")
	}
}

// externalSigner models a caller-owned KMS/HSM implementation.
type externalSigner struct{ key *rsa.PrivateKey }

func (s *externalSigner) Public() crypto.PublicKey { return &s.key.PublicKey }
func (s *externalSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

type changingSigner struct {
	key   *rsa.PrivateKey
	calls int
}

type badPublicSigner struct{ pub *rsa.PublicKey }

func (s *badPublicSigner) Public() crypto.PublicKey { return s.pub }
func (s *badPublicSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not called")
}

func (s *changingSigner) Public() crypto.PublicKey {
	s.calls++
	if s.calls > 1 {
		return nil
	}
	return &s.key.PublicKey
}
func (s *changingSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, d, o)
}

func TestBuildRequestMalformedSigner(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	c := requestCredential(t)
	r := sampleRequest()
	r.Kind = Additional
	r.Signer = &c
	t.Run("changing public key", func(t *testing.T) {
		c := c
		c.Signer = &changingSigner{key: c.Signer.(*externalSigner).key}
		r := r
		r.Signer = &c
		if _, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader); err != nil {
			t.Fatalf("sign using verified public key: %v", err)
		}
	})
	t.Run("malformed private key", func(t *testing.T) {
		c := c
		c.Signer = &rsa.PrivateKey{}
		r := r
		r.Signer = &c
		if _, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid RSA public key", func(t *testing.T) {
		c := c
		cert := *c.Cert
		x := *cert.X509
		pub := &rsa.PublicKey{N: big.NewInt(0), E: 0}
		x.PublicKey = pub
		cert.X509 = &x
		c.Cert = &cert
		c.Signer = &badPublicSigner{pub: pub}
		r := r
		r.Signer = &c
		if _, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("nil certificate public key", func(t *testing.T) {
		c := c
		cert := *c.Cert
		x := *cert.X509
		var nilKey *rsa.PublicKey
		x.PublicKey = nilKey
		cert.X509 = &x
		c.Cert = &cert
		r := r
		r.Signer = &c
		if _, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestBuildRequestRejectsMalformedIssuer(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	cred := requestCredential(t)
	for _, issuer := range [][]byte{{0xff}, {0x30, 0x00}, {0x30, 0x00, 0x00}} {
		c := cred
		cert := *c.Cert
		x := *cert.X509
		x.RawIssuer = issuer
		cert.X509 = &x
		c.Cert = &cert
		r := sampleRequest()
		r.Kind, r.Signer = Additional, &c
		if _, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("issuer %x: got %v", issuer, err)
		}
	}
}

func requestCredential(t testing.TB) Credential {
	t.Helper()
	k := newTestKey(t)
	issuer, err := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test CA"}}, {{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "ca@example.org"}}})
	if err != nil {
		t.Fatal(err)
	}
	return Credential{Cert: &Certificate{Callsign: "KF0TST", X509: &x509.Certificate{PublicKey: &k.PublicKey, RawIssuer: issuer, SerialNumber: big.NewInt(12345), NotAfter: time.Now().Add(24 * time.Hour)}}, Signer: &externalSigner{k}}
}

func TestBuildRequestSigned(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	cred := requestCredential(t)
	for _, tc := range []struct {
		kind   RequestKind
		marker string
	}{{Renewal, "TQSL_CRQ_RENEWAL"}, {Additional, "TQSL_CRQ_ADDITIONAL"}} {
		t.Run(tc.marker, func(t *testing.T) {
			r := sampleRequest()
			r.Kind = tc.kind
			r.Signer = &cred
			f, _ := buildTestRequest(t, cfg, r)
			if f[1].name != tc.marker {
				t.Fatal(f[1])
			}
			_, der := parseRequestCSR(t, f)
			encoded := fieldValue(t, f, "TQSL_CRQ_SIGNATURE")
			if len(encoded) != 175 || len(strings.Split(encoded, "\n")[0]) != 64 || len(strings.Split(encoded, "\n")[1]) != 64 || !strings.HasSuffix(encoded, "\n") {
				t.Fatalf("signature format %q", encoded)
			}
			sig, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			h := sha1.Sum(der)
			if err := rsa.VerifyPKCS1v15(cred.Signer.Public().(*rsa.PublicKey), crypto.SHA1, h[:], sig); err != nil {
				t.Fatal(err)
			}
			if got := fieldValue(t, f, "TQSL_CRQ_SIGNATURE_CERT_ISSUER"); got != "/CN=Test CA/emailAddress=ca@example.org" {
				t.Fatal(got)
			}
			if got := fieldValue(t, f, "TQSL_CRQ_SIGNATURE_CERT_SERIAL"); got != "12345" {
				t.Fatal(got)
			}
		})
	}
}

func TestBuildRequestTrim(t *testing.T) {
	r := sampleRequest()
	r.Name = "  John   Q  Public "
	r.Callsign = " kf0tst "
	f, _ := buildTestRequest(t, loadTestConfig(t, "config-11.35.xml"), r)
	if fieldValue(t, f, "TQSL_CRQ_NAME") != "John Q Public" {
		t.Fatal("bad trim")
	}
	c, _ := parseRequestCSR(t, f)
	if c.Subject.Names[0].Value != "KF0TST" {
		t.Fatal(c.Subject.Names)
	}
}

func TestBuildRequestByteLengths(t *testing.T) {
	b, _, err := BuildRequest(loadTestConfig(t, "config-11.35.xml"), sampleRequest(), Ident{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("<TQSL_CRQ_CITY:9>Doña Ana\n\n")) {
		t.Fatal("length is not bytes")
	}
}

func TestBuildRequestValidation(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	cred := requestCredential(t)
	tests := []struct {
		name, label string
		edit        func(*Request)
	}{
		{"name", "Name", func(r *Request) { r.Name = "" }}, {"call", "Call Sign", func(r *Request) { r.Callsign = "" }}, {"address", "Address", func(r *Request) { r.Address1 = "" }}, {"city", "City", func(r *Request) { r.City = "" }}, {"country", "Country", func(r *Request) { r.Country = "" }}, {"email", "Email address", func(r *Request) { r.Email = "" }},
		{"email short", "", func(r *Request) { r.Email = "a@b" }}, {"email local", "", func(r *Request) { r.Email = "@b.c" }}, {"email domain", "", func(r *Request) { r.Email = "ab.c@" }}, {"bad call", "", func(r *Request) { r.Callsign = "0BAD" }}, {"long call", "", func(r *Request) { r.Callsign = "K12345678901234567890" }}, {"dxcc", "", func(r *Request) { r.DXCC = -1 }}, {"date order", "", func(r *Request) { r.QSONotAfter = Date{2019, 1, 1} }}, {"bad date", "", func(r *Request) { r.QSONotBefore = Date{2020, 2, 30} }}, {"renewal signer", "", func(r *Request) { r.Kind = Renewal }}, {"additional signer", "", func(r *Request) { r.Kind = Additional }}, {"wrong call", "", func(r *Request) { r.Kind = Renewal; r.Signer = &cred; r.Callsign = "W1AW" }}, {"kind", "", func(r *Request) { r.Kind = 99 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := sampleRequest()
			tc.edit(&r)
			_, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader)
			if !errors.Is(err, ErrInvalidRequest) || tc.label != "" && err.Error() != "gabbi: invalid certificate request: Missing parameter: "+tc.label {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, _, err := BuildRequest(nil, sampleRequest(), Ident{}, rand.Reader); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil config: %v", err)
	}
	if _, _, err := BuildRequest(cfg, sampleRequest(), Ident{}, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil random: %v", err)
	}
}

// TrustedQSL 9b30153: openssl_cert.cpp:853-905, 909-982 and
// tqsllib.cpp:884-947. It compares UTC dates and accepts diff < 180.
func TestBuildRequestRenewalExpiryBoundary(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	cred := requestCredential(t)
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	for _, days := range []int{179, 180, 181} {
		for _, hour := range []int{0, 23} {
			t.Run(fmt.Sprintf("%d_days_hour_%d", days, hour), func(t *testing.T) {
				c := cred
				cert := *c.Cert
				x := *cert.X509
				x.NotAfter = today.AddDate(0, 0, -days).Add(time.Duration(hour) * time.Hour)
				cert.X509 = &x
				c.Cert = &cert
				r := sampleRequest()
				r.Kind = Renewal
				r.Signer = &c
				_, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader)
				if DateOf(time.Now()) != DateOf(today) {
					t.Skip("UTC date changed during test")
				}
				if days == 179 && err != nil || days >= 180 && (!errors.Is(err, ErrExpired) || !errors.Is(err, ErrInvalidRequest)) {
					t.Fatalf("expiry at %s: %v", x.NotAfter, err)
				}
			})
		}
	}
}

// crqwiz.cpp:1477-1485,1539-1572,1841-1849; location.cpp:919-936.
func TestBuildRequestDXCCValidity(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	cred := requestCredential(t)
	tests := []struct {
		name       string
		dxcc       int
		start, end Date
		kind       RequestKind
		wantError  bool
		wantEnd    string
	}{
		{"none unsigned", 0, Date{2020, 1, 1}, Date{}, NewRequest, true, ""},
		{"none signed", 0, Date{2020, 1, 1}, Date{}, Additional, false, ""},
		{"before start", 8, Date{1945, 11, 14}, Date{1976, 6, 29}, NewRequest, true, ""},
		{"inclusive boundaries", 8, Date{1945, 11, 15}, Date{1976, 6, 29}, NewRequest, false, "1976-06-29"},
		{"after end", 8, Date{1976, 6, 30}, Date{}, NewRequest, true, ""},
		{"end after range", 8, Date{1976, 6, 1}, Date{1976, 6, 30}, NewRequest, true, ""},
		{"deleted open end", 8, Date{1976, 6, 1}, Date{}, NewRequest, false, "1976-06-29"},
		{"current open end", 291, Date{2020, 1, 1}, Date{}, NewRequest, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := sampleRequest()
			r.DXCC, r.QSONotBefore, r.QSONotAfter, r.Kind = tc.dxcc, tc.start, tc.end, tc.kind
			if tc.kind != NewRequest {
				r.Signer = &cred
			}
			b, _, err := BuildRequest(cfg, r, Ident{}, rand.Reader)
			if tc.wantError {
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f := readRequestFields(t, b)
			got := ""
			for _, v := range f {
				if v.name == "TQSL_CRQ_QSO_NOT_AFTER" {
					got = v.value
				}
			}
			if got != tc.wantEnd {
				t.Fatalf("end %q, want %q", got, tc.wantEnd)
			}
		})
	}
}

func TestConfigProvider(t *testing.T) {
	for _, file := range []string{"config-11.34.tq6", "config-11.35.xml"} {
		t.Run(file, func(t *testing.T) {
			name, unit := loadTestConfig(t, file).Provider()
			if name != "American Radio Relay League" || unit != "Logbook of the World" {
				t.Fatalf("%q %q", name, unit)
			}
		})
	}
	var cfg *Config
	name, unit := cfg.Provider()
	if name != "" || unit != "" {
		t.Fatal(name, unit)
	}
}

func TestBuildRequestNoProviders(t *testing.T) {
	data := readTestdata(t, "config-11.35.xml")
	start := bytes.Index(data, []byte("<providers>"))
	end := bytes.Index(data, []byte("</providers>"))
	if start < 0 || end < 0 {
		t.Fatal("missing providers")
	}
	data = append(bytes.Clone(data[:start]), data[end+len("</providers>"):]...)
	cfg, err := ParseConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := buildTestRequest(t, cfg, sampleRequest())
	if fieldValue(t, f, "TQSL_CRQ_PROVIDER") != "" || fieldValue(t, f, "TQSL_CRQ_PROVIDER_UNIT") != "" {
		t.Fatal("providers not empty")
	}
}

func FuzzBuildRequest(f *testing.F) {
	f.Add(byte(0), "KF0TST")
	f.Add(byte(1), "\x00")
	cfg := loadTestConfig(f, "config-11.35.xml")
	f.Fuzz(func(t *testing.T, which byte, value string) {
		r := sampleRequest()
		// Keep the other fields valid so mutations can reach CSR generation.
		fields := []*string{&r.Callsign, &r.Name, &r.Email, &r.Address1, &r.Address2, &r.City, &r.State, &r.Postal, &r.Country}
		*fields[int(which)%len(fields)] = value
		_, _, _ = BuildRequest(cfg, r, Ident{}, rand.Reader)
	})
}
