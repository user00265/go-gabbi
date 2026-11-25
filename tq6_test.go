package gabbi

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Line numbers in comments refer to TrustedQSL at commit 9b30153 (2.8.8):
// https://sourceforge.net/p/trustedqsl/tqsl/ci/9b301538a7b8b2766917ef23d344840686138e1f/tree/

// pemCert returns c as one PEM CERTIFICATE block.
func pemCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// certEl returns a <name> element holding body, as tqsl_importTQSLFile reads
// it (location.cpp:4309-4335).
func certEl(name, body string) string {
	return "<" + name + ">\n" + body + "</" + name + ">\n"
}

// tq6Doc wraps cert elements and any extra <tqsldata> children in the .tq6
// layout: <tqsldata><tqslcerts>...</tqslcerts>...</tqsldata>
// (location.cpp:4302-4308).
func tq6Doc(certs, extra string) []byte {
	return []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<tqsldata>\n<tqslcerts>\n" +
		certs + "</tqslcerts>\n" + extra + "</tqsldata>\n")
}

// tq6PKI is a test PKI with a second user certificate under the same CA.
type tq6PKI struct {
	*testPKI
	Key2  crypto.Signer
	Leaf2 *x509.Certificate
}

func newTQ6PKI(t testing.TB) *tq6PKI {
	t.Helper()
	p := &tq6PKI{testPKI: newTestPKI(t)}
	k := newTestKey(t)
	f := defaultTestCertFields()
	f.Callsign = "KF0TS2"
	p.Key2, p.Leaf2 = k, newTestCert(t, p.Inter, p.InterKey, k.Public(), f)
	return p
}

func sameCerts(t *testing.T, what string, got, want []*x509.Certificate) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d certificates, want %d", what, len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].Raw, want[i].Raw) {
			t.Errorf("%s[%d] is %s, want %s", what, i, got[i].Subject, want[i].Subject)
		}
	}
}

// TQSL reads the root, CA and user cert elements by name, whatever their
// order in the file, and keeps document order within each name: the XML
// children live in a multimap (location.cpp:4309-4335). The file is opened
// through gzopen, which reads gzip and plain text alike (xml.cpp:116,130).
func TestParseTQ6Layout(t *testing.T) {
	p := newTQ6PKI(t)
	doc := tq6Doc(
		certEl("usercert", pemCert(p.Leaf))+
			certEl("rootcert", pemCert(p.Root))+
			certEl("cacert", pemCert(p.Inter))+
			certEl("usercert", pemCert(p.Leaf2)), "")

	for name, data := range map[string][]byte{"plain": doc, "gzip": gzipBytes(t, doc)} {
		t.Run(name, func(t *testing.T) {
			tq6, err := ParseTQ6(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ParseTQ6: %v", err)
			}
			sameCerts(t, "Roots", tq6.Roots, []*x509.Certificate{p.Root})
			sameCerts(t, "CAs", tq6.CAs, []*x509.Certificate{p.Inter})
			sameCerts(t, "Users", tq6.Users, []*x509.Certificate{p.Leaf, p.Leaf2})
			if tq6.Config != nil {
				t.Errorf("Config = %v, want nil without <tqslconfig>", tq6.Config)
			}
		})
	}
}

// PEM_read_bio_X509 reads only the first certificate in the element
// (openssl_cert.cpp:424).
func TestParseTQ6FirstPEMOnly(t *testing.T) {
	p := newTQ6PKI(t)
	doc := tq6Doc(certEl("usercert", pemCert(p.Leaf)+pemCert(p.Leaf2)), "")
	tq6, err := ParseTQ6(bytes.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseTQ6: %v", err)
	}
	sameCerts(t, "Users", tq6.Users, []*x509.Certificate{p.Leaf})
}

// PEM_read_bio_X509 skips any text before -----BEGIN (openssl_cert.cpp:424).
func TestParseTQ6LeadingText(t *testing.T) {
	p := newTQ6PKI(t)
	doc := tq6Doc(certEl("rootcert", "Subject: go-gabbi Test Root CA\nsome notes\n"+pemCert(p.Root)), "")
	tq6, err := ParseTQ6(bytes.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseTQ6: %v", err)
	}
	sameCerts(t, "Roots", tq6.Roots, []*x509.Certificate{p.Root})
}

// An optional <tqslconfig> child of <tqsldata> is the configuration
// (location.cpp:4344). It goes through the same decoder as ParseConfig,
// so the minimum version applies.
func TestParseTQ6Config(t *testing.T) {
	p := newTQ6PKI(t)
	certs := certEl("usercert", pemCert(p.Leaf))
	cfg := string(readTestdata(t, "config-11.35.xml"))

	tq6, err := ParseTQ6(bytes.NewReader(gzipBytes(t, tq6Doc(certs, cfg))))
	if err != nil {
		t.Fatalf("ParseTQ6: %v", err)
	}
	if major, minor := tq6.Config.Version(); major != 11 || minor != 35 {
		t.Errorf("Config.Version() = %d.%d, want 11.35", major, minor)
	}
	sameCerts(t, "Users", tq6.Users, []*x509.Certificate{p.Leaf})

	old := strings.Replace(cfg, `minorversion="35"`, `minorversion="31"`, 1)
	if _, err := ParseTQ6(bytes.NewReader(tq6Doc(certs, old))); !errors.Is(err, ErrConfigOutdated) {
		t.Errorf("11.31 config: err = %v, want ErrConfigOutdated", err)
	}
}

// tq6BombStream is a gzip .tq6 that opens an element and then decompresses
// to more than 16 MiB of spaces, so only the size cap can stop it.
func tq6BombStream(t testing.TB, open string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(open)
	buf.Write(bytes.Repeat([]byte(" "), 17<<20))
	return gzipBytes(t, buf.Bytes())
}

// Ruling D1-a: a root or CA that fails to parse is an error. TQSL only logs
// it (location.cpp:4314-4325); a user cert failure fails the import there
// too (4329-4333). A file whose root is not <tqsldata> is a syntax error
// (4302-4306).
func TestParseTQ6Errors(t *testing.T) {
	p := newTQ6PKI(t)
	truncated := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Root.Raw[:len(p.Root.Raw)-10]}))
	badDER := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}))

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"wrong root", []byte(`<tqslconfig majorversion="11" minorversion="35" />`)},
		{"bad XML", []byte(`<tqsldata><tqslcerts><rootcert>`)},
		{"trailing garbage", append(tq6Doc("", ""), "<"...)},
		{"rootcert without PEM", tq6Doc(certEl("rootcert", "no certificate here\n"), "")},
		{"cacert without PEM", tq6Doc(certEl("cacert", ""), "")},
		{"usercert without PEM", tq6Doc(certEl("usercert", "-----BEGIN CERTIFICATE-----\n"), "")},
		{"malformed DER", tq6Doc(certEl("cacert", badDER), "")},
		{"truncated root", tq6Doc(certEl("rootcert", truncated), "")},
		{"truncated gzip", gzipBytes(t, tq6Doc(certEl("rootcert", pemCert(p.Root)), ""))[:40]},
		{"bad config", tq6Doc("", `<tqslconfig majorversion="11" minorversion="35"></tqslconfig>`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tq6, err := ParseTQ6(bytes.NewReader(tt.data))
			if err == nil {
				t.Fatalf("ParseTQ6 succeeded (%+v), want error", tq6)
			}
			if tq6 != nil {
				t.Errorf("ParseTQ6 returned %+v with an error", tq6)
			}
			if !errors.Is(err, ErrTQ6) {
				t.Errorf("err = %v, want ErrTQ6", err)
			}
		})
	}

	// A decompression bomb hits the cap ParseConfig uses, whether it sits
	// in the certificates or in the configuration.
	for _, open := range []string{
		"<tqsldata><tqslcerts><rootcert>",
		`<tqsldata><tqslconfig majorversion="11" minorversion="35">`,
	} {
		t.Run("gzip bomb "+open, func(t *testing.T) {
			_, err := ParseTQ6(bytes.NewReader(tq6BombStream(t, open)))
			if !errors.Is(err, errConfigTooLarge) || !strings.Contains(err.Error(), "16 MiB") {
				t.Errorf("err = %v, want the 16 MiB cap error", err)
			}
		})
	}
}

func TestParseTQ6ReadError(t *testing.T) {
	_, err := ParseTQ6(errReader{})
	if !errors.Is(err, ErrTQ6) || !strings.Contains(err.Error(), "disk on fire") {
		t.Errorf("err = %v, want ErrTQ6 wrapping the read error", err)
	}
}

// Ruling D1-b: a file with no usercert is valid. TQSL needs at least one
// certificate element of any kind (foundcerts, location.cpp:4312) or a
// config.
func TestParseTQ6NoUsers(t *testing.T) {
	p := newTQ6PKI(t)
	tq6, err := ParseTQ6(bytes.NewReader(tq6Doc(certEl("rootcert", pemCert(p.Root)), "")))
	if err != nil {
		t.Fatalf("ParseTQ6: %v", err)
	}
	sameCerts(t, "Roots", tq6.Roots, []*x509.Certificate{p.Root})
	if len(tq6.CAs) != 0 || len(tq6.Users) != 0 {
		t.Errorf("CAs = %d, Users = %d, want none", len(tq6.CAs), len(tq6.Users))
	}
}

// TQSL pairs a user certificate with a pending key on the public key alone
// (tqsl_find_matching_key, EVP_PKEY_cmp, openssl_cert.cpp:5162).
func TestPair(t *testing.T) {
	p := newTQ6PKI(t)
	users := []*x509.Certificate{p.Leaf, p.Leaf2}

	t.Run("matches second", func(t *testing.T) {
		cred, err := Pair(users, p.Key2)
		if err != nil {
			t.Fatalf("Pair: %v", err)
		}
		if !bytes.Equal(cred.Cert.X509.Raw, p.Leaf2.Raw) {
			t.Errorf("paired %s, want %s", cred.Cert.X509.Subject, p.Leaf2.Subject)
		}
		if cred.Cert.Callsign != "KF0TS2" {
			t.Errorf("Callsign = %q, want KF0TS2", cred.Cert.Callsign)
		}
		if cred.Signer != p.Key2 {
			t.Error("Signer is not the key passed in")
		}
	})
	t.Run("foreign key", func(t *testing.T) {
		if _, err := Pair(users, newTestKey(t)); !errors.Is(err, ErrCertMismatch) {
			t.Errorf("err = %v, want ErrCertMismatch", err)
		}
	})
	t.Run("no users", func(t *testing.T) {
		if _, err := Pair(nil, p.Key); !errors.Is(err, ErrCertMismatch) {
			t.Errorf("err = %v, want ErrCertMismatch", err)
		}
	})
	t.Run("nil entries", func(t *testing.T) {
		cred, err := Pair([]*x509.Certificate{nil, p.Leaf}, p.Key)
		if err != nil || !bytes.Equal(cred.Cert.X509.Raw, p.Leaf.Raw) {
			t.Errorf("Pair = %v, %v; want the first user", cred.Cert, err)
		}
	})
	t.Run("nil key", func(t *testing.T) {
		if _, err := Pair(users, nil); !errors.Is(err, ErrNoKey) {
			t.Errorf("err = %v, want ErrNoKey", err)
		}
		// A typed nil *rsa.PrivateKey panics in Public().
		if _, err := Pair(users, (*rsa.PrivateKey)(nil)); !errors.Is(err, ErrNoKey) {
			t.Errorf("typed nil: err = %v, want ErrNoKey", err)
		}
	})
	t.Run("RSA-2048", func(t *testing.T) {
		// TQSL cannot sign with more than 1024 bits (location.cpp:3826).
		big := newTestKeyBits(t, 2048)
		leaf := newTestCert(t, p.Inter, p.InterKey, big.Public(), defaultTestCertFields())
		if _, err := Pair([]*x509.Certificate{leaf}, big); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("err = %v, want ErrUnsupportedKey", err)
		}
	})
	t.Run("no AROcallsign", func(t *testing.T) {
		// TQSL rejects a user cert without one (openssl_cert.cpp:2955).
		f := defaultTestCertFields()
		f.Callsign = ""
		leaf := newTestCert(t, p.Inter, p.InterKey, p.Key.Public(), f)
		if _, err := Pair([]*x509.Certificate{leaf}, p.Key); !errors.Is(err, ErrNoCertificate) {
			t.Errorf("err = %v, want ErrNoCertificate", err)
		}
	})
}

func TestExportPKCS12RoundTrip(t *testing.T) {
	p := newTQ6PKI(t)
	cred, err := Pair([]*x509.Certificate{p.Leaf}, p.Key)
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{p.Inter, p.Root}
	for _, pw := range []string{"", "pässwörd"} {
		t.Run(pw, func(t *testing.T) {
			data, err := ExportPKCS12(cred, chain, pw)
			if err != nil {
				t.Fatalf("ExportPKCS12: %v", err)
			}
			got, gotChain, err := LoadPKCS12(data, pw)
			if err != nil {
				t.Fatalf("LoadPKCS12: %v", err)
			}
			if !bytes.Equal(got.Cert.X509.Raw, p.Leaf.Raw) {
				t.Error("leaf differs")
			}
			sameCerts(t, "chain", gotChain, chain)
			if !p.Key.PublicKey.Equal(got.Signer.Public()) {
				t.Error("signer public key differs")
			}
		})
	}
	t.Run("nil chain", func(t *testing.T) {
		// Root and CA bags are optional to TQSL: it imports whatever it
		// collected (openssl_cert.cpp:2943-2945, 3161-3172).
		data, err := ExportPKCS12(cred, nil, "")
		if err != nil {
			t.Fatalf("ExportPKCS12: %v", err)
		}
		_, gotChain, err := LoadPKCS12(data, "")
		if err != nil || len(gotChain) != 0 {
			t.Errorf("LoadPKCS12 = %d chain certs, %v; want none", len(gotChain), err)
		}
	})
}

// TQSL's import fails without a MAC (PKCS12_verify_mac,
// openssl_cert.cpp:2874) and rejects a plain keyBag, so the key must be
// shrouded (3104-3107). LoadPKCS12 retries a MAC-less file without the
// password, so a wrong password failing with ErrPassword proves the MAC is
// there. The shrouded key comes from go-pkcs12's Modern2023 encoder
// (pkcs12.go:700-708).
func TestExportPKCS12Structure(t *testing.T) {
	cred := newTestCredential(t)
	for _, pw := range []string{"", "pässwörd"} {
		t.Run(pw, func(t *testing.T) {
			data, err := ExportPKCS12(cred, nil, pw)
			if err != nil {
				t.Fatalf("ExportPKCS12: %v", err)
			}
			_, _, err = LoadPKCS12(data, pw+"wrong")
			if !errors.Is(err, ErrPassword) || !errors.Is(err, pkcs12.ErrIncorrectPassword) {
				t.Errorf("wrong password: err = %v, want ErrPassword wrapping pkcs12.ErrIncorrectPassword", err)
			}
		})
	}
}

// opaqueSigner hides the concrete key type, like a KMS or HSM signer.
type opaqueSigner struct{ crypto.Signer }

func TestExportPKCS12KeyTypes(t *testing.T) {
	cred := newTestCredential(t)
	other := newTestCredential(t)
	tests := []struct {
		name string
		cred Credential
		want error
	}{
		{"opaque signer", Credential{Cert: cred.Cert, Signer: opaqueSigner{cred.Signer}}, ErrUnsupportedKey},
		{"wrong key", Credential{Cert: cred.Cert, Signer: other.Signer}, ErrCertMismatch},
		{"zero credential", Credential{}, ErrNoCertificate},
		{"nil X509", Credential{Cert: &Certificate{}, Signer: cred.Signer}, ErrNoCertificate},
		{"nil signer", Credential{Cert: cred.Cert}, ErrNoKey},
		{"typed nil signer", Credential{Cert: cred.Cert, Signer: (*rsa.PrivateKey)(nil)}, ErrNoKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := ExportPKCS12(tt.cred, nil, "")
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if data != nil {
				t.Errorf("got %d bytes with an error", len(data))
			}
		})
	}
	t.Run("nil chain entry", func(t *testing.T) {
		if _, err := ExportPKCS12(cred, []*x509.Certificate{nil}, ""); err == nil {
			t.Error("ExportPKCS12 accepted a nil chain certificate")
		}
	})
}

func FuzzParseTQ6(f *testing.F) {
	p := newTQ6PKI(f)
	doc := tq6Doc(certEl("rootcert", pemCert(p.Root))+certEl("cacert", pemCert(p.Inter))+
		certEl("usercert", pemCert(p.Leaf)), "")
	f.Add(doc)
	f.Add(gzipBytes(f, doc))
	f.Add(tq6Doc("", `<tqslconfig majorversion="11" minorversion="34"></tqslconfig>`))
	f.Add([]byte("<tqsldata/>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tq6, err := ParseTQ6(bytes.NewReader(data))
		if err != nil {
			if tq6 != nil {
				t.Fatalf("result %+v returned with error %v", tq6, err)
			}
			if !errors.Is(err, ErrTQ6) {
				t.Fatalf("error does not wrap ErrTQ6: %v", err)
			}
			return
		}
		if tq6 == nil {
			t.Fatal("nil result without an error")
		}
		for _, list := range [][]*x509.Certificate{tq6.Roots, tq6.CAs, tq6.Users} {
			for _, c := range list {
				if c == nil {
					t.Fatal("nil certificate in result")
				}
			}
		}
		tq6.Config.Version()
		_, _ = Pair(tq6.Users, p.Key)
	})
}
