package gabbi

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TQ6 is the content of a .tq6 file: the signed certificates LoTW sends
// back for a certificate request, and the form config.tq6 comes in.
type TQ6 struct {
	// Roots, CAs and Users hold the rootcert, cacert and usercert
	// elements, each in document order. Nothing in a .tq6 file is signed,
	// so none of them is verified here.
	Roots, CAs, Users []*x509.Certificate
	// Config is the <tqslconfig> element, or nil when the file has none.
	Config *Config
}

// ParseTQ6 reads a .tq6 file, plain or gzipped.
//
// The root element must be <tqsldata>. Its first <tqslcerts> child holds
// <rootcert>, <cacert> and <usercert> elements in any order, each holding
// PEM text. As in TrustedQSL, text before the PEM block is ignored and only
// the first CERTIFICATE block of an element is read. A file need not hold a
// user certificate: it may carry only CA certificates or a configuration.
//
// Every error wraps [ErrTQ6]. TrustedQSL skips a root or CA certificate it
// cannot read; ParseTQ6 returns an error instead, so a damaged file is never
// half imported. A <tqslconfig> element is parsed as [ParseConfig] parses
// it, so its errors also wrap [ErrConfig] or [ErrConfigOutdated]. Input that
// decompresses to more than 16 MiB is rejected.
func ParseTQ6(r io.Reader) (*TQ6, error) {
	src, err := openTQSLData(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTQ6, err)
	}
	d := xml.NewDecoder(src)
	if err := tq6Root(d); err != nil {
		return nil, err
	}

	t := &TQ6{}
	certsSeen := false
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, tq6Err(err)
		}
		if _, ok := tok.(xml.EndElement); ok {
			break // </tqsldata>
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		// TrustedQSL reads the first of each (location.cpp:4308, 4344).
		switch {
		case el.Name.Local == "tqslcerts" && !certsSeen:
			certsSeen = true
			err = t.decodeCerts(d)
		case el.Name.Local == "tqslconfig" && t.Config == nil:
			t.Config, err = decodeConfig(d, el)
			if err != nil {
				return nil, fmt.Errorf("%w: tqslconfig: %w", ErrTQ6, err)
			}
		default:
			err = d.Skip()
		}
		if err != nil {
			return nil, tq6Err(err)
		}
	}
	// Read to the end, so trailing garbage or a bad gzip checksum is an
	// error.
	for {
		if _, err := d.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				return t, nil
			}
			return nil, tq6Err(err)
		}
	}
}

// tq6Root consumes tokens up to the root start element and checks that it
// is <tqsldata> (location.cpp:4302-4306).
func tq6Root(d *xml.Decoder) error {
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: no tqsldata element", ErrTQ6)
		}
		if err != nil {
			return tq6Err(err)
		}
		if el, ok := tok.(xml.StartElement); ok {
			if el.Name.Local != "tqsldata" {
				return fmt.Errorf("%w: root element is %s, not tqsldata", ErrTQ6, el.Name.Local)
			}
			return nil
		}
	}
}

// decodeCerts reads the children of <tqslcerts> up to its end element.
func (t *TQ6) decodeCerts(d *xml.Decoder) error {
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		if _, ok := tok.(xml.EndElement); ok {
			return nil // </tqslcerts>
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		var list *[]*x509.Certificate
		switch el.Name.Local {
		case "rootcert":
			list = &t.Roots
		case "cacert":
			list = &t.CAs
		case "usercert":
			list = &t.Users
		default:
			if err := d.Skip(); err != nil {
				return err
			}
			continue
		}
		var text xmlText
		if err := d.DecodeElement(&text, &el); err != nil {
			return err
		}
		c, err := firstPEMCert(text.Text)
		if err != nil {
			return fmt.Errorf("%s %d: %w", el.Name.Local, len(*list)+1, err)
		}
		*list = append(*list, c)
	}
}

// firstPEMCert parses the first certificate PEM block in s, as
// PEM_read_bio_X509 reads it (openssl_cert.cpp:424). OpenSSL reads PEM
// blocks in turn and skips any whose label is not CERTIFICATE or
// X509 CERTIFICATE (OpenSSL master crypto/pem/pem_lib.c:239-259, check_pem
// at 128-200). Text outside blocks is ignored. A block that is malformed as
// PEM ends the search with an error, as does a certificate block whose DER
// does not parse.
func firstPEMCert(s string) (*x509.Certificate, error) {
	for n := 1; ; n++ {
		i := pemBeginLine(s)
		if i < 0 {
			return nil, errors.New("no PEM certificate")
		}
		s = s[i:]
		// Cut at the next BEGIN line, so pem.Decode cannot skip a
		// malformed block and return a later one.
		block, rest := s, ""
		if j := pemBeginLine(s[len(pemBegin):]); j >= 0 {
			block, rest = s[:len(pemBegin)+j], s[len(pemBegin)+j:]
		}
		b, _ := pem.Decode([]byte(block))
		if b == nil {
			return nil, fmt.Errorf("PEM block %d is malformed", n)
		}
		if b.Type == "CERTIFICATE" || b.Type == "X509 CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
		s = rest
	}
}

// pemBegin opens a PEM encapsulation boundary line.
const pemBegin = "-----BEGIN "

// pemBeginLine returns the index of the first "-----BEGIN " at the start of a
// line in s, or -1.
func pemBeginLine(s string) int {
	if strings.HasPrefix(s, pemBegin) {
		return 0
	}
	if j := strings.Index(s, "\n"+pemBegin); j >= 0 {
		return j + 1
	}
	return -1
}

// tq6Err wraps a read, XML or certificate error in ErrTQ6.
func tq6Err(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("%w: %w", ErrTQ6, err)
}

// Pair finds the certificate in users whose public key is key's and returns
// the credential for it. TrustedQSL pairs a returned certificate with its
// pending key the same way, on the public key alone
// (tqsl_find_matching_key, openssl_cert.cpp:5162). Nil entries are skipped.
//
// A nil key gives an error wrapping [ErrNoKey], a key that is not RSA gives
// [ErrUnsupportedKey], and a key that matches none of users gives
// [ErrCertMismatch]. The matching certificate then goes
// through [ParseCertificate] and [NewCredential], so a certificate with no
// callsign gives [ErrNoCertificate] and a key TrustedQSL cannot sign with
// gives [ErrUnsupportedKey].
func Pair(users []*x509.Certificate, key crypto.Signer) (Credential, error) {
	pub, err := signerRSAPublic(key)
	if err != nil {
		return Credential{}, err
	}
	for _, u := range users {
		if u == nil || !pub.Equal(u.PublicKey) {
			continue
		}
		cert, err := ParseCertificate(u)
		if err != nil {
			return Credential{}, err
		}
		return NewCredential(cert, key)
	}
	return Credential{}, fmt.Errorf("%w: no certificate matches the key", ErrCertMismatch)
}

// ExportPKCS12 encodes c and the CA certificates in chain as a .p12 file
// that [LoadPKCS12] reads back. The password may be empty.
//
// The file uses go-pkcs12's Modern2023 encoder: an HMAC-SHA-256 MAC, AES-256
// PBES2 encryption, a shrouded key bag, and a localKeyID linking the key to
// the certificate. TrustedQSL needs the MAC and the shrouded key bag, and
// uses the localKeyID to find the key's certificate. Pass the ARRL CA chain:
// TrustedQSL verifies the certificate against it on import. Whether
// TrustedQSL imports this file has not yet been checked against tqsl itself.
//
// c must pass the [NewCredential] checks, or the error wraps the sentinel
// NewCredential documents. The key must also be held in memory as an
// *rsa.PrivateKey; a key in a KMS or HSM cannot be exported and gives
// [ErrUnsupportedKey]. A nil certificate in chain gives [ErrNoCertificate].
func ExportPKCS12(c Credential, chain []*x509.Certificate, password string) ([]byte, error) {
	if err := checkCredential(c.Cert, c.Signer); err != nil {
		return nil, err
	}
	key, ok := c.Signer.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T is not an exportable *rsa.PrivateKey", ErrUnsupportedKey, c.Signer)
	}
	// checkCredential only looks at the public half, so a key without its
	// private part gets this far.
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
	}
	for i, ca := range chain {
		if ca == nil {
			return nil, fmt.Errorf("%w: chain[%d] is nil", ErrNoCertificate, i)
		}
	}
	data, err := pkcs12.Modern2023.Encode(key, c.Cert.X509, chain, password)
	if err != nil {
		return nil, fmt.Errorf("gabbi: encode PKCS#12: %w", err)
	}
	return data, nil
}
