package gabbi

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ARRL object identifiers under the private enterprise arc
// 1.3.6.1.4.1.12348.1 (tqsllib.cpp:64-96). They are strings, compared with
// asn1.ObjectIdentifier.String, so the package holds no mutable state.
const (
	oidCallsign     = "1.3.6.1.4.1.12348.1.1" // AROcallsign, a subject attribute
	oidQSONotBefore = "1.3.6.1.4.1.12348.1.2" // QSONotBeforeDate extension
	oidQSONotAfter  = "1.3.6.1.4.1.12348.1.3" // QSONotAfterDate extension
	oidDXCC         = "1.3.6.1.4.1.12348.1.4" // dxccEntity extension
	oidSupersedes   = "1.3.6.1.4.1.12348.1.5" // supercededCertificate extension
)

// maxKeyBits is the largest RSA key TrustedQSL can sign with. It writes each
// signature into a 129-byte buffer (location.cpp:3826), so a 2048-bit
// signature does not fit.
const maxKeyBits = 1024

// Certificate is a callsign certificate with the ARRL fields read out.
type Certificate struct {
	// X509 is the parsed certificate.
	X509 *x509.Certificate
	// Callsign is the AROcallsign subject attribute.
	Callsign string
	// DXCC is the dxccEntity extension, or 0 when the certificate has none.
	DXCC int
	// QSONotBefore and QSONotAfter bound the QSO dates the certificate may
	// sign, inclusive at both ends. This range is separate from the
	// certificate's own validity period. Either is the zero Date when the
	// certificate does not carry it; TrustedQSL skips a certificate with no
	// QSONotAfter when choosing one to sign with.
	QSONotBefore, QSONotAfter Date
	// Supersedes names the certificate this one replaces, or is nil.
	Supersedes *Superseded
}

// Superseded identifies a certificate by issuer and serial number, as held in
// the supercededCertificate extension.
type Superseded struct {
	// Issuer is the issuer name in OpenSSL's one-line form, exactly as
	// written by ARRL, for example "/C=US/.../Email=lotw@arrl.org".
	Issuer string
	// Serial is the serial number of the superseded certificate.
	Serial *big.Int
}

// ParseCertificate reads the ARRL fields from a callsign certificate.
//
// The callsign comes from the AROcallsign subject attribute; a certificate
// without one is not a callsign certificate and gives an error wrapping
// [ErrNoCertificate], as TrustedQSL rejects it on import
// (openssl_cert.cpp:2955). The QSO dates, DXCC entity and superseded
// certificate come from extensions whose OCTET STRING holds raw ASCII, which
// is how TrustedQSL reads them (openssl_cert.cpp:5414-5466). Each is
// optional, but a value that is present and malformed gives an error
// wrapping [ErrNoCertificate] that names the OID.
func ParseCertificate(c *x509.Certificate) (*Certificate, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil certificate", ErrNoCertificate)
	}
	cert := &Certificate{X509: c}
	for _, n := range c.Subject.Names {
		if n.Type.String() != oidCallsign {
			continue
		}
		if s, ok := n.Value.(string); ok && s != "" {
			cert.Callsign = s
			break
		}
	}
	if cert.Callsign == "" {
		return nil, fmt.Errorf("%w: no AROcallsign", ErrNoCertificate)
	}
	for _, e := range c.Extensions {
		var err error
		oid := e.Id.String()
		switch oid {
		case oidQSONotBefore:
			cert.QSONotBefore, err = ParseDate(string(e.Value))
		case oidQSONotAfter:
			cert.QSONotAfter, err = ParseDate(string(e.Value))
		case oidDXCC:
			cert.DXCC, err = parseDXCC(string(e.Value))
		case oidSupersedes:
			cert.Supersedes, err = parseSuperseded(string(e.Value))
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: extension %s: %w", ErrNoCertificate, oid, err)
		}
	}
	return cert, nil
}

// parseDXCC reads the dxccEntity value. TrustedQSL uses strtol(buf, NULL, 10)
// (openssl_cert.cpp:2083-2088), which skips leading white space, takes an
// optional sign and stops at the first non-digit. This parse keeps those
// leading-number rules but is stricter: it requires at least one digit and
// rejects negative and out-of-range numbers instead of returning 0 or
// clamping.
func parseDXCC(s string) (int, error) {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, fmt.Errorf("invalid DXCC entity %q", s)
	}
	n, err := strconv.Atoi(s[start:i])
	if err != nil {
		return 0, fmt.Errorf("invalid DXCC entity %q", s)
	}
	if neg && n != 0 {
		return 0, fmt.Errorf("negative DXCC entity %q", s)
	}
	return n, nil
}

// parseSuperseded reads "<issuer>;<decimal serial>" (openssl_cert.cpp:1056).
// The issuer is a one-line DN that may itself hold ';', so the split is on
// the last one.
func parseSuperseded(s string) (*Superseded, error) {
	i := strings.LastIndexByte(s, ';')
	if i <= 0 {
		return nil, fmt.Errorf("superseded certificate %q is not issuer;serial", s)
	}
	serial := s[i+1:]
	if serial == "" || strings.TrimLeft(serial, "0123456789") != "" {
		return nil, fmt.Errorf("superseded certificate serial %q is not a decimal number", serial)
	}
	n, ok := new(big.Int).SetString(serial, 10)
	if !ok {
		return nil, fmt.Errorf("superseded certificate serial %q is not a decimal number", serial)
	}
	return &Superseded{Issuer: s[:i], Serial: n}, nil
}

// Credential pairs a callsign certificate with the key that signs for it.
// Build one with [NewCredential] or [LoadPKCS12].
type Credential struct {
	// Cert is the callsign certificate.
	Cert *Certificate
	// Signer holds the certificate's private key. It may live in memory, a
	// KMS or an HSM.
	Signer crypto.Signer
}

// NewCredential checks that s can sign for c and returns the pair.
//
// The checks run in this order. The signer's public key must be RSA, and at
// most 1024 bits because TrustedQSL cannot hold a longer signature
// (location.cpp:3826); otherwise the error wraps [ErrUnsupportedKey]. It must
// then equal the certificate's public key, or the error wraps
// [ErrCertMismatch].
func NewCredential(c *Certificate, s crypto.Signer) (Credential, error) {
	if err := checkCredential(c, s); err != nil {
		return Credential{}, err
	}
	return Credential{Cert: c, Signer: s}, nil
}

// checkCredential runs the checks NewCredential documents. The Writer runs
// them again, since a Credential can also be built as a literal.
func checkCredential(c *Certificate, s crypto.Signer) error {
	if c == nil || c.X509 == nil {
		return fmt.Errorf("%w: nil certificate", ErrNoCertificate)
	}
	if s == nil {
		return fmt.Errorf("%w: nil signer", ErrNoKey)
	}
	pub, ok := s.Public().(*rsa.PublicKey)
	if !ok || pub == nil || pub.N == nil {
		return fmt.Errorf("%w: %T is not an RSA public key", ErrUnsupportedKey, s.Public())
	}
	if bits := pub.N.BitLen(); bits > maxKeyBits {
		return fmt.Errorf("%w: RSA key is %d bits, TrustedQSL signs with at most %d",
			ErrUnsupportedKey, bits, maxKeyBits)
	}
	if !pub.Equal(c.X509.PublicKey) {
		return fmt.Errorf("%w: signer key is not the key of %s's certificate", ErrCertMismatch, c.Callsign)
	}
	return nil
}

// LoadPKCS12 reads a .p12 file exported by TrustedQSL and returns the
// callsign credential and the remaining certificates, which are normally the
// ARRL CA chain, in file order.
//
// TrustedQSL usually exports without a password, so password may be empty.
// A file with no MAC at all is read even when a password is given. A wrong
// password gives an error wrapping [ErrPassword]. The user certificate is the
// one whose public key matches the private key, wherever it sits in the
// file. A file without a certificate gives [ErrNoCertificate], one without a
// key gives [ErrNoKey], a key that matches no certificate gives
// [ErrCertMismatch], and a key TrustedQSL cannot sign with gives
// [ErrUnsupportedKey]. Any other decoding failure, such as malformed or
// unsupported PKCS#12 data, is returned wrapping go-pkcs12's own error and
// no gabbi sentinel.
//
// The password never appears in returned errors. Go strings cannot be
// cleared, so callers that care should drop their copy promptly.
func LoadPKCS12(data []byte, password string) (Credential, []*x509.Certificate, error) {
	key, first, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil && password != "" && err.Error() == p12NoMAC {
		// An unprotected file has no MAC to check a password against.
		key, first, cas, err = pkcs12.DecodeChain(data, "")
	}
	if err != nil {
		return Credential{}, nil, mapPKCS12Error(err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return Credential{}, nil, fmt.Errorf("%w: %T is not a signing key", ErrUnsupportedKey, key)
	}
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return Credential{}, nil, fmt.Errorf("%w: %T is not an RSA public key", ErrUnsupportedKey, signer.Public())
	}

	// DecodeChain takes the first certificate bag as the leaf. TrustedQSL
	// writes the user certificate first, but pick it by key to be sure.
	all := append([]*x509.Certificate{first}, cas...)
	leaf := -1
	for i, c := range all {
		if pub.Equal(c.PublicKey) {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		return Credential{}, nil, fmt.Errorf("%w: no certificate in the file matches the private key", ErrCertMismatch)
	}
	chain := make([]*x509.Certificate, 0, len(all)-1)
	chain = append(chain, all[:leaf]...)
	chain = append(chain, all[leaf+1:]...)

	cert, err := ParseCertificate(all[leaf])
	if err != nil {
		return Credential{}, nil, err
	}
	cred, err := NewCredential(cert, signer)
	if err != nil {
		return Credential{}, nil, err
	}
	return cred, chain, nil
}

// Error messages go-pkcs12 v0.7.4 builds with errors.New rather than
// exporting as sentinels (pkcs12.go:494, 497, 571). They can only be matched
// by text, so recheck them whenever go-pkcs12 is upgraded.
const (
	p12NoMAC  = "pkcs12: no MAC in data"
	p12NoCert = "pkcs12: certificate missing"
	p12NoKey  = "pkcs12: private key missing"
)

// mapPKCS12Error maps the go-pkcs12 errors that have a gabbi meaning to the
// matching sentinel. Any other error is wrapped without a sentinel. The
// original error always stays in the chain for errors.Is and errors.As.
func mapPKCS12Error(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pkcs12.ErrIncorrectPassword):
		return fmt.Errorf("%w: %w", ErrPassword, err)
	case err.Error() == p12NoCert:
		return fmt.Errorf("%w: %w", ErrNoCertificate, err)
	case err.Error() == p12NoKey:
		return fmt.Errorf("%w: %w", ErrNoKey, err)
	default:
		return fmt.Errorf("gabbi: decode PKCS#12: %w", err)
	}
}
