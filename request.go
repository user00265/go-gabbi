package gabbi

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" // TrustedQSL signs request data with SHA-1.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// RequestKind selects the type of certificate request.
type RequestKind int

const (
	// NewRequest requests a new callsign certificate without a signer.
	NewRequest RequestKind = iota
	// Renewal requests a replacement signed by the existing certificate.
	// Submitting it can immediately invalidate that certificate; callers
	// should show [RenewalWarning] before submission.
	Renewal
	// Additional requests another certificate signed by an existing one.
	Additional
)

// RenewalWarning is TrustedQSL's warning about submitting a renewal.
const RenewalWarning = "Note that if you renew Callsign Certificate before it expires, requesting the renewal immediately invalidates the existing Callsign Certificate."

// Request describes a callsign certificate request. Signer is required for
// Renewal and Additional and must match the callsign for Renewal.
type Request struct {
	Kind                                                                    RequestKind
	Callsign, Name, Email, Address1, Address2, City, State, Postal, Country string
	DXCC                                                                    int
	QSONotBefore, QSONotAfter                                               Date
	Signer                                                                  *Credential
}

// BuildRequest creates a .tq5 request and a fresh RSA-1024 private key. The
// caller owns the key and can later pair it with the issued certificate.
// No request is submitted. Validation errors wrap [ErrInvalidRequest]; an
// renewal whose expiry date is at least 180 UTC calendar days ago also wraps
// [ErrExpired]. TrustedQSL's separate status and supersession checks require
// information this function does not have.
// Request dates must fall within the selected DXCC entity's validity dates.
// An open end is replaced by the entity's end date when it has one. Entity
// NONE (DXCC 0) requires a signed request.
//
// random must be non-nil. It is passed to Go's crypto functions and the
// external signer. Since Go 1.26, crypto functions normally ignore custom
// readers and use a secure global source; their behavior depends on Go's
// cryptocustomrand setting. Do not rely on deterministic key generation.
func BuildRequest(cfg *Config, req Request, id Ident, random io.Reader) ([]byte, *rsa.PrivateKey, error) {
	if cfg == nil || isNilRequestValue(random) {
		return nil, nil, fmt.Errorf("%w: nil config or random reader", ErrInvalidRequest)
	}
	var err error
	req, err = validateRequest(cfg, req)
	if err != nil {
		return nil, nil, err
	}
	key, err := rsa.GenerateKey(random, 1024)
	if err != nil {
		return nil, nil, fmt.Errorf("gabbi: generate request key: %w", err)
	}
	subject := pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 1}, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(req.Callsign)}},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(req.Name)}},
		{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(req.Email)}},
	}}
	der, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{Subject: subject, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("gabbi: create certificate request: %w", err)
	}
	marker := [...]string{"TQSL_CRQ_NEW", "TQSL_CRQ_RENEWAL", "TQSL_CRQ_ADDITIONAL"}[req.Kind]
	program, version := id.Program, id.Version
	if program == "" {
		program = "go-gabbi"
	}
	if version == "" {
		version = "0.0.0"
	}
	major, minor := cfg.Version()
	name, unit := cfg.Provider()
	var b strings.Builder
	b.WriteString("\ntQSL certificate request\n\n<eoh>\n\n")
	write := func(name, value string) {
		if value == "" {
			b.WriteString("<" + name + ":0>")
		} else {
			b.WriteString(field(name, 0, value))
		}
		b.WriteString("\n\n")
	}
	write("TQSL_IDENT", fmt.Sprintf("%s: %s, Lib: V%s, Config: %d.%d", program, version, version, major, minor))
	b.WriteString("<" + marker + ">\n\n")
	for _, f := range []struct{ name, value string }{
		{"PROVIDER", requestTrim(name)}, {"PROVIDER_UNIT", requestTrim(unit)}, {"EMAIL", req.Email}, {"NAME", req.Name},
		{"ADDRESS1", req.Address1}, {"ADDRESS2", req.Address2}, {"CITY", req.City}, {"STATE", req.State},
		{"POSTAL", req.Postal}, {"COUNTRY", req.Country}, {"DXCC_ENTITY", strconv.Itoa(req.DXCC)}, {"QSO_NOT_BEFORE", req.QSONotBefore.String()},
	} {
		write("TQSL_CRQ_"+f.name, f.value)
	}
	if !req.QSONotAfter.IsZero() {
		write("TQSL_CRQ_QSO_NOT_AFTER", req.QSONotAfter.String())
	}
	write("TQSL_CRQ_REQUEST", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
	if req.Kind != NewRequest {
		digest := sha1.Sum(der)
		sig, err := req.Signer.Signer.Sign(random, digest[:], crypto.SHA1)
		if err != nil {
			return nil, nil, fmt.Errorf("gabbi: sign certificate request: %w", err)
		}
		pub := req.Signer.Cert.X509.PublicKey.(*rsa.PublicKey)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest[:], sig); err != nil {
			return nil, nil, fmt.Errorf("gabbi: invalid request signature: %w", err)
		}
		write("TQSL_CRQ_SIGNATURE", base64Lines(sig))
		issuer := onelineName(req.Signer.Cert.X509.RawIssuer)
		if len(issuer) > 255 {
			issuer = issuer[:255]
		}
		write("TQSL_CRQ_SIGNATURE_CERT_ISSUER", issuer)
		write("TQSL_CRQ_SIGNATURE_CERT_SERIAL", req.Signer.Cert.X509.SerialNumber.String())
	}
	b.WriteString("<eor>\n\n")
	return []byte(b.String()), key, nil
}

func isNilRequestValue(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

func requestTrim(s string) string {
	s = trimC(s)
	var b strings.Builder
	space := false
	for i := 0; i < len(s); i++ {
		if isCSpace(s[i]) {
			if !space {
				b.WriteByte(' ')
			}
			space = true
		} else {
			b.WriteByte(s[i])
			space = false
		}
	}
	return b.String()
}

func validateRequest(cfg *Config, r Request) (Request, error) {
	values := []*string{&r.Callsign, &r.Name, &r.Email, &r.Address1, &r.Address2, &r.City, &r.State, &r.Postal, &r.Country}
	for _, value := range values {
		if !utf8.ValidString(*value) || strings.ContainsRune(*value, 0) {
			return r, fmt.Errorf("%w: invalid text", ErrInvalidRequest)
		}
		*value = requestTrim(*value)
	}
	r.Callsign = asciiUpper(r.Callsign)
	for _, f := range []struct{ value, label string }{{r.Name, "Name"}, {r.Callsign, "Call Sign"}, {r.Address1, "Address"}, {r.City, "City"}, {r.Country, "Country"}, {r.Email, "Email address"}} {
		if f.value == "" {
			return r, fmt.Errorf("%w: Missing parameter: %s", ErrInvalidRequest, f.label)
		}
	}
	if r.Kind < NewRequest || r.Kind > Additional {
		return r, fmt.Errorf("%w: unknown request kind", ErrInvalidRequest)
	}
	if len(r.Callsign) > 20 || !checkCallSign(r.Callsign) {
		return r, fmt.Errorf("%w: invalid callsign", ErrInvalidRequest)
	}
	at, dot := strings.IndexByte(r.Email, '@'), strings.LastIndexByte(r.Email, '.')
	if at < 1 || dot < at+2 || dot >= len(r.Email)-1 {
		return r, fmt.Errorf("%w: invalid email", ErrInvalidRequest)
	}
	for i := 0; i < len(r.Email); i++ {
		if r.Email[i] >= 128 {
			return r, fmt.Errorf("%w: email must be IA5", ErrInvalidRequest)
		}
	}
	entity, ok := cfg.dxcc(r.DXCC)
	if !ok || r.DXCC < 0 {
		return r, fmt.Errorf("%w: invalid DXCC entity", ErrInvalidRequest)
	}
	if !r.QSONotBefore.valid() || !r.QSONotAfter.IsZero() && (!r.QSONotAfter.valid() || r.QSONotAfter.Compare(r.QSONotBefore) < 0) {
		return r, fmt.Errorf("%w: invalid QSO date range", ErrInvalidRequest)
	}
	// init_dxcc defaults a missing or invalid start to 1945-11-15 and an
	// invalid end to the null date (location.cpp:919-936).
	start := Date{1945, time.November, 15}
	if d, err := ParseDate(entity.valid); err == nil {
		start = d
	}
	end, _ := ParseDate(entity.invalid)
	if r.QSONotBefore.Compare(start) < 0 || !end.IsZero() && r.QSONotBefore.Compare(end) > 0 {
		return r, fmt.Errorf("%w: QSO start date outside DXCC validity", ErrInvalidRequest)
	}
	if r.QSONotAfter.IsZero() {
		r.QSONotAfter = end
	} else if r.QSONotAfter.Compare(start) < 0 || !end.IsZero() && r.QSONotAfter.Compare(end) > 0 {
		return r, fmt.Errorf("%w: QSO end date outside DXCC validity", ErrInvalidRequest)
	}
	if r.DXCC == 0 && r.Kind == NewRequest {
		return r, fmt.Errorf("%w: DXCC NONE requires a signed request", ErrInvalidRequest)
	}
	if r.Kind == NewRequest {
		if r.Signer != nil {
			return r, fmt.Errorf("%w: new request has signer", ErrInvalidRequest)
		}
		return r, nil
	}
	if r.Signer == nil || isNilRequestValue(r.Signer.Signer) {
		return r, fmt.Errorf("%w: missing signer", ErrInvalidRequest)
	}
	if k, ok := r.Signer.Signer.(*rsa.PrivateKey); ok {
		if err := k.Validate(); err != nil {
			return r, fmt.Errorf("%w: invalid signer key", ErrInvalidRequest)
		}
	}
	c := r.Signer.Cert
	if c == nil || c.X509 == nil {
		return r, fmt.Errorf("%w: missing signer certificate", ErrInvalidRequest)
	}
	pub, ok := c.X509.PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E < 3 || pub.E%2 == 0 {
		return r, fmt.Errorf("%w: invalid signer public key", ErrInvalidRequest)
	}
	if err := checkCredential(c, r.Signer.Signer); err != nil {
		return r, fmt.Errorf("%w: signer: %w", ErrInvalidRequest, err)
	}
	if c.X509.SerialNumber == nil || c.X509.SerialNumber.Sign() < 0 || onelineName(c.X509.RawIssuer) == "" {
		return r, fmt.Errorf("%w: invalid signer certificate issuer or serial", ErrInvalidRequest)
	}
	if r.Kind == Renewal {
		if !strings.EqualFold(r.Callsign, c.Callsign) {
			return r, fmt.Errorf("%w: renewal callsign does not match signer", ErrInvalidRequest)
		}
		now := time.Now().UTC()
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		// tqsl_subtractDates(expiry, today) < 180 (openssl_cert.cpp:977-982).
		if DateOf(c.X509.NotAfter).Compare(DateOf(today.AddDate(0, 0, -180))) <= 0 {
			return r, fmt.Errorf("%w: %w: renewal is at least 180 days after expiry", ErrInvalidRequest, ErrExpired)
		}
	}
	return r, nil
}
