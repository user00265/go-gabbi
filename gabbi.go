package gabbi

import (
	"encoding/base64"
	"encoding/pem"
	"strconv"
	"strings"
)

// field is tqsl_adifMakeField (adif.cpp:614-651): "<NAME:len>value", with
// ":typ" after the length when typ is neither 0 nor ' ', and "<NAME>" when
// value is empty. len is the byte length of value.
func field(name string, typ byte, value string) string {
	if value == "" {
		return "<" + name + ">"
	}
	s := "<" + name + ":" + strconv.Itoa(len(value))
	if typ != 0 && typ != ' ' {
		// One raw byte, as adif.cpp:637 copies it.
		s += ":" + string([]byte{typ})
	}
	return s + ">" + value
}

// base64Lines is tqsl_encodeBase64 (tqsllib.cpp:638-685), an OpenSSL
// BIO_f_base64: standard base64 with a newline after every 64 characters
// and after the last partial line.
func base64Lines(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(enc) > 64 {
		b.WriteString(enc[:64])
		b.WriteByte('\n')
		enc = enc[64:]
	}
	if enc != "" {
		b.WriteString(enc)
		b.WriteByte('\n')
	}
	return b.String()
}

// signatureField returns the GAbbI name of the signature field for ss, such
// as "SIGN_LOTW_V2.0" (location.cpp:822-825).
func signatureField(ss Sigspec) string {
	return "SIGN_" + ss.Name + "_V" + ss.Version
}

// recCert is tqsl_getGABBItCERT (location.cpp:3667-3691): a tCERT record
// holding the certificate's PEM body, without the BEGIN and END lines but
// with every base64 line's newline. It returns "" when c has no certificate.
func recCert(c *Certificate, uid int) string {
	if c == nil || c.X509 == nil {
		return ""
	}
	// pem.EncodeToMemory writes 64-column lines, as PEM_write_bio_X509
	// does (openssl_cert.cpp:1368).
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.X509.Raw}))
	if i := strings.Index(p, "-----END CERTIFICATE-----"); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '\n'); i >= 0 {
		p = p[i+1:]
	}
	return "<Rec_Type:5>tCERT\n" +
		field("CERT_UID", 0, strconv.Itoa(uid)) + "\n" +
		"<CERTIFICATE:" + strconv.Itoa(len(p)) + ">" + p + "<eor>\n"
}

// recStation is tqsl_getGABBItSTATION (location.cpp:3694-3759): a tSTATION
// record with every location field of fs, CALL and DXCC included, one per
// line. fs comes from Config.stationFields, which leaves out empty values
// and BADZONE fields as TrustedQSL does.
func recStation(fs []stationField, uid, certUID int) string {
	var b strings.Builder
	b.WriteString("<Rec_Type:8>tSTATION\n")
	b.WriteString(field("STATION_UID", 0, strconv.Itoa(uid)) + "\n")
	b.WriteString(field("CERT_UID", 0, strconv.Itoa(certUID)) + "\n")
	for _, f := range fs {
		if f.value == "" {
			continue
		}
		b.WriteString(field(f.name, 0, f.value) + "\n")
	}
	b.WriteString("<eor>\n")
	return b.String()
}

// recContact is the record part of tqsl_getGABBItCONTACTData
// (location.cpp:3839-3897): a tCONTACT record for q with the signature sig
// in the field sigName (see signatureField) and the signed bytes signData.
// CALL, BAND, MODE, QSO_DATE and QSO_TIME are always written, as "<NAME>"
// when empty; FREQ, FREQ_RX, PROP_MODE, SAT_NAME and BAND_RX only when set.
// The signature field carries its own trailing newline.
func recContact(q QSO, stationUID int, sigName string, sig []byte, signData string) string {
	var b strings.Builder
	b.WriteString("<Rec_Type:8>tCONTACT\n")
	b.WriteString(field("STATION_UID", 0, strconv.Itoa(stationUID)) + "\n")
	b.WriteString(field("CALL", 0, q.Call) + "\n")
	b.WriteString(field("BAND", 0, q.Band) + "\n")
	b.WriteString(field("MODE", 0, q.Mode) + "\n")
	for _, f := range [...]struct{ name, value string }{
		{"FREQ", q.Freq},
		{"FREQ_RX", q.FreqRX},
		{"PROP_MODE", q.PropMode},
		{"SAT_NAME", q.SatName},
		{"BAND_RX", q.BandRX},
	} {
		if f.value != "" {
			b.WriteString(field(f.name, 0, f.value) + "\n")
		}
	}
	b.WriteString(field("QSO_DATE", 0, qsoDate(q)) + "\n")
	b.WriteString(field("QSO_TIME", 0, qsoTime(q)) + "\n")
	b.WriteString(field(sigName, '6', base64Lines(sig)))
	b.WriteString(field("SIGNDATA", 0, signData) + "\n")
	b.WriteString("<eor>\n")
	return b.String()
}
