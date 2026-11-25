package gabbi

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Line numbers in comments refer to TrustedQSL at commit 9b30153 (2.8.8):
// https://sourceforge.net/p/trustedqsl/tqsl/ci/9b301538a7b8b2766917ef23d344840686138e1f/tree/.

func TestFieldEncoding(t *testing.T) {
	// tqsl_adifMakeField (adif.cpp:614-651): "<" NAME, then ":" len and
	// ":" type (when type is not 0 or ' ') and ">" value when the value is
	// non-empty, otherwise ">" alone.
	for _, tt := range []struct {
		name  string
		typ   byte
		value string
		want  string
	}{
		{"CALL", 0, "W1AW", "<CALL:4>W1AW"},
		{"X", 0, "", "<X>"},
		{"X", '6', "", "<X>"},                 // adif.cpp:644-646: no type when empty
		{"CALL", ' ', "W1AW", "<CALL:4>W1AW"}, // adif.cpp:634
		{"SIGN_LOTW_V2.0", '6', "QUJD\n", "<SIGN_LOTW_V2.0:5:6>QUJD\n"},
	} {
		if got := field(tt.name, tt.typ, tt.value); got != tt.want {
			t.Errorf("field(%q, %q, %q) = %q, want %q", tt.name, tt.typ, tt.value, got, tt.want)
		}
	}
}

func TestFieldByteLength(t *testing.T) {
	// The length is strlen of the value (adif.cpp:625-626, 631): bytes, not
	// characters. "Doña Ana" is 8 characters and 9 bytes.
	if got, want := field("US_COUNTY", 0, "Doña Ana"), "<US_COUNTY:9>Doña Ana"; got != want {
		t.Errorf("field = %q, want %q", got, want)
	}
}

func TestRecCert(t *testing.T) {
	p := newTestPKI(t)
	c := &Certificate{X509: p.Leaf, Callsign: "KF0TST"}
	got := recCert(c, 1)

	// PEM_write_bio_X509 (openssl_cert.cpp:1368) writes 64-column base64
	// lines. tqsl_getGABBItCERT cuts at the END line (location.cpp:3674-3676)
	// and drops the first line (3677-3680).
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Leaf.Raw}))
	body := strings.TrimPrefix(pemText, "-----BEGIN CERTIFICATE-----\n")
	body = body[:strings.Index(body, "-----END CERTIFICATE-----")]
	for _, line := range strings.SplitAfter(body, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, "\n") || len(line) > 65 {
			t.Fatalf("body line %q is not a base64 line of at most 64 columns", line)
		}
	}
	// location.cpp:3681-3689.
	want := "<Rec_Type:5>tCERT\n<CERT_UID:1>1\n<CERTIFICATE:" + strconv.Itoa(len(body)) + ">" + body + "<eor>\n"
	if got != want {
		t.Errorf("recCert =\n%s\nwant\n%s", got, want)
	}
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\n", ""))
	if err != nil || !bytes.Equal(der, p.Leaf.Raw) {
		t.Errorf("body does not decode to the certificate DER (err %v)", err)
	}
}

func TestRecCertUID(t *testing.T) {
	p := newTestPKI(t)
	got := recCert(&Certificate{X509: p.Leaf}, 12)
	// "<CERT_UID:%d>%s\n" with the length of the decimal uid
	// (location.cpp:3683-3684).
	if !strings.HasPrefix(got, "<Rec_Type:5>tCERT\n<CERT_UID:2>12\n<CERTIFICATE:") {
		t.Errorf("recCert = %q", got[:min(len(got), 60)])
	}
}

func TestRecStation(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	fs, err := cfg.stationFields(usStation())
	if err != nil {
		t.Fatalf("stationFields: %v", err)
	}
	// location.cpp:3702-3709 header, 3742-3747 each field and "\n", 3757
	// "<eor>\n". The fields are every page field, CALL and DXCC included.
	const want = "<Rec_Type:8>tSTATION\n" +
		"<STATION_UID:1>1\n" +
		"<CERT_UID:1>1\n" +
		"<CALL:6>KF0TST\n" +
		"<DXCC:3>291\n" +
		"<GRIDSQUARE:6>EM10dh\n" +
		"<ITUZ:1>7\n" +
		"<CQZ:1>4\n" +
		"<US_STATE:2>TX\n" +
		"<US_COUNTY:6>Travis\n" +
		"<eor>\n"
	if got := recStation(fs, 1, 1); got != want {
		t.Errorf("recStation =\n%s\nwant\n%s", got, want)
	}
}

// testSig is a 128-byte signature, the size an RSA-1024 key gives.
func testSig() []byte {
	sig := make([]byte, 128)
	for i := range sig {
		sig[i] = byte(i * 7)
	}
	return sig
}

func TestRecContactSignatureField(t *testing.T) {
	q := workedQSO()
	const sd = "4EM10DH7TRAVISTX20MW1AW14.250SSB2026-11-0115:30:00Z"
	got := recContact(q, 1, "SIGN_LOTW_V2.0", testSig(), sd)

	// tqsl_encodeBase64 (tqsllib.cpp:638-685) runs a BIO_f_base64, which
	// writes 64-column lines, each ending in "\n", the last one included.
	// 128 bytes give 172 characters: 64 + 64 + 44, plus 3 newlines = 175.
	b64 := base64.StdEncoding.EncodeToString(testSig())
	if len(b64) != 172 {
		t.Fatalf("base64 is %d characters", len(b64))
	}
	sigText := b64[:64] + "\n" + b64[64:128] + "\n" + b64[128:] + "\n"
	// location.cpp:3891-3897: the signature field has type '6' and no
	// extra newline, then SIGNDATA, "\n" and "<eor>\n".
	wantTail := "<SIGN_LOTW_V2.0:175:6>" + sigText +
		"<SIGNDATA:" + strconv.Itoa(len(sd)) + ">" + sd + "\n<eor>\n"
	if !strings.HasSuffix(got, wantTail) {
		t.Errorf("recContact =\n%s\nwant suffix\n%s", got, wantTail)
	}
}

func TestRecContactFieldOrder(t *testing.T) {
	q := workedQSO()
	q.FreqRX = "145.9"
	q.PropMode = "SAT"
	q.SatName = "AO-7"
	q.BandRX = "2M"
	sd := "SD"
	got := recContact(q, 3, "SIGN_LOTW_V2.0", testSig(), sd)
	// location.cpp:3839-3897: STATION_UID CALL BAND MODE, then FREQ FREQ_RX
	// PROP_MODE SAT_NAME BAND_RX when set, QSO_DATE QSO_TIME, signature,
	// SIGNDATA.
	b64 := base64.StdEncoding.EncodeToString(testSig())
	want := "<Rec_Type:8>tCONTACT\n" +
		"<STATION_UID:1>3\n" +
		"<CALL:4>W1AW\n" +
		"<BAND:3>20M\n" +
		"<MODE:3>SSB\n" +
		"<FREQ:6>14.250\n" +
		"<FREQ_RX:5>145.9\n" +
		"<PROP_MODE:3>SAT\n" +
		"<SAT_NAME:4>AO-7\n" +
		"<BAND_RX:2>2M\n" +
		"<QSO_DATE:10>2026-11-01\n" +
		"<QSO_TIME:9>15:30:00Z\n" +
		"<SIGN_LOTW_V2.0:175:6>" + b64[:64] + "\n" + b64[64:128] + "\n" + b64[128:] + "\n" +
		"<SIGNDATA:2>SD\n" +
		"<eor>\n"
	if got != want {
		t.Errorf("recContact =\n%s\nwant\n%s", got, want)
	}
}

func TestRecContactOptionalOmitted(t *testing.T) {
	q := workedQSO()
	q.Freq = ""
	q.Mode = ""
	got := recContact(q, 1, "SIGN_LOTW_V2.0", testSig(), "SD")
	// CALL, BAND and MODE are always written, as "<NAME>" when empty
	// (location.cpp:3845-3853, adif.cpp:644-646). FREQ is written only when
	// set (location.cpp:3855-3859).
	want := "<Rec_Type:8>tCONTACT\n<STATION_UID:1>1\n<CALL:4>W1AW\n<BAND:3>20M\n<MODE>\n<QSO_DATE:10>2026-11-01\n<QSO_TIME:9>15:30:00Z\n<SIGN_LOTW_V2.0:"
	if !strings.HasPrefix(got, want) {
		t.Errorf("recContact =\n%s\nwant prefix\n%s", got, want)
	}
}

func TestSignatureField(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// "SIGN_" + name + "_V" + version (location.cpp:822-825) of
	// <sigspec name="LOTW" version="2.0"> (config.xml:7817).
	if got := signatureField(cfg.Sigspec()); got != "SIGN_LOTW_V2.0" {
		t.Errorf("signatureField = %q, want SIGN_LOTW_V2.0", got)
	}
}

func TestSignatureBase64(t *testing.T) {
	// BIO_f_base64 framing (tqsllib.cpp:638-685): a "\n" after every 64
	// characters and after the last partial line; no data gives no output.
	for _, n := range []int{0, 1, 47, 48, 49, 96, 128, 256} {
		data := bytes.Repeat([]byte{0xA5}, n)
		got := base64Lines(data)
		flat := base64.StdEncoding.EncodeToString(data)
		if strings.ReplaceAll(got, "\n", "") != flat {
			t.Errorf("n=%d: base64Lines content differs", n)
		}
		wantNL := (len(flat) + 63) / 64
		if strings.Count(got, "\n") != wantNL {
			t.Errorf("n=%d: %d newlines, want %d", n, strings.Count(got, "\n"), wantNL)
		}
		if n > 0 && !strings.HasSuffix(got, "\n") {
			t.Errorf("n=%d: no trailing newline", n)
		}
	}
}

var fieldRE = regexp.MustCompile(`(?s)^<([^:>]*)(?::([0-9]+)(?::(.))?)?>(.*)$`)

func FuzzField(f *testing.F) {
	f.Add("CALL", byte(0), "W1AW")
	f.Add("X", byte(0), "")
	f.Add("SIGN_LOTW_V2.0", byte('6'), "QUJD\n")
	f.Add("US_COUNTY", byte(' '), "Doña Ana")
	f.Add("A", byte('>'), "<eor>")
	f.Fuzz(func(t *testing.T, name string, typ byte, value string) {
		got := field(name, typ, value)
		// The name is copied verbatim (adif.cpp:623). Names with ':' or
		// '>' cannot be parsed back, so stop after the generic checks.
		if !strings.HasPrefix(got, "<"+name) || !strings.HasSuffix(got, value) {
			t.Fatalf("field(%q, %q, %q) = %q", name, typ, value, got)
		}
		if strings.ContainsAny(name, ":>") {
			return
		}
		m := fieldRE.FindStringSubmatch(got)
		if m == nil {
			t.Fatalf("field(%q, %q, %q) = %q does not parse", name, typ, value, got)
		}
		if m[1] != name || m[4] != value {
			t.Fatalf("round trip: name %q value %q, want %q %q", m[1], m[4], name, value)
		}
		if value == "" {
			if m[2] != "" || m[3] != "" {
				t.Fatalf("empty value has length or type: %q", got)
			}
			return
		}
		if n, err := strconv.Atoi(m[2]); err != nil || n != len(value) {
			t.Fatalf("length prefix %q, want %d", m[2], len(value))
		}
		wantType := ""
		if typ != 0 && typ != ' ' {
			wantType = string([]byte{typ})
		}
		if m[3] != wantType {
			t.Fatalf("type %q, want %q", m[3], wantType)
		}
	})
}
