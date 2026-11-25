package gabbi

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Line numbers in comments refer to testdata/config-11.35.xml, which is
// TrustedQSL's src/config.xml (sha256 5a0747d3...3538).

func gunzipTestdata(t testing.TB, name string) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(readTestdata(t, name)))
	if err != nil {
		t.Fatalf("gzip.NewReader(%s): %v", name, err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip %s: %v", name, err)
	}
	return b
}

func gzipBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// replaceOnce replaces exactly one occurrence of old in b and fails the test
// if old does not occur exactly once.
func replaceOnce(t testing.TB, b []byte, old, new string) []byte {
	t.Helper()
	if n := bytes.Count(b, []byte(old)); n != 1 {
		t.Fatalf("%q occurs %d times, want 1", old, n)
	}
	return bytes.Replace(b, []byte(old), []byte(new), 1)
}

// dropSection removes the first <name>...</name> element from b.
func dropSection(t testing.TB, b []byte, name string) []byte {
	t.Helper()
	open := []byte("<" + name + ">")
	end := []byte("</" + name + ">")
	i := bytes.Index(b, open)
	j := bytes.Index(b, end)
	if i < 0 || j < i {
		t.Fatalf("section %s not found", name)
	}
	out := slices.Clone(b[:i])
	return append(out, b[j+len(end):]...)
}

// minimalConfig is the smallest config ParseConfig accepts, with the given
// <sigspecs> body.
func minimalConfig(sigspecs string) string {
	return `<tqslconfig majorversion="11" minorversion="34">
<sigspecs>` + sigspecs + `</sigspecs>
<bands><band high="14350" low="14000" spectrum="HF">20M</band></bands>
<modes><mode group="CW">CW</mode></modes>
<adifmap><adifmode adif-mode="CW" mode="CW">CW</adifmode></adifmap>
<propmodes><propmode name="SAT">Satellite</propmode></propmodes>
<satellites><satellite name="AO-7" startDate="1974-11-15">AMSAT-OSCAR 7</satellite></satellites>
<dxcc><entity arrlId="291" deleted="0" valid="1945-11-15 00:00:00" zonemap="08:05">UNITED STATES OF AMERICA</entity></dxcc>
<locfields><field Id="CALL" flags="0" intype="2" label="Call Sign" len="20" type="C" /></locfields>
<locpages><page Id="1" follows="0"><pageField>CALL</pageField></page></locpages>
</tqslconfig>`
}

const minimalSigspec = `<sigspec name="LOTW" version="2.0"><tCONTACT><CALL required="1" /></tCONTACT><tSTATION><GRIDSQUARE /></tSTATION></sigspec>`

func TestParseConfigFormats(t *testing.T) {
	tests := []struct {
		name         string
		data         func(t *testing.T) []byte
		major, minor int
	}{
		{"gzip tq6", func(t *testing.T) []byte { return readTestdata(t, "config-11.34.tq6") }, 11, 34},
		{"tqsldata wrapper", func(t *testing.T) []byte { return gunzipTestdata(t, "config-11.34.tq6") }, 11, 34},
		{"bare tqslconfig", func(t *testing.T) []byte { return readTestdata(t, "config-11.35.xml") }, 11, 35},
		{"bare tqslconfig gzipped", func(t *testing.T) []byte { return gzipBytes(t, readTestdata(t, "config-11.35.xml")) }, 11, 35},
		{"minimal inline", func(*testing.T) []byte { return []byte(minimalConfig(minimalSigspec)) }, 11, 34},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(bytes.NewReader(tt.data(t)))
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			major, minor := cfg.Version()
			if major != tt.major || minor != tt.minor {
				t.Errorf("Version() = %d.%d, want %d.%d", major, minor, tt.major, tt.minor)
			}
		})
	}
}

func TestParseConfigOutOfOrderSectionsWithProlog(t *testing.T) {
	// TrustedQSL's XMLElementList indexes children by name (xml.h:31,161-166).
	xml := `<?xml version="1.0"?><tqsldata><tqslconfig majorversion="11" minorversion="34">` +
		`<locpages><page Id="1" follows="0"><pageField>CALL</pageField></page></locpages>` +
		`<locfields><field Id="CALL" flags="0" intype="2" label="Call Sign" len="20" type="C" /></locfields>` +
		`<dxcc><entity arrlId="291" deleted="0" valid="1945-11-15 00:00:00" zonemap="08:05">UNITED STATES OF AMERICA</entity></dxcc>` +
		`<satellites><satellite name="AO-7" startDate="1974-11-15">AMSAT-OSCAR 7</satellite></satellites>` +
		`<propmodes><propmode name="SAT">Satellite</propmode></propmodes>` +
		`<adifmap><adifmode adif-mode="CW" mode="CW">CW</adifmode></adifmap>` +
		`<modes><mode group="CW">CW</mode></modes><bands><band high="14350" low="14000" spectrum="HF">20M</band></bands>` +
		`<sigspecs>` + minimalSigspec + `</sigspecs></tqslconfig></tqsldata>`
	cfg, err := ParseConfig(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if major, minor := cfg.Version(); major != 11 || minor != 34 {
		t.Fatalf("Version = %d.%d, want 11.34", major, minor)
	}
	if cfg.Sigspec().Name != "LOTW" || !cfg.hasMode("CW") {
		t.Fatal("out-of-order sections were not decoded")
	}
}

func TestParseConfigEquivalent(t *testing.T) {
	c34 := loadTestConfig(t, "config-11.34.tq6")
	c35 := loadTestConfig(t, "config-11.35.xml")

	if !reflect.DeepEqual(c34.Sigspec(), c35.Sigspec()) {
		t.Errorf("Sigspec differs:\n11.34 %+v\n11.35 %+v", c34.Sigspec(), c35.Sigspec())
	}

	p34, p35 := c34.pages(), c35.pages()
	if len(p34) != len(p35) {
		t.Fatalf("page count: 11.34 %d, 11.35 %d", len(p34), len(p35))
	}
	for i := range p34 {
		a, b := p34[i], p35[i]
		if a.id != b.id || a.follows != b.follows || a.dependsOn != b.dependsOn ||
			a.dependency != b.dependency || !slices.Equal(a.fields, b.fields) {
			t.Errorf("page %d differs:\n11.34 %+v\n11.35 %+v", i, a, b)
		}
	}

	ids := func(c *Config) []string {
		var out []string
		for id := range c.fields {
			out = append(out, id)
		}
		slices.Sort(out)
		return out
	}
	if a, b := ids(c34), ids(c35); !slices.Equal(a, b) {
		t.Errorf("locField ids differ:\n11.34 %v\n11.35 %v", a, b)
	}

	// knowledge.md §10.1.3: 11.35 adds RS95S (config.xml:7814).
	if !c35.hasSatellite("RS95S") {
		t.Error("11.35 hasSatellite(RS95S) = false, want true")
	}
	if c34.hasSatellite("RS95S") {
		t.Error("11.34 hasSatellite(RS95S) = true, want false")
	}
}

func TestParseConfigOutdated(t *testing.T) {
	x35 := readTestdata(t, "config-11.35.xml")

	t.Run("11.31 rejected", func(t *testing.T) {
		_, err := ParseConfig(bytes.NewReader(replaceOnce(t, x35, `minorversion="35"`, `minorversion="31"`)))
		if !errors.Is(err, ErrConfigOutdated) {
			t.Fatalf("err = %v, want ErrConfigOutdated", err)
		}
		for _, s := range []string{"11.31", "11.34", "config.tq6"} {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("error %q does not contain %q", err, s)
			}
		}
	})

	t.Run("10.35 rejected", func(t *testing.T) {
		_, err := ParseConfig(bytes.NewReader(replaceOnce(t, x35, `majorversion="11"`, `majorversion="10"`)))
		if !errors.Is(err, ErrConfigOutdated) {
			t.Fatalf("err = %v, want ErrConfigOutdated", err)
		}
	})

	accepted := []struct {
		name         string
		data         func(t *testing.T) []byte
		major, minor int
	}{
		{"11.34 accepted", func(t *testing.T) []byte { return readTestdata(t, "config-11.34.tq6") }, 11, 34},
		{"11.99 accepted", func(t *testing.T) []byte {
			return replaceOnce(t, x35, `minorversion="35"`, `minorversion="99"`)
		}, 11, 99},
		{"12.0 accepted", func(t *testing.T) []byte {
			b := replaceOnce(t, x35, `majorversion="11"`, `majorversion="12"`)
			return replaceOnce(t, b, `minorversion="35"`, `minorversion="0"`)
		}, 12, 0},
	}
	for _, tt := range accepted {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(bytes.NewReader(tt.data(t)))
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if major, minor := cfg.Version(); major != tt.major || minor != tt.minor {
				t.Errorf("Version() = %d.%d, want %d.%d", major, minor, tt.major, tt.minor)
			}
		})
	}
}

func TestParseConfigMissingVersion(t *testing.T) {
	x35 := readTestdata(t, "config-11.35.xml")
	tests := []struct {
		name string
		data []byte
	}{
		{"both", replaceOnce(t, x35, `<tqslconfig majorversion="11" minorversion="35">`, `<tqslconfig>`)},
		{"major", replaceOnce(t, x35, `majorversion="11" `, ``)},
		{"minor", replaceOnce(t, x35, ` minorversion="35"`, ``)},
		{"not a number", replaceOnce(t, x35, `minorversion="35"`, `minorversion="x"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig(bytes.NewReader(tt.data))
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("err = %v, want ErrConfig", err)
			}
			if errors.Is(err, ErrConfigOutdated) {
				t.Errorf("err = %v, must not be ErrConfigOutdated", err)
			}
		})
	}
}

func TestSigspecPicksNewest(t *testing.T) {
	// config.xml:7816-7848, sigspec LOTW 2.0.
	wantStation := strings.Fields("AU_STATE CA_PROVINCE CA_US_PARK CN_PROVINCE CQZ DX_US_PARK FI_KUNTA GRIDSQUARE IOTA ITUZ JA_CITY_GUN_KU JA_PREFECTURE RU_OBLAST US_COUNTY US_PARK US_STATE")
	wantContact := strings.Fields("BAND BAND_RX CALL FREQ FREQ_RX MODE PROP_MODE QSO_DATE QSO_TIME SAT_NAME")
	required := map[string]bool{"BAND": true, "CALL": true, "MODE": true, "QSO_DATE": true, "QSO_TIME": true}

	for _, name := range []string{"config-11.34.tq6", "config-11.35.xml"} {
		t.Run(name, func(t *testing.T) {
			ss := loadTestConfig(t, name).Sigspec()
			if ss.Name != "LOTW" || ss.Version != "2.0" {
				t.Errorf("sigspec = %s %s, want LOTW 2.0", ss.Name, ss.Version)
			}
			var station, contact []string
			for _, f := range ss.Station {
				station = append(station, f.Name)
				if f.Required {
					t.Errorf("tSTATION %s Required = true, want false", f.Name)
				}
			}
			for _, f := range ss.Contact {
				contact = append(contact, f.Name)
				if f.Required != required[f.Name] {
					t.Errorf("tCONTACT %s Required = %v, want %v", f.Name, f.Required, required[f.Name])
				}
			}
			if !slices.Equal(station, wantStation) {
				t.Errorf("Station = %v\nwant %v", station, wantStation)
			}
			if !slices.Equal(contact, wantContact) {
				t.Errorf("Contact = %v\nwant %v", contact, wantContact)
			}
		})
	}
}

func TestSigspecReturnsCopy(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	ss := cfg.Sigspec()
	ss.Station[0].Name = "CHANGED"
	ss.Contact[0].Required = false
	again := cfg.Sigspec()
	if again.Station[0].Name != "AU_STATE" || !again.Contact[0].Required {
		t.Errorf("Sigspec() shares its slices with the Config: %+v", again)
	}
}

func TestSigspecDeprecatedQuirk(t *testing.T) {
	// location.cpp:807-820: the seed is the first sigspec, and only later
	// candidates are skipped when deprecated.
	sig := func(version, status string) string {
		if status != "" {
			status = ` status="` + status + `"`
		}
		return `<sigspec name="LOTW" version="` + version + `"` + status +
			`><tCONTACT><CALL required="1" /></tCONTACT><tSTATION><GRIDSQUARE /></tSTATION></sigspec>`
	}
	tests := []struct {
		name, sigspecs, want string
	}{
		{"deprecated first wins", sig("3.0", "deprecated") + sig("2.0", ""), "3.0"},
		{"deprecated second skipped", sig("2.0", "") + sig("3.0", "deprecated"), "2.0"},
		{"newest wins", sig("1.0", "") + sig("2.0", ""), "2.0"},
		{"equal keeps first", sig("2.0", "") + sig("2.00", ""), "2.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(strings.NewReader(minimalConfig(tt.sigspecs)))
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if got := cfg.Sigspec().Version; got != tt.want {
				t.Errorf("Sigspec().Version = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSigspecFieldOrder(t *testing.T) {
	// TrustedQSL keeps child elements in a std::multimap keyed by element
	// name (xml.h:31, xml.cpp:156-158), so make_sign_data and
	// tqsl_getGABBItCONTACTData walk tSTATION and tCONTACT in name order,
	// not document order. Equal names keep document order.
	sigspecs := `<sigspec name="LOTW" version="2.0"><tCONTACT><QSO_DATE required="1" /><BAND required="1" /><CALL /></tCONTACT>` +
		`<tSTATION><US_STATE /><CQZ /><GRIDSQUARE /></tSTATION></sigspec>`
	cfg, err := ParseConfig(strings.NewReader(minimalConfig(sigspecs)))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	ss := cfg.Sigspec()
	want := []SpecField{{"BAND", true}, {"CALL", false}, {"QSO_DATE", true}}
	if !slices.Equal(ss.Contact, want) {
		t.Errorf("Contact = %v, want %v", ss.Contact, want)
	}
	wantStation := []SpecField{{"CQZ", false}, {"GRIDSQUARE", false}, {"US_STATE", false}}
	if !slices.Equal(ss.Station, wantStation) {
		t.Errorf("Station = %v, want %v", ss.Station, wantStation)
	}
}

func TestBandOrder(t *testing.T) {
	// config.xml:154-186 sorted by operator< (location.cpp:175-195): suffix
	// M, then CM, then MM, then anything else; larger number first.
	want := strings.Fields(`2190M 630M 160M 80M 60M 40M 30M 20M 17M 15M 12M 10M 8M 6M 4M 2M 1.25M
		70CM 33CM 23CM 13CM 9CM 6CM 3CM 1.25CM 6MM 4MM 2.5MM 2MM 1MM SUBMM`)
	cfg := loadTestConfig(t, "config-11.35.xml")
	var got []string
	for _, b := range cfg.bands {
		got = append(got, b.name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("band order:\n got %v\nwant %v", got, want)
	}

	b, ok := cfg.band("20M") // config.xml:165
	if !ok || b.low != 14000 || b.high != 14350 || b.spectrum != "HF" {
		t.Errorf("band(20M) = %+v, %v", b, ok)
	}
	b, ok = cfg.band("SUBMM") // config.xml:184
	if !ok || b.low != 300000 || b.high != 2000000000 || b.spectrum != "UHF" {
		t.Errorf("band(SUBMM) = %+v, %v", b, ok)
	}
	if _, ok := cfg.band("20m"); ok {
		t.Error("band(20m) found; band names are case-sensitive")
	}
}

func TestInferBand(t *testing.T) {
	// tqslconvert.cpp:603-637 over config.xml:154-186.
	cfg := loadTestConfig(t, "config-11.35.xml")
	tests := []struct{ freq, want string }{
		{"14.074", "20M"},
		{"10.1", "30M"},  // relaxed low edge 10000 kHz
		{"10.05", "30M"}, // 10050 kHz >= 10000
		{"144.2", "2M"},
		{"2400", "13CM"},
		{"0", ""},
		{"abc", ""},
		{"", ""},
		{"14.074abc", "20M"}, // atof reads the numeric prefix
		{" 7.074", "40M"},    // atof skips leading whitespace
		{"18.0", "17M"},      // relaxed low edge 18000 kHz
		{"24.5", "12M"},      // relaxed low edge 24000 kHz
		{"0.136", "2190M"},
		{"1.25", ""},
		{"222", "1.25M"},
		{"10368", "3CM"},
		{"1000000", "SUBMM"},
		{"-14.074", ""},
	}
	for _, tt := range tests {
		if got := cfg.inferBand(tt.freq); got != tt.want {
			t.Errorf("inferBand(%q) = %q, want %q", tt.freq, got, tt.want)
		}
	}
}

func TestInferBandOpenHigh(t *testing.T) {
	// tqslconvert.cpp:625-626: a non-HF band with high == 0 has no upper edge.
	cfg, err := ParseConfig(strings.NewReader(strings.Replace(minimalConfig(minimalSigspec),
		`<bands><band high="14350" low="14000" spectrum="HF">20M</band></bands>`,
		`<bands><band high="0" low="300000" spectrum="UHF">SUBMM</band></bands>`, 1)))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if got := cfg.inferBand("9e9"); got != "" {
		// No exponent support: "9e9" reads as 9.
		t.Errorf("inferBand(9e9) = %q, want empty", got)
	}
	if got := cfg.inferBand("500000"); got != "SUBMM" {
		t.Errorf("inferBand(500000) = %q, want SUBMM", got)
	}
}

func TestAtof(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"14.074", 14.074},
		{"14.074abc", 14.074},
		{"abc", 0},
		{"", 0},
		{"  3.5", 3.5},
		{"+2", 2},
		{"-2.5", -2.5},
		{".5", 0.5},
		{"5.", 5},
		{"14.074.5", 14.074},
		// C atof gives 1000 (C11 7.22.1.3). This helper keeps only the
		// decimal prefix; unreachable for FREQ because NormalizeQSO rejects
		// non-ADIF-Number values (Ruling AR).
		{"1e3", 1},
		{"-", 0},
		{".", 0},
	}
	for _, tt := range tests {
		if got := atof(tt.in); got != tt.want {
			t.Errorf("atof(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestMapMode(t *testing.T) {
	// Map: config.xml:13,67,68,139,140 (init_adif_map, location.cpp:1486-1540).
	// Lookup order: tqslconvert.cpp:1409-1427.
	cfg := loadTestConfig(t, "config-11.35.xml")
	tests := []struct{ mode, submode, want string }{
		{"MFSK", "FT4", "FT4"},  // :67
		{"MFSK", "JS8", "DATA"}, // :68
		{"SSB", "USB", "SSB"},   // :139
		{"usb", "", "SSB"},      // text key USB, query uppercased
		{"CW", "", "CW"},        // :13 maps CW to CW
		{"DATA", "", ""},        // a mode, but no adifmap key
		{"mfsk", "ft4", "FT4"},  // mode%submode, uppercased
		{"XYZ", "FT4", "FT4"},   // bare submode fallback
		{"CW", "XYZ", "CW"},     // mode fallback
		{"XYZ", "XYZ", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		if got := cfg.mapMode(tt.mode, tt.submode); got != tt.want {
			t.Errorf("mapMode(%q, %q) = %q, want %q", tt.mode, tt.submode, got, tt.want)
		}
	}
	// config.xml:7621-7622.
	for _, m := range []string{"CW", "DATA"} {
		if !cfg.hasMode(m) {
			t.Errorf("hasMode(%q) = false, want true", m)
		}
	}
	if cfg.hasMode("cw") {
		t.Error(`hasMode("cw") = true; the mode set is case-sensitive`)
	}
}

func TestPropMode(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	if !cfg.hasPropMode("SAT") { // config.xml:7690
		t.Error("hasPropMode(SAT) = false, want true")
	}
	if cfg.hasPropMode("Satellite") {
		t.Error("hasPropMode(Satellite) = true; the key is the name attribute")
	}
}

func TestSatelliteCaseQuirk(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	if !cfg.hasSatellite("AO-7") { // config.xml:7711
		t.Error("hasSatellite(AO-7) = false, want true")
	}
	// config.xml:7722 names it "Arsene"; TQSL uppercases SAT_NAME first, so
	// it never validates.
	if cfg.hasSatellite("ARSENE") {
		t.Error("hasSatellite(ARSENE) = true, want false")
	}
}

func TestLocPages(t *testing.T) {
	// config.xml:7513-7611.
	cfg := loadTestConfig(t, "config-11.35.xml")
	pages := cfg.pages()
	if len(pages) == 0 || pages[0].id != 1 || pages[0].follows != 0 {
		t.Fatalf("first page = %+v, want Id 1 follows 0", pages)
	}
	want1 := strings.Fields("CALL DXCC GRIDSQUARE ITUZ CQZ IOTA ZERR")
	if !slices.Equal(pages[0].fields, want1) {
		t.Errorf("page 1 fields = %v, want %v", pages[0].fields, want1)
	}
	for i := 1; i < len(pages); i++ {
		if pages[i-1].id >= pages[i].id {
			t.Errorf("pages not in Id order: %d then %d", pages[i-1].id, pages[i].id)
		}
	}

	var next *locPage
	for i := range pages {
		p := &pages[i]
		if p.follows == 1 && p.dependsOn == "DXCC" && p.dependency == "291" {
			next = p
			break
		}
	}
	if next == nil {
		t.Fatal("no page follows 1 with DXCC=291")
	}
	if next.id != 2 {
		t.Errorf("DXCC 291 page Id = %d, want 2", next.id)
	}
	want2 := strings.Fields("US_STATE US_COUNTY US_PARK ZERR")
	if !slices.Equal(next.fields, want2) {
		t.Errorf("DXCC 291 page fields = %v, want %v", next.fields, want2)
	}
}

func TestLocField(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")

	// config.xml:784.
	f, ok := cfg.locField("CQZ")
	if !ok || f.typ != "I" || f.intype != 2 || f.flags != 0 || f.lower != 1 || f.upper != 40 || f.dependsOn != "" {
		t.Errorf("CQZ = %+v, %v", f, ok)
	}
	// config.xml:1317.
	f, ok = cfg.locField("IOTA")
	if !ok || f.typ != "C" || f.intype != 1 || f.flags&1 == 0 {
		t.Errorf("IOTA = %+v, %v", f, ok)
	}
	// config.xml:7511.
	if f, ok = cfg.locField("ZERR"); !ok || f.intype != 4 {
		t.Errorf("ZERR = %+v, %v", f, ok)
	}
	// config.xml:7451-7453: flags 4 (SELNXT), dependsOn DXCC, enums by entity.
	f, ok = cfg.locField("US_STATE")
	if !ok || f.flags != 4 || f.dependsOn != "DXCC" {
		t.Fatalf("US_STATE = %+v, %v", f, ok)
	}
	if hi := f.enums["110"]; len(hi) != 1 || hi[0].value != "HI" || hi[0].label != "Hawaii" ||
		!slices.Equal(hi[0].zonemap, []zone{{itu: 61, cq: 31}}) {
		t.Errorf("US_STATE enums[110] = %+v", hi)
	}
	// config.xml:5899, 6126.
	f, _ = cfg.locField("US_COUNTY")
	if f.dependsOn != "US_STATE" || !slices.ContainsFunc(f.enums["TX"], func(e enumItem) bool {
		return e.value == "Travis" && e.label == "Travis"
	}) {
		t.Errorf("US_COUNTY enums[TX] lacks Travis (dependsOn %q)", f.dependsOn)
	}
	// config.xml:813-814: area attribute.
	f, _ = cfg.locField("FI_KUNTA")
	if k := f.enums["224"]; len(k) == 0 || k[0].value != "100" || k[0].label != "Somero" || k[0].area != "1" {
		t.Errorf("FI_KUNTA enums[224][0] = %+v", k)
	}
	// config.xml:700-701: enums without a dependency use the "" key.
	f, _ = cfg.locField("AU_STATE")
	if a := f.enums[""]; len(a) != 8 || a[0].value != "ACT" {
		t.Errorf("AU_STATE enums[\"\"] = %+v", a)
	}
	if _, ok := cfg.locField("NOPE"); ok {
		t.Error("locField(NOPE) found")
	}
}

func TestDXCC(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	// config.xml:579.
	e, ok := cfg.dxcc(291)
	if !ok || e.arrlID != 291 || e.name != "UNITED STATES OF AMERICA" || e.deleted ||
		e.valid != "1945-11-15 00:00:00" || e.invalid != "" {
		t.Errorf("dxcc(291) = %+v, %v", e, ok)
	}
	wantZones := []zone{{8, 5}, {8, 4}, {7, 4}, {7, 3}, {6, 4}, {6, 3}}
	if !slices.Equal(e.zonemap, wantZones) {
		t.Errorf("dxcc(291).zonemap = %v, want %v", e.zonemap, wantZones)
	}
	// config.xml:297.
	e, ok = cfg.dxcc(2)
	if !ok || !e.deleted || e.invalid != "1991-03-31 00:00:00" {
		t.Errorf("dxcc(2) = %+v, %v", e, ok)
	}
	// config.xml:295: no zonemap.
	if e, ok = cfg.dxcc(0); !ok || e.name != "-NONE-" || e.zonemap != nil {
		t.Errorf("dxcc(0) = %+v, %v", e, ok)
	}
	if _, ok := cfg.dxcc(99999); ok {
		t.Error("dxcc(99999) found")
	}
}

// bombStream returns a gzip stream that opens a <tqslconfig> element and then
// decompresses to more than 16 MiB of spaces. Spaces keep the XML decoder
// reading, so only the size guard can stop it.
func bombStream(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(zw, `<tqslconfig majorversion="11" minorversion="35">`); err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte(" "), 1<<20)
	for range 17 {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseConfigErrors(t *testing.T) {
	x35 := readTestdata(t, "config-11.35.xml")
	tq6 := readTestdata(t, "config-11.34.tq6")

	tests := []struct {
		name string
		data []byte
		want string // substring of the error message
	}{
		{"empty", nil, "no tqslconfig"},
		{"not xml", []byte("hello, world"), "no tqslconfig"},
		{"syntax error", []byte("<tqslconfig majorversion=\"11\" minorversion=\"35\"><bands>"), "XML"},
		{"wrong root", []byte(`<foo majorversion="11" minorversion="35" />`), "no tqslconfig"},
		{"tqsldata without config", []byte(`<tqsldata><tqslcerts /></tqsldata>`), "no tqslconfig"},
		{"truncated gzip", tq6[:len(tq6)/2], "unexpected EOF"},
		{"gzip header only", tq6[:10], "EOF"},
		{"gzip bomb", bombStream(t), "16 MiB"},
		{"plain too large", append([]byte(`<tqslconfig majorversion="11" minorversion="35">`),
			bytes.Repeat([]byte(" "), 16<<20)...), "16 MiB"},
		{"missing sigspecs", dropSection(t, x35, "sigspecs"), "it does not have a sigspecs section"}, // location.cpp:793
		{"no sigspec", []byte(minimalConfig("")), "it does not have a sigspec section"},              // location.cpp:802
		{"missing tCONTACT", []byte(minimalConfig(`<sigspec name="LOTW" version="2.0"><tSTATION><CQZ /></tSTATION></sigspec>`)),
			"missing sigspec.tCONTACT"}, // location.cpp:830
		{"empty tCONTACT", []byte(minimalConfig(`<sigspec name="LOTW" version="2.0"><tCONTACT></tCONTACT><tSTATION><CQZ /></tSTATION></sigspec>`)),
			"empty sigspec.tCONTACT"}, // location.cpp:837
		{"missing tSTATION", []byte(minimalConfig(`<sigspec name="LOTW" version="2.0"><tCONTACT><CALL /></tCONTACT></sigspec>`)),
			"missing sigspec.tSTATION"}, // location.cpp:845
		{"empty tSTATION", []byte(minimalConfig(`<sigspec name="LOTW" version="2.0"><tCONTACT><CALL /></tCONTACT><tSTATION /></sigspec>`)),
			"missing tSTATION.specfield"}, // location.cpp:854
		{"page missing Id", []byte(strings.Replace(minimalConfig(minimalSigspec), `<page Id="1" follows="0">`, `<page follows="0">`, 1)),
			"page missing ID"}, // location.cpp:1654
		{"page Id zero", []byte(strings.Replace(minimalConfig(minimalSigspec), `<page Id="1" follows="0">`, `<page Id="0" follows="0">`, 1)),
			"page missing ID"}, // location.cpp:1654
		{"field missing Id", []byte(strings.Replace(minimalConfig(minimalSigspec), `<field Id="CALL" `, `<field `, 1)),
			"field missing ID"}, // location.cpp:1672
		{"undefined pageField", []byte(strings.Replace(minimalConfig(minimalSigspec), `<pageField>CALL</pageField>`, `<pageField>NOPE</pageField>`, 1)),
			"page references undefined field"}, // location.cpp:2189
		{"bad dxcc zonemap", []byte(strings.Replace(minimalConfig(minimalSigspec), `zonemap="08:05"`, `zonemap="08-05"`, 1)),
			"zonemap"},
	}
	// TrustedQSL has no message of its own for these sections; the text
	// follows the sigspecs one (location.cpp:793).
	for _, section := range []string{"bands", "modes", "adifmap", "propmodes", "satellites", "dxcc", "locfields", "locpages"} {
		tests = append(tests, struct {
			name string
			data []byte
			want string
		}{"missing " + section, dropSection(t, x35, section), "it does not have a " + section + " section"})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(bytes.NewReader(tt.data))
			if err == nil {
				t.Fatalf("ParseConfig succeeded (%v), want error", cfg)
			}
			if !errors.Is(err, ErrConfig) {
				t.Errorf("err = %v, want ErrConfig", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// errReader fails every read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

func TestParseConfigReadError(t *testing.T) {
	_, err := ParseConfig(errReader{})
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "disk on fire") {
		t.Errorf("err = %v, want ErrConfig wrapping the read error", err)
	}
}

func TestParseConfigNilReader(t *testing.T) {
	if _, err := ParseConfig(nil); !errors.Is(err, ErrConfig) {
		t.Errorf("err = %v, want ErrConfig", err)
	}
}

func FuzzParseConfig(f *testing.F) {
	// Seeds live in testdata/fuzz/FuzzParseConfig.
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseConfig(bytes.NewReader(data))
		if err != nil {
			if !errors.Is(err, ErrConfig) && !errors.Is(err, ErrConfigOutdated) {
				t.Fatalf("error does not wrap a sentinel: %v", err)
			}
			return
		}
		cfg.Version()
		cfg.Sigspec()
		cfg.inferBand("14.074")
		cfg.mapMode("MFSK", "FT4")
		for _, p := range cfg.pages() {
			for _, id := range p.fields {
				if _, ok := cfg.locField(id); !ok {
					t.Fatalf("page %d references undefined field %q", p.id, id)
				}
			}
		}
	})
}

func BenchmarkParseConfig(b *testing.B) {
	for _, name := range []string{"config-11.35.xml", "config-11.34.tq6"} {
		data := readTestdata(b, name)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				if _, err := ParseConfig(bytes.NewReader(data)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
