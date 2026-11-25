package gabbi

import (
	"bufio"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
)

// The oldest TrustedQSL configuration version ParseConfig accepts: 11.34, the
// version LoTW served when this minimum was set. Newer versions are accepted.
const (
	// MinConfigMajor is the minimum configuration major version.
	MinConfigMajor = 11
	// MinConfigMinor is the minimum configuration minor version, when the
	// major version equals MinConfigMajor.
	MinConfigMinor = 34
)

// maxConfigSize caps the decompressed configuration and .tq6 input. The real
// config file is about 480 KB.
const maxConfigSize = 16 << 20

var errConfigTooLarge = errors.New("input exceeds 16 MiB")

// Config is a parsed TrustedQSL configuration: the bands, modes, ADIF mode
// map, propagation modes, satellites, DXCC entities, station location fields
// and pages, and the signature specification. Create one with
// [ParseConfig]. A Config is read-only after parsing and safe for concurrent
// use.
type Config struct {
	major, minor               int
	sigspec                    Sigspec
	bands                      []band // in TrustedQSL's sort order (location.cpp:175-195)
	adifMap                    map[string]string
	modes                      map[string]bool
	propModes                  map[string]bool
	satellites                 map[string]bool
	entities                   map[int]entity
	fields                     map[string]locField
	locPages                   []locPage // sorted by id
	providerName, providerUnit string
}

// Sigspec is the signature specification TrustedQSL signs with: the station
// and contact fields whose values make up the signed data, in order.
type Sigspec struct {
	// Name and Version name the specification, such as "LOTW" and "2.0".
	// The signature field in a GAbbI record is "SIGN_" + Name + "_V" +
	// Version.
	Name, Version string
	// Station lists the tSTATION fields, Contact the tCONTACT fields.
	Station, Contact []SpecField
}

// SpecField is one field of a [Sigspec].
type SpecField struct {
	// Name is the GAbbI field name, such as "BAND" or "GRIDSQUARE".
	Name string
	// Required means signing fails when the value is empty.
	Required bool
}

// band is one <band> entry. HF limits are in kHz, VHF and UHF in MHz.
type band struct {
	name, spectrum string
	low, high      int
}

// zone is one ITU:CQ pair from a zonemap attribute.
type zone struct{ itu, cq int }

// enumItem is one <enum> of a location field.
type enumItem struct {
	value, label, area string
	zonemap            []zone
}

// locField is one <field> of <locfields>.
type locField struct {
	id, label, dependsOn string
	typ                  string // "C" or "I"
	length               int
	// intype is 1 TEXT, 2 DDLIST, 3 LIST (unused) or 4 BADZONE.
	intype int
	// flags bits (location.h:15-17): 1 UPPER, 2 MUSTSEL, 4 SELNXT.
	flags        int
	lower, upper int
	// enums groups the enumerations by their dependency attribute. Enums
	// with no dependency use the "" key.
	enums map[string][]enumItem
}

// locPage is one <page> of <locpages>.
type locPage struct {
	id, follows           int
	dependsOn, dependency string
	fields                []string // pageField ids, in order
}

// entity is one DXCC <entity>.
type entity struct {
	arrlID  int
	name    string
	deleted bool
	// valid and invalid are the raw attribute values, "" when absent.
	// TrustedQSL treats a missing valid date as 1945-11-15.
	valid, invalid string
	zonemap        []zone
}

// ParseConfig reads a TrustedQSL configuration. It accepts config.tq6 as
// LoTW serves it (gzip around a <tqsldata> wrapper), the same file after
// gunzip, or a bare config.xml whose root is <tqslconfig>. The format is
// detected from the content.
//
// A configuration older than [MinConfigMajor].[MinConfigMinor] returns an
// error wrapping [ErrConfigOutdated]. Any other problem, including a missing
// section the signing path needs, wraps [ErrConfig]. Input that decompresses
// to more than 16 MiB is rejected.
// Version attributes accept a decimal prefix like TrustedQSL's strtol; unlike
// TrustedQSL, missing attributes, values without digits and overflows are errors.
//
// The library embeds no configuration and downloads nothing. Fetching and
// storing it is the caller's job:
//
//  1. On startup, load the stored config, if you have one, and pass it to
//     ParseConfig.
//  2. Periodically, and whenever no config is stored, GET
//     https://lotw.arrl.org/lotw/config_xml_version. The body is one line:
//     "config.xml: Version <major>.<minor>". The server's cache lifetime is
//     14 days, which makes a sensible polling interval.
//  3. If no config is stored, or the online version is newer, GET
//     https://lotw.arrl.org/lotw/config.tq6, store the bytes unchanged, and
//     pass them to ParseConfig.
//  4. Keep the previous config until the new one parses without error.
//  5. Always verify TLS. The file carries no signature, so HTTPS is its only
//     protection. TrustedQSL turns verification off and retries when it
//     fails; do not copy that.
//  6. If ParseConfig returns [ErrConfigOutdated] (the config is older than
//     the minimum supported version, 11.34), download it again. If LoTW
//     itself is serving an older file, report that and do not sign.
func ParseConfig(r io.Reader) (*Config, error) {
	src, err := openTQSLData(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	d := xml.NewDecoder(src)
	cfg, err := decodeRoot(d)
	if err != nil {
		return nil, err
	}
	// Read to the end, so an unclosed wrapper, trailing garbage or a bad
	// gzip checksum is an error.
	for {
		if _, err := d.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, configErr(err)
		}
	}
	return cfg, nil
}

// openTQSLData returns the content of r, gunzipped when it starts with the
// gzip magic bytes, as TrustedQSL's gzopen reads both forms (xml.cpp:116,130).
// The returned reader fails with errConfigTooLarge past maxConfigSize
// decompressed bytes. Callers read it to EOF, which also verifies the gzip
// checksum, so the gzip reader needs no Close.
func openTQSLData(r io.Reader) (io.Reader, error) {
	if r == nil {
		return nil, errors.New("nil reader")
	}
	br := bufio.NewReader(r)
	var src io.Reader = br
	magic, err := br.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		src = zr
	}
	return &capReader{r: src, left: maxConfigSize}, nil
}

// capReader fails with errConfigTooLarge once more than left bytes are read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, errConfigTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return 0, errConfigTooLarge
	}
	return n, err
}

// configErr wraps a read or XML error in ErrConfig.
func configErr(err error) error {
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("%w: XML: %w", ErrConfig, err)
	}
	return fmt.Errorf("%w: %w", ErrConfig, err)
}

// invalid returns ErrConfig with TrustedQSL's message format.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: TQSL Configuration file invalid - "+format, append([]any{ErrConfig}, args...)...)
}

// decodeRoot finds <tqslconfig>, either at the top level or as a direct child
// of a top-level <tqsldata>, and parses it.
func decodeRoot(d *xml.Decoder) (*Config, error) {
	inData := false
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil, invalid("no tqslconfig element")
		}
		if err != nil {
			return nil, configErr(err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case t.Name.Local == "tqslconfig":
				return decodeConfig(d, t)
			case t.Name.Local == "tqsldata" && !inData:
				inData = true
			case inData:
				if err := d.Skip(); err != nil {
					return nil, configErr(err)
				}
			default:
				return nil, invalid("no tqslconfig element (root is %s)", t.Name.Local)
			}
		case xml.EndElement:
			// Only </tqsldata> can get here.
			return nil, invalid("no tqslconfig element")
		}
	}
}

// XML shapes of the sections.
type (
	xmlText struct {
		Text string `xml:",chardata"`
	}
	xmlSigspecs struct {
		Sigspecs []xmlSigspec `xml:"sigspec"`
	}
	xmlSigspec struct {
		Name    string         `xml:"name,attr"`
		Version string         `xml:"version,attr"`
		Status  string         `xml:"status,attr"`
		Contact []xmlFieldList `xml:"tCONTACT"`
		Station []xmlFieldList `xml:"tSTATION"`
	}
	xmlFieldList struct {
		Fields []xmlSpecField `xml:",any"`
	}
	xmlSpecField struct {
		XMLName  xml.Name
		Required string `xml:"required,attr"`
	}
	xmlBands struct {
		Bands []struct {
			Low      string `xml:"low,attr"`
			High     string `xml:"high,attr"`
			Spectrum string `xml:"spectrum,attr"`
			Name     string `xml:",chardata"`
		} `xml:"band"`
	}
	xmlModes struct {
		Modes []xmlText `xml:"mode"`
	}
	xmlAdifMap struct {
		Modes []struct {
			Mode    string `xml:"adif-mode,attr"`
			Submode string `xml:"adif-submode,attr"`
			Gabbi   string `xml:"mode,attr"`
			Text    string `xml:",chardata"`
		} `xml:"adifmode"`
	}
	xmlPropModes struct {
		PropModes []struct {
			Name string `xml:"name,attr"`
		} `xml:"propmode"`
	}
	xmlSatellites struct {
		Satellites []struct {
			Name string `xml:"name,attr"`
		} `xml:"satellite"`
	}
	xmlProviders struct {
		Providers []struct {
			Name string `xml:"organizationName,attr"`
			Unit string `xml:"organizationalUnitName"`
		} `xml:"provider"`
	}
	xmlDXCC struct {
		Entities []struct {
			ArrlID  *string `xml:"arrlId,attr"`
			Deleted string  `xml:"deleted,attr"`
			Valid   string  `xml:"valid,attr"`
			Invalid string  `xml:"invalid,attr"`
			Zonemap string  `xml:"zonemap,attr"`
			Name    string  `xml:",chardata"`
		} `xml:"entity"`
	}
	xmlLocFields struct {
		Fields []struct {
			ID        *string `xml:"Id,attr"`
			Label     string  `xml:"label,attr"`
			Type      string  `xml:"type,attr"`
			Len       string  `xml:"len,attr"`
			Intype    string  `xml:"intype,attr"`
			Flags     string  `xml:"flags,attr"`
			Lower     string  `xml:"lower,attr"`
			Upper     string  `xml:"upper,attr"`
			DependsOn string  `xml:"dependsOn,attr"`
			Enums     []struct {
				Dependency string `xml:"dependency,attr"`
				Items      []struct {
					Value   string `xml:"value,attr"`
					Zonemap string `xml:"zonemap,attr"`
					Area    string `xml:"area,attr"`
					Label   string `xml:",chardata"`
				} `xml:"enum"`
			} `xml:"enums"`
		} `xml:"field"`
	}
	xmlLocPages struct {
		Pages []struct {
			ID         *string   `xml:"Id,attr"`
			Follows    string    `xml:"follows,attr"`
			DependsOn  string    `xml:"dependsOn,attr"`
			Dependency string    `xml:"dependency,attr"`
			Fields     []xmlText `xml:"pageField"`
		} `xml:"page"`
	}
)

// configSections holds the raw sections. As in TrustedQSL
// (tqsl_get_xml_config_section, location.cpp:698-713), the first occurrence
// of a section wins, and section order does not matter.
type configSections struct {
	sigspecs   *xmlSigspecs
	bands      *xmlBands
	modes      *xmlModes
	adifMap    *xmlAdifMap
	propModes  *xmlPropModes
	satellites *xmlSatellites
	dxcc       *xmlDXCC
	locFields  *xmlLocFields
	locPages   *xmlLocPages
	providers  *xmlProviders
}

// decodeSection decodes the element start into *dst unless a section of that
// name was already seen, in which case it skips it.
func decodeSection[T any](d *xml.Decoder, start xml.StartElement, dst **T) error {
	if *dst != nil {
		return d.Skip()
	}
	v := new(T)
	if err := d.DecodeElement(v, &start); err != nil {
		return err
	}
	*dst = v
	return nil
}

func decodeConfig(d *xml.Decoder, start xml.StartElement) (*Config, error) {
	cfg := &Config{}
	var err error
	if cfg.major, err = versionAttr(start, "majorversion"); err != nil {
		return nil, err
	}
	if cfg.minor, err = versionAttr(start, "minorversion"); err != nil {
		return nil, err
	}
	if cfg.major < MinConfigMajor || (cfg.major == MinConfigMajor && cfg.minor < MinConfigMinor) {
		return nil, fmt.Errorf("%w: configuration %d.%d is older than the minimum supported %d.%d; download a current config.tq6 from LoTW",
			ErrConfigOutdated, cfg.major, cfg.minor, MinConfigMajor, MinConfigMinor)
	}

	var s configSections
	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, configErr(err)
		}
		if _, ok := tok.(xml.EndElement); ok {
			break // </tqslconfig>
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch el.Name.Local {
		case "sigspecs":
			err = decodeSection(d, el, &s.sigspecs)
		case "bands":
			err = decodeSection(d, el, &s.bands)
		case "modes":
			err = decodeSection(d, el, &s.modes)
		case "adifmap":
			err = decodeSection(d, el, &s.adifMap)
		case "propmodes":
			err = decodeSection(d, el, &s.propModes)
		case "satellites":
			err = decodeSection(d, el, &s.satellites)
		case "dxcc":
			err = decodeSection(d, el, &s.dxcc)
		case "locfields":
			err = decodeSection(d, el, &s.locFields)
		case "locpages":
			err = decodeSection(d, el, &s.locPages)
		case "providers":
			err = decodeSection(d, el, &s.providers)
		default:
			err = d.Skip()
		}
		if err != nil {
			return nil, configErr(err)
		}
	}

	missing := func(name string) error {
		return invalid("it does not have a %s section", name)
	}
	switch {
	case s.sigspecs == nil:
		return nil, missing("sigspecs")
	case s.bands == nil:
		return nil, missing("bands")
	case s.modes == nil:
		return nil, missing("modes")
	case s.adifMap == nil:
		return nil, missing("adifmap")
	case s.propModes == nil:
		return nil, missing("propmodes")
	case s.satellites == nil:
		return nil, missing("satellites")
	case s.dxcc == nil:
		return nil, missing("dxcc")
	case s.locFields == nil:
		return nil, missing("locfields")
	case s.locPages == nil:
		return nil, missing("locpages")
	}

	if cfg.sigspec, err = buildSigspec(s.sigspecs); err != nil {
		return nil, err
	}
	cfg.bands = buildBands(s.bands)
	cfg.modes = make(map[string]bool, len(s.modes.Modes))
	for _, m := range s.modes.Modes {
		cfg.modes[m.Text] = true
	}
	cfg.adifMap = buildAdifMap(s.adifMap)
	cfg.propModes = make(map[string]bool, len(s.propModes.PropModes))
	for _, p := range s.propModes.PropModes {
		cfg.propModes[p.Name] = true
	}
	cfg.satellites = make(map[string]bool, len(s.satellites.Satellites))
	for _, sat := range s.satellites.Satellites {
		cfg.satellites[sat.Name] = true
	}
	if cfg.entities, err = buildDXCC(s.dxcc); err != nil {
		return nil, err
	}
	if cfg.fields, err = buildFields(s.locFields); err != nil {
		return nil, err
	}
	if cfg.locPages, err = buildPages(s.locPages, cfg.fields); err != nil {
		return nil, err
	}
	if s.providers != nil && len(s.providers.Providers) > 0 {
		cfg.providerName = s.providers.Providers[0].Name
		cfg.providerUnit = s.providers.Providers[0].Unit
	}
	return cfg, nil
}

func versionAttr(start xml.StartElement, name string) (int, error) {
	for _, a := range start.Attr {
		if a.Name.Local == name {
			// TrustedQSL reads a decimal prefix with strtol, accepting C
			// whitespace and ignoring text after the number (location.cpp:492-497).
			text := strings.TrimLeft(a.Value, " \t\n\v\f\r")
			i := 0
			if len(text) > 0 && (text[0] == '+' || text[0] == '-') {
				i++
			}
			start := i
			for i < len(text) && text[i] >= '0' && text[i] <= '9' {
				i++
			}
			if i == start {
				return 0, invalid("tqslconfig %s %q is not a number", name, a.Value)
			}
			v, err := strconv.Atoi(text[:i])
			if err != nil {
				return 0, invalid("tqslconfig %s %q is not a number", name, a.Value)
			}
			return v, nil
		}
	}
	return 0, invalid("tqslconfig has no %s attribute", name)
}

// buildSigspec picks the sigspec the way make_sign_data does
// (location.cpp:791-856). The first sigspec seeds the choice even when it is
// deprecated; later deprecated sigspecs are skipped; a later one wins only
// when its version is strictly higher.
func buildSigspec(x *xmlSigspecs) (Sigspec, error) {
	if len(x.Sigspecs) == 0 {
		return Sigspec{}, invalid("it does not have a sigspec section")
	}
	ss := x.Sigspecs[0]
	for _, cand := range x.Sigspecs {
		if cand.Status == "deprecated" {
			continue
		}
		if atof(cand.Version) > atof(ss.Version) {
			ss = cand
		}
	}
	if len(ss.Contact) == 0 {
		return Sigspec{}, invalid("missing sigspec.tCONTACT")
	}
	if len(ss.Contact[0].Fields) == 0 {
		return Sigspec{}, invalid("empty sigspec.tCONTACT")
	}
	if len(ss.Station) == 0 {
		return Sigspec{}, invalid("missing sigspec.tSTATION")
	}
	if len(ss.Station[0].Fields) == 0 {
		return Sigspec{}, invalid("missing tSTATION.specfield")
	}
	return Sigspec{
		Name:    ss.Name,
		Version: ss.Version,
		Station: specFields(ss.Station[0].Fields),
		Contact: specFields(ss.Contact[0].Fields),
	}, nil
}

// specFields converts a tCONTACT or tSTATION child list. TrustedQSL keeps
// child elements in a std::multimap keyed by name (xml.h:31,
// xml.cpp:156-158), so it walks them in name order; equal names keep document
// order. A field is required when strtol(required) is non-zero.
func specFields(x []xmlSpecField) []SpecField {
	out := make([]SpecField, len(x))
	for i, f := range x {
		out[i] = SpecField{Name: f.XMLName.Local, Required: strtol(f.Required) != 0}
	}
	slices.SortStableFunc(out, func(a, b SpecField) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func buildBands(x *xmlBands) []band {
	out := make([]band, len(x.Bands))
	for i, b := range x.Bands {
		out[i] = band{name: b.Name, spectrum: b.Spectrum, low: strtol(b.Low), high: strtol(b.High)}
	}
	slices.SortStableFunc(out, compareBands)
	return out
}

// compareBands is TrustedQSL's band operator< (location.cpp:175-195): suffix
// M, then CM, then MM, then any other suffix; within a suffix, the larger
// number first.
func compareBands(a, b band) int {
	as, bs := bandSuffix(a.name), bandSuffix(b.name)
	if as != bs {
		return bandSuffixRank(as) - bandSuffixRank(bs)
	}
	af, bf := atof(a.name), atof(b.name)
	switch {
	case af > bf:
		return -1
	case af < bf:
		return 1
	}
	return 0
}

func bandSuffix(name string) string {
	i := strings.IndexFunc(name, func(r rune) bool { return !strings.ContainsRune("0123456789.", r) })
	if i < 0 {
		return ""
	}
	return name[i:]
}

func bandSuffixRank(suffix string) int {
	switch suffix {
	case "M":
		return 0
	case "CM":
		return 1
	case "MM":
		return 2
	}
	return 3
}

// buildAdifMap follows init_adif_map (location.cpp:1486-1540). Keys are
// stored as written; lookups uppercase the query.
func buildAdifMap(x *xmlAdifMap) map[string]string {
	m := make(map[string]string, 3*len(x.Modes))
	for _, a := range x.Modes {
		mode, sub, gabbi, text := a.Mode, a.Submode, a.Gabbi, a.Text
		if mode == "" {
			mode = text
		}
		if gabbi == "" {
			continue
		}
		if mode != "" {
			m[mode] = gabbi
		}
		if sub != "" && sub != mode {
			m[sub] = gabbi
		}
		if text != "" && text != mode {
			m[text] = gabbi
		}
		if mode != "" && sub != "" {
			m[mode+"%"+sub] = gabbi
		}
	}
	return m
}

// buildDXCC follows init_dxcc (location.cpp:891-943). Entities without an
// arrlId are ignored; a later duplicate replaces an earlier one.
func buildDXCC(x *xmlDXCC) (map[int]entity, error) {
	m := make(map[int]entity, len(x.Entities))
	for _, e := range x.Entities {
		if e.ArrlID == nil {
			continue
		}
		id := strtol(*e.ArrlID)
		zm, err := parseZonemap(e.Zonemap)
		if err != nil {
			return nil, invalid("dxcc entity %d: %v", id, err)
		}
		m[id] = entity{
			arrlID:  id,
			name:    e.Name,
			deleted: e.Deleted == "1",
			valid:   e.Valid,
			invalid: e.Invalid,
			zonemap: zm,
		}
	}
	return m, nil
}

// parseZonemap parses a comma list of ITU:CQ pairs (location.cpp:1700). An
// empty map gives nil.
func parseZonemap(s string) ([]zone, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]zone, 0, len(parts))
	for _, p := range parts {
		itu, cq, ok := strings.Cut(p, ":")
		i, err1 := strconv.Atoi(itu)
		c, err2 := strconv.Atoi(cq)
		if !ok || err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad zonemap entry %q", p)
		}
		out = append(out, zone{itu: i, cq: c})
	}
	return out, nil
}

// buildFields follows init_loc_maps (location.cpp:1662-1677).
func buildFields(x *xmlLocFields) (map[string]locField, error) {
	m := make(map[string]locField, len(x.Fields))
	for _, f := range x.Fields {
		if f.ID == nil {
			return nil, invalid("field missing ID")
		}
		lf := locField{
			id:        *f.ID,
			label:     f.Label,
			dependsOn: f.DependsOn,
			typ:       f.Type,
			length:    strtol(f.Len),
			intype:    strtol(f.Intype),
			flags:     strtol(f.Flags),
			lower:     strtol(f.Lower),
			upper:     strtol(f.Upper),
		}
		if len(f.Enums) > 0 {
			lf.enums = make(map[string][]enumItem, len(f.Enums))
		}
		for _, es := range f.Enums {
			items := lf.enums[es.Dependency]
			for _, e := range es.Items {
				zm, err := parseZonemap(e.Zonemap)
				if err != nil {
					return nil, invalid("field %s enum %q: %v", lf.id, e.Value, err)
				}
				items = append(items, enumItem{value: e.Value, label: e.Label, area: e.Area, zonemap: zm})
			}
			lf.enums[es.Dependency] = items
		}
		m[lf.id] = lf
	}
	return m, nil
}

// buildPages follows init_loc_maps and make_page (location.cpp:1638-1661,
// 2163-2205). Pages are keyed by Id, so a later duplicate replaces an
// earlier one, and they come back sorted by Id. Every pageField must name a
// defined field.
func buildPages(x *xmlLocPages, fields map[string]locField) ([]locPage, error) {
	byID := make(map[int]locPage, len(x.Pages))
	for _, p := range x.Pages {
		if p.ID == nil || strtol(*p.ID) < 1 {
			return nil, invalid("page missing ID")
		}
		lp := locPage{
			id:         strtol(*p.ID),
			follows:    strtol(p.Follows),
			dependsOn:  p.DependsOn,
			dependency: p.Dependency,
			fields:     make([]string, len(p.Fields)),
		}
		for i, f := range p.Fields {
			if _, ok := fields[f.Text]; f.Text == "" || !ok {
				return nil, invalid("page references undefined field. (page %d, field %q)", lp.id, f.Text)
			}
			lp.fields[i] = f.Text
		}
		byID[lp.id] = lp
	}
	out := make([]locPage, 0, len(byID))
	for _, p := range byID {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b locPage) int { return a.id - b.id })
	return out, nil
}

// Version returns the configuration version, such as 11 and 35. A nil
// Config gives 0, 0.
func (c *Config) Version() (major, minor int) {
	if c == nil {
		return 0, 0
	}
	return c.major, c.minor
}

// Provider returns the first configured certificate provider's organization
// and unit. A nil Config or missing provider returns two empty strings.
func (c *Config) Provider() (name, unit string) {
	if c == nil {
		return "", ""
	}
	return c.providerName, c.providerUnit
}

// Sigspec returns the signature specification used for signing: the newest
// one, chosen the way TrustedQSL chooses it. The returned slices are copies.
// A nil Config gives the zero Sigspec.
func (c *Config) Sigspec() Sigspec {
	if c == nil {
		return Sigspec{}
	}
	ss := c.sigspec
	ss.Station = slices.Clone(ss.Station)
	ss.Contact = slices.Clone(ss.Contact)
	return ss
}

// band returns the band with the given name. Names are case-sensitive.
func (c *Config) band(name string) (band, bool) {
	for _, b := range c.bands {
		if b.name == name {
			return b, true
		}
	}
	return band{}, false
}

// inferBand returns the band holding freq (MHz), or "" when none does. It is
// tqsl_infer_band (tqslconvert.cpp:603-637): HF limits are in kHz, with the
// low edges of 30M, 17M and 12M relaxed for loggers that record a rounded
// frequency; other limits are in MHz, and a high limit of 0 is open-ended.
// The first match in band sort order wins.
func (c *Config) inferBand(freq string) string {
	mhz := atof(freq)
	khz := mhz * 1000
	for _, b := range c.bands {
		low, high := float64(b.low), float64(b.high)
		if b.spectrum == "HF" {
			switch b.low {
			case 10100:
				low = 10000
			case 18068:
				low = 18000
			case 24890:
				low = 24000
			}
			if khz >= low && khz <= high {
				return b.name
			}
			continue
		}
		if mhz >= low && (mhz <= high || b.high == 0) {
			return b.name
		}
	}
	return ""
}

// mapMode maps an ADIF mode and submode to a GAbbI mode through the adifmap,
// trying mode%submode, then submode, then mode (tqslconvert.cpp:1409-1427).
// Lookups are uppercased. It returns "" when nothing matches, in which case
// TrustedQSL keeps the uppercased mode as it is.
func (c *Config) mapMode(mode, submode string) string {
	mode, submode = asciiUpper(mode), asciiUpper(submode)
	if submode != "" {
		if v, ok := c.adifMap[mode+"%"+submode]; ok {
			return v
		}
		if v, ok := c.adifMap[submode]; ok {
			return v
		}
	}
	return c.adifMap[mode]
}

// hasMode reports whether mode is a GAbbI mode. The check is case-sensitive.
func (c *Config) hasMode(mode string) bool { return c.modes[mode] }

// hasPropMode reports whether name is a propagation mode name. The check is
// case-sensitive.
func (c *Config) hasPropMode(name string) bool { return c.propModes[name] }

// hasSatellite reports whether name is a satellite name. The check is
// case-sensitive, and TrustedQSL uppercases SAT_NAME before it, so a
// mixed-case config name such as "Arsene" never matches.
func (c *Config) hasSatellite(name string) bool { return c.satellites[name] }

// locField returns the location field with the given Id.
func (c *Config) locField(id string) (locField, bool) {
	f, ok := c.fields[id]
	return f, ok
}

// pages returns the location pages sorted by Id. Callers must not modify
// the slice or the nested page fields.
func (c *Config) pages() []locPage { return c.locPages }

// dxcc returns the DXCC entity with the given ARRL id.
func (c *Config) dxcc(id int) (entity, bool) {
	e, ok := c.entities[id]
	return e, ok
}

// isCSpace reports whether b is a C-locale isspace character.
func isCSpace(b byte) bool {
	return b == ' ' || (b >= '\t' && b <= '\r')
}

// asciiUpper uppercases ASCII letters only, like toupper in the C locale.
func asciiUpper(s string) string {
	for i := 0; i < len(s); i++ {
		if 'a' <= s[i] && s[i] <= 'z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'a' <= b[j] && b[j] <= 'z' {
					b[j] -= 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// atof mirrors C atof for plain decimals: it skips leading C whitespace and
// parses the longest prefix of the form [sign] digits [. digits], giving 0
// when there is none. Exponents, hex and inf/nan are not recognized.
func atof(s string) float64 {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	start := i
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digits := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
		digits++
	}
	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			digits++
		}
	}
	if digits == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(s[start:i], 64)
	if err != nil {
		return 0
	}
	return v
}

// strtol mirrors C strtol in base 10: it skips leading C whitespace and
// parses [sign] digits, giving 0 when there are none. Values saturate
// instead of overflowing.
func strtol(s string) int {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	v := 0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		d := int(s[i] - '0')
		if v > (math.MaxInt-d)/10 {
			v = math.MaxInt
			continue
		}
		v = v*10 + d
	}
	if neg {
		return -v
	}
	return v
}
