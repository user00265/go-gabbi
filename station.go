package gabbi

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Station is a station location: the values TrustedQSL stores for one entry
// in its Station Locations list. Zero or empty fields are unset.
//
// The fields of page 1 of the configuration's location pages have their own
// struct fields. Everything else, such as the US state and county, goes in
// Fields, keyed by the GAbbI field id. Which ids are allowed depends on the
// configuration and on DXCC: for DXCC 291 (USA) the current configuration has
// US_STATE, US_COUNTY and US_PARK.
//
// TrustedQSL can also take station values from MY_* fields in an ADIF log.
// This package does not: the caller builds the Station.
type Station struct {
	// Call is the station callsign. It must match the certificate.
	Call string
	// DXCC is the ARRL DXCC entity number, such as 291 for the USA.
	DXCC int
	// GridSquare is the Maidenhead locator. Its case is kept.
	GridSquare string
	// ITUZ and CQZ are the ITU and CQ zones. 0 means unset.
	ITUZ, CQZ int
	// IOTA is the Islands On The Air reference. It is uppercased.
	IOTA string
	// Fields holds the other location fields by GAbbI id, such as
	// "US_STATE": "TX". Values of list fields are the configuration's
	// enum values, not their labels: "TX", not "Texas". They match
	// ignoring case. The ids of the typed fields above (CALL, DXCC,
	// GRIDSQUARE, ITUZ, CQZ and IOTA) are not allowed here.
	Fields map[string]string
}

// stationField is one GAbbI field of a tSTATION record.
type stationField struct {
	name, value string
}

// typedStationFields returns the GAbbI ids that have their own Station
// field. It returns an array, a fresh value on each call, so there is no
// package state to modify.
func typedStationFields() [6]string {
	return [...]string{"CALL", "DXCC", "GRIDSQUARE", "ITUZ", "CQZ", "IOTA"}
}

// primarySubdivision is one entry of primarySubdivisions.
type primarySubdivision struct{ id, errText string }

// primarySubdivisions returns TrustedQSL's sasMapping
// (location.cpp:1768-1777): the fields that can be a location's primary
// subdivision, in priority order, with the error text for a zone mismatch.
// Like typedStationFields it returns an array value.
func primarySubdivisions() [7]primarySubdivision {
	return [...]primarySubdivision{
		{"US_STATE", "Invalid zone selections for state"},
		{"CA_PROVINCE", "Invalid zone selections for province"},
		{"RU_OBLAST", "Invalid zone selections for oblast"},
		{"CN_PROVINCE", "Invalid zone selections for province"},
		{"AU_STATE", "Invalid zone selections for state"},
		{"JA_PREFECTURE", "Invalid zone selections for prefecture"},
		{"FI_KUNTA", "Invalid zone selections for kunta"},
	}
}

// Location field input types (tqsllib.h:978-981) and the UPPER flag
// (location.h:15).
const (
	intypeDDList  = 2
	intypeList    = 3
	intypeBadZone = 4

	flagUpper = 1
)

// stationError is an invalid station field. It wraps [ErrInvalidStation]
// and carries the GAbbI field name, so the Writer can report it in
// [QSOError.Field].
type stationError struct {
	field, msg string
}

func (e *stationError) Error() string {
	return ErrInvalidStation.Error() + ": " + e.field + ": " + e.msg
}

func (e *stationError) Unwrap() error { return ErrInvalidStation }

func stationErr(field, format string, args ...any) error {
	return &stationError{field: field, msg: fmt.Sprintf(format, args...)}
}

// ValidateStation checks st against the configuration the way TrustedQSL's
// station location editor does, and returns an error wrapping
// [ErrInvalidStation] that names the offending field.
//
//   - Call is required and must pass the same callsign check as a QSO call.
//   - DXCC is required and must be a configured entity. Deleted entities are
//     accepted; whether the certificate allows one is checked when signing.
//   - Every Fields key must be a field on the location pages this station
//     reaches: page 1, then the page that follows it and whose dependency
//     matches, and so on. The typed ids (CALL, DXCC, GRIDSQUARE, ITUZ, CQZ,
//     IOTA) are rejected in Fields.
//   - List fields must match one of the configured values for their
//     dependency, such as a county of the selected state. The match ignores
//     ASCII case, as tqsl_setLocationField does.
//   - ITUZ and CQZ, when set, must be within the configured range, and must
//     fit the zone map of the DXCC entity and of the primary subdivision
//     (state, province, oblast, prefecture or kunta). 0 matches any zone.
//
// Two rules are stricter than TrustedQSL:
//
//   - Call is run through the QSO callsign check. TrustedQSL does not check
//     station callsigns, because it takes them from certificates.
//   - A list value must be the configured enum value, compared ignoring
//     case. TrustedQSL's tqsl_setLocationField also accepts a fuzzy match on
//     the label (location.cpp:4154-4161), such as "Texas" for "TX"; this
//     package rejects those.
//   - NUL bytes in station text are rejected to avoid C string truncation.
//   - List and numeric values are matched without trimming surrounding
//     whitespace. Text fields are trimmed when the station is written.
//
// ValidateStation does not change st. The canonical forms (the configured
// spelling of list values, uppercased callsign and IOTA) are applied when
// the station is written. A nil Config gives an error wrapping [ErrConfig].
func (c *Config) ValidateStation(st Station) error {
	if c == nil {
		return fmt.Errorf("%w: nil Config", ErrConfig)
	}
	_, err := c.stationFields(st)
	return err
}

// rawStationValue returns the value st gives for the field id, before
// canonicalization.
func rawStationValue(st Station, id string) string {
	switch id {
	case "CALL":
		return st.Call
	case "DXCC":
		return itoaNonZero(st.DXCC)
	case "GRIDSQUARE":
		return st.GridSquare
	case "ITUZ":
		return itoaNonZero(st.ITUZ)
	case "CQZ":
		return itoaNonZero(st.CQZ)
	case "IOTA":
		return st.IOTA
	}
	return st.Fields[id]
}

func itoaNonZero(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// stationFields validates st and returns its tSTATION fields in
// configuration page order, with canonical values, leaving out empty values
// and BADZONE fields. It is the single source for the tSTATION record and
// the station part of the sign data. When st is invalid it returns the error
// ValidateStation returns.
func (c *Config) stationFields(st Station) ([]stationField, error) {
	for _, value := range []struct{ field, text string }{
		{"CALL", st.Call}, {"GRIDSQUARE", st.GridSquare}, {"IOTA", st.IOTA},
	} {
		if strings.ContainsRune(value.text, 0) {
			return nil, stationErr(value.field, "field contains NUL byte")
		}
	}
	keys := make([]string, 0, len(st.Fields))
	for field := range st.Fields {
		keys = append(keys, field)
	}
	slices.Sort(keys)
	for _, field := range keys {
		value := st.Fields[field]
		if strings.ContainsRune(field, 0) || strings.ContainsRune(value, 0) {
			return nil, stationErr(field, "field contains NUL byte")
		}
	}
	if st.Call == "" {
		return nil, stationErr("CALL", "callsign is required")
	}
	if call := asciiUpper(st.Call); !checkCallSign(call) {
		return nil, stationErr("CALL", "Invalid amateur CALL (%s)", call)
	}
	if st.DXCC == 0 {
		return nil, stationErr("DXCC", "DXCC entity is required")
	}
	ent, ok := c.dxcc(st.DXCC)
	if !ok {
		return nil, stationErr("DXCC", "unknown DXCC entity %d", st.DXCC)
	}

	var (
		out      []stationField
		values   = map[string]string{} // canonical values by id
		selected = map[string]enumItem{}
		onPages  = map[string]bool{}
	)
	pages := c.pages()
	visited := map[int]bool{}
	for id := 1; id > 0 && !visited[id]; id = nextPage(pages, id, values) {
		visited[id] = true
		i, found := slices.BinarySearchFunc(pages, id, func(p locPage, id int) int { return p.id - id })
		if !found {
			break
		}
		for _, fid := range pages[i].fields {
			if onPages[fid] {
				continue
			}
			onPages[fid] = true
			f, _ := c.locField(fid) // buildPages checked every pageField
			if f.intype == intypeBadZone {
				continue
			}
			raw := rawStationValue(st, fid)
			if raw == "" {
				continue
			}
			v, item, err := c.resolveStationField(f, raw, values)
			if err != nil {
				return nil, err
			}
			if v == "" {
				continue
			}
			values[fid] = v
			if item != nil {
				selected[fid] = *item
			}
			out = append(out, stationField{name: fid, value: v})
		}
	}

	for _, id := range typedStationFields() {
		if _, ok := st.Fields[id]; ok {
			return nil, stationErr(id, "use the Station field, not Fields")
		}
		if rawStationValue(st, id) != "" && !onPages[id] {
			return nil, stationErr(id, "not a location field for DXCC %d", st.DXCC)
		}
	}
	for _, k := range keys {
		f, ok := c.locField(k)
		if !ok || !onPages[k] || f.intype == intypeBadZone {
			return nil, stationErr(k, "not a location field for DXCC %d", st.DXCC)
		}
	}

	if err := checkZones(st, ent, onPages, selected); err != nil {
		return nil, err
	}
	return out, nil
}

// nextPage is find_next_page (location.cpp:2340-2362): the first page, by
// Id, that follows page cur and either has no dependsOn or whose dependsOn
// field has the selected value equal to its dependency. It returns 0 when
// there is none.
func nextPage(pages []locPage, cur int, values map[string]string) int {
	for _, p := range pages {
		if p.follows != cur {
			continue
		}
		if p.dependsOn == "" || values[p.dependsOn] == p.dependency {
			return p.id
		}
	}
	return 0
}

// resolveStationField validates the non-empty raw value of field f and
// returns its canonical value, and the selected enum item for list fields
// with enumerations. values holds the canonical values resolved so far.
func (c *Config) resolveStationField(f locField, raw string, values map[string]string) (string, *enumItem, error) {
	switch {
	case f.id == "CALL":
		// The callsign list holds certificate callsigns
		// (location.cpp:1820-1858), matched ignoring case
		// (location.cpp:4146-4148). Checked in stationFields.
		return asciiUpper(raw), nil, nil
	case f.id == "DXCC":
		// The entity list (location.cpp:1860-1945). Checked in
		// stationFields.
		return raw, nil, nil
	case f.intype == intypeDDList || f.intype == intypeList:
		if f.enums != nil {
			dep := ""
			if f.dependsOn != "" {
				dep = values[f.dependsOn]
			}
			// tqsl_setLocationField (location.cpp:4140-4148) matches
			// item text ignoring case and keeps the item's text.
			want := asciiUpper(raw)
			for i, e := range f.enums[dep] {
				if asciiUpper(e.value) == want {
					return e.value, &f.enums[dep][i], nil
				}
			}
			if f.dependsOn != "" {
				return "", nil, stationErr(f.id, "%q is not a valid value for %s %q", raw, f.dependsOn, dep)
			}
			return "", nil, stationErr(f.id, "%q is not a valid value", raw)
		}
		if f.typ == "I" {
			// A numeric range list such as CQZ or ITUZ
			// (location.cpp:2046-2116).
			n, err := strconv.Atoi(raw)
			if err != nil || n < f.lower || n > f.upper {
				return "", nil, stationErr(f.id, "%q is not between %d and %d", raw, f.lower, f.upper)
			}
			return strconv.Itoa(n), nil, nil
		}
		return "", nil, stationErr(f.id, "the configuration lists no values")
	}
	// Text fields are trimmed, and uppercased when flagged
	// (location.cpp:3485-3489).
	v := trimC(raw)
	if f.flags&flagUpper != 0 {
		v = asciiUpper(v)
	}
	return v, nil, nil
}

// checkZones is the zone sanity check at the end of update_page
// (location.cpp:2124-2160). The entity's zonemap is checked first, then the
// primary subdivision's. The error text is the subdivision's whenever the
// location has one, even when only the entity check failed, because
// get_primary_sub overwrites it (location.cpp:2144).
func checkZones(st Station, ent entity, onPages map[string]bool, selected map[string]enumItem) error {
	ok := inZoneMap(st.CQZ, st.ITUZ, ent.zonemap)
	text := "Invalid zone selections for DXCC entity"
	for _, ps := range primarySubdivisions() {
		if !onPages[ps.id] {
			continue
		}
		text = ps.errText
		// An unset subdivision selects [None], whose zonemap is empty.
		if item, set := selected[ps.id]; set && !inZoneMap(st.CQZ, st.ITUZ, item.zonemap) {
			ok = false
		}
		break
	}
	if !ok {
		return stationErr("CQZ/ITUZ", "%s", text)
	}
	return nil
}

// inZoneMap is inMap (location.cpp:1683-1717) with both zones checked: an
// empty map matches everything, and a zone of 0 matches any value.
func inZoneMap(cq, itu int, zm []zone) bool {
	if len(zm) == 0 {
		return true
	}
	for _, z := range zm {
		if (z.cq == cq || cq == 0) && (z.itu == itu || itu == 0) {
			return true
		}
	}
	return false
}
