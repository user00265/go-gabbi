package gabbi

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Line numbers in comments refer to testdata/config-11.35.xml, which is
// TrustedQSL's src/config.xml, and to TrustedQSL's src/location.cpp at HEAD
// 9b30153.

// testConfigs are the configurations every station test runs against.
var testConfigs = []string{"config-11.34.tq6", "config-11.35.xml"}

// usStation is a valid US station in Travis County, Texas.
func usStation() Station {
	return Station{
		Call:       "KF0TST",
		DXCC:       291, // config.xml:579
		GridSquare: "EM10dh",
		ITUZ:       7, // TX zonemap 07:04, config.xml:7497
		CQZ:        4,
		// The map's order is irrelevant: page order decides.
		Fields: map[string]string{"US_COUNTY": "Travis", "US_STATE": "TX"},
	}
}

func fieldNames(fs []stationField) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.name
	}
	return out
}

func fieldValues(fs []stationField) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.value
	}
	return out
}

func TestStationFieldsOrder(t *testing.T) {
	for _, name := range testConfigs {
		t.Run(name, func(t *testing.T) {
			cfg := loadTestConfig(t, name)
			st := usStation()
			if err := cfg.ValidateStation(st); err != nil {
				t.Fatalf("ValidateStation: %v", err)
			}
			fs, err := cfg.stationFields(st)
			if err != nil {
				t.Fatalf("stationFields: %v", err)
			}
			// Page 1 is CALL DXCC GRIDSQUARE ITUZ CQZ IOTA ZERR
			// (config.xml:7514-7522); page 2 (dependency 291) is US_STATE
			// US_COUNTY US_PARK ZERR (config.xml:7523-7528). IOTA and
			// US_PARK are empty and ZERR is never output
			// (location.cpp:3717-3718).
			wantNames := []string{"CALL", "DXCC", "GRIDSQUARE", "ITUZ", "CQZ", "US_STATE", "US_COUNTY"}
			// GRIDSQUARE has flags 0 (config.xml:1316), so it keeps its
			// case (location.cpp:3712-3747 writes cdata as is).
			wantValues := []string{"KF0TST", "291", "EM10dh", "7", "4", "TX", "Travis"}
			if got := fieldNames(fs); !reflect.DeepEqual(got, wantNames) {
				t.Errorf("names = %q, want %q", got, wantNames)
			}
			if got := fieldValues(fs); !reflect.DeepEqual(got, wantValues) {
				t.Errorf("values = %q, want %q", got, wantValues)
			}
		})
	}
}

func TestStationFieldsCanonical(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := usStation()
	st.Call = "kf0tst"
	st.IOTA = " na-001 "
	// tqsl_setLocationField matches list items ignoring case and stores the
	// item's text (location.cpp:4146-4148).
	st.Fields = map[string]string{"US_STATE": "tx", "US_COUNTY": "TRAVIS"}
	if err := cfg.ValidateStation(st); err != nil {
		t.Fatalf("ValidateStation: %v", err)
	}
	fs, err := cfg.stationFields(st)
	if err != nil {
		t.Fatalf("stationFields: %v", err)
	}
	got := fieldValues(fs)
	// IOTA has flags 1, UPPER (config.xml:1317); text fields are trimmed and
	// uppercased on save (location.cpp:3485-3489).
	want := []string{"KF0TST", "291", "EM10dh", "7", "4", "NA-001", "TX", "Travis"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("values = %q, want %q", got, want)
	}
}

func TestStationFieldsCanada(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := Station{
		Call:   "VE3TST",
		DXCC:   1, // config.xml:296
		ITUZ:   4, // ON zonemap 03:04,04:04, config.xml:723
		Fields: map[string]string{"CA_PROVINCE": "ON"},
	}
	if err := cfg.ValidateStation(st); err != nil {
		t.Fatalf("ValidateStation: %v", err)
	}
	// Page 4 (dependency 1) is CA_PROVINCE CA_US_PARK ZERR
	// (config.xml:7535-7539).
	fs, err := cfg.stationFields(st)
	if err != nil {
		t.Fatalf("stationFields: %v", err)
	}
	got := fieldNames(fs)
	want := []string{"CALL", "DXCC", "ITUZ", "CA_PROVINCE"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
}

func TestStationUnsetZonesOmitted(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	st := usStation()
	st.CQZ, st.ITUZ = 0, 0
	if err := cfg.ValidateStation(st); err != nil {
		t.Fatalf("ValidateStation: %v", err)
	}
	// Unset CQZ/ITUZ select the [None] item, whose text is empty, so they
	// are left out (knowledge.md §10.1; location.cpp:3733-3734).
	fs, err := cfg.stationFields(st)
	if err != nil {
		t.Fatalf("stationFields: %v", err)
	}
	for _, f := range fs {
		if f.name == "CQZ" || f.name == "ITUZ" {
			t.Errorf("unset %s present with value %q", f.name, f.value)
		}
	}
}

func TestStationUnknownField(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	for _, tc := range []struct {
		name, key string
	}{
		{"misspelled", "US_STAET"},
		{"typed GRIDSQUARE", "GRIDSQUARE"},
		{"typed CALL", "CALL"},
		{"typed DXCC", "DXCC"},
		{"typed ITUZ", "ITUZ"},
		{"typed CQZ", "CQZ"},
		{"typed IOTA", "IOTA"},
		// ZERR is a BADZONE field (config.xml:7511), never set or output.
		{"badzone", "ZERR"},
		// CA_PROVINCE is only on page 4, DXCC 1 (config.xml:7535).
		{"other entity", "CA_PROVINCE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := usStation()
			st.Fields = map[string]string{tc.key: "x"}
			err := cfg.ValidateStation(st)
			if !errors.Is(err, ErrInvalidStation) {
				t.Fatalf("err = %v, want ErrInvalidStation", err)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("err = %q, does not name %s", err, tc.key)
			}
		})
	}
}

func TestValidateStation(t *testing.T) {
	cfg := loadTestConfig(t, "config-11.35.xml")
	for _, tc := range []struct {
		name    string
		edit    func(*Station)
		field   string // "" means valid
		message string // exact text the error must contain, if any
	}{
		{
			// Travis is under dependency TX (config.xml:5899,6126);
			// TX is under 291 (config.xml:7455,7497).
			name: "travis tx",
			edit: func(*Station) {},
		},
		{
			// CT's county list starts at config.xml:3612 and has no
			// Travis; CT zonemap 08:05 (config.xml:7461).
			name:  "travis ct",
			edit:  func(s *Station) { s.Fields["US_STATE"] = "CT"; s.ITUZ, s.CQZ = 8, 5 },
			field: "US_COUNTY",
		},
		{
			name:  "state not in list",
			edit:  func(s *Station) { s.Fields["US_STATE"] = "ZZ" },
			field: "US_STATE",
		},
		{
			// CQZ upper="40" (config.xml:784).
			name:  "cqz 41",
			edit:  func(s *Station) { s.CQZ = 41 },
			field: "CQZ",
		},
		{
			name:  "cqz negative",
			edit:  func(s *Station) { s.CQZ = -1 },
			field: "CQZ",
		},
		{
			// ITUZ upper="90" (config.xml:1318).
			name:  "ituz 91",
			edit:  func(s *Station) { s.ITUZ = 91 },
			field: "ITUZ",
		},
		{
			// US_STATE is on pages for DXCC 291, 6 and 110 only
			// (config.xml:7523-7550); CANADA is 1 (config.xml:296).
			name: "us state in canada",
			edit: func(s *Station) {
				s.DXCC = 1
				s.ITUZ, s.CQZ = 0, 0
				s.Fields = map[string]string{"US_STATE": "TX"}
			},
			field: "US_STATE",
		},
		{
			name:  "unknown dxcc",
			edit:  func(s *Station) { s.DXCC = 99999 },
			field: "DXCC",
		},
		{
			name:  "no dxcc",
			edit:  func(s *Station) { s.DXCC = 0 },
			field: "DXCC",
		},
		{
			name:  "no call",
			edit:  func(s *Station) { s.Call = "" },
			field: "CALL",
		},
		{
			// Same rules as a QSO call (tqslconvert.cpp:2234-2281).
			name:  "bad call",
			edit:  func(s *Station) { s.Call = "W1AW/" },
			field: "CALL",
		},
		{
			// TX zonemap 07:04 (config.xml:7497); the US entity map
			// (config.xml:579) has 08:05, so only the state fails.
			// Message: location.cpp:1769.
			name:    "zone not in state map",
			edit:    func(s *Station) { s.ITUZ, s.CQZ = 8, 5 },
			field:   "CQZ/ITUZ",
			message: "Invalid zone selections for state",
		},
		{
			// 0 is a wildcard in inMap (location.cpp:1701-1702).
			name: "zone wildcard",
			edit: func(s *Station) { s.ITUZ, s.CQZ = 7, 0 },
		},
		{
			// 61:31 is Hawaii (config.xml:7453), not in the 291 map
			// (config.xml:579). The entity check fails, but the text is
			// the primary subdivision's, because get_primary_sub
			// overwrites zone_error (location.cpp:2133,2144,1785).
			name: "entity fails, state text",
			edit: func(s *Station) {
				s.ITUZ, s.CQZ = 61, 31
				s.Fields = map[string]string{}
			},
			field:   "CQZ/ITUZ",
			message: "Invalid zone selections for state",
		},
		{
			// AFGHANISTAN zonemap 40:21 (config.xml:298), no
			// subdivision page, so the entity text stays
			// (location.cpp:2133).
			name: "entity only",
			edit: func(s *Station) {
				s.DXCC = 3
				s.ITUZ, s.CQZ = 1, 1
				s.Fields = nil
			},
			field:   "CQZ/ITUZ",
			message: "Invalid zone selections for DXCC entity",
		},
		{
			// ON zonemap 03:04,04:04 (config.xml:723); 02:03 is in the
			// CANADA map (config.xml:296) but not ON's. Message:
			// location.cpp:1770.
			name: "province",
			edit: func(s *Station) {
				s.Call = "VE3TST"
				s.DXCC = 1
				s.ITUZ, s.CQZ = 2, 3
				s.Fields = map[string]string{"CA_PROVINCE": "ON"}
			},
			field:   "CQZ/ITUZ",
			message: "Invalid zone selections for province",
		},
		{
			// Deleted entities are accepted: ABU AIL ISLANDS, deleted="1"
			// zonemap 39:21 (config.xml:297). The certificate check
			// decides whether one may be used.
			name: "deleted entity",
			edit: func(s *Station) {
				s.DXCC = 2
				s.ITUZ, s.CQZ = 39, 21
				s.Fields = nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := usStation()
			tc.edit(&st)
			err := cfg.ValidateStation(st)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("ValidateStation: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidStation) {
				t.Fatalf("err = %v, want ErrInvalidStation", err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("err = %q, does not name %s", err, tc.field)
			}
			if tc.message != "" && !strings.Contains(err.Error(), tc.message) {
				t.Errorf("err = %q, want it to contain %q", err, tc.message)
			}
		})
	}
}

func FuzzValidateStation(f *testing.F) {
	cfg := loadTestConfig(f, "config-11.35.xml")
	f.Add("KF0TST", 291, "EM10dh", 7, 4, "", "US_STATE", "TX", "US_COUNTY", "Travis")
	f.Add("VE3TST", 1, "", 0, 0, "na-001", "CA_PROVINCE", "on", "CA_US_PARK", "x")
	f.Add("", 0, "", -1, 99, "", "", "", "ZERR", "")
	f.Fuzz(func(t *testing.T, call string, dxcc int, grid string, ituz, cqz int, iota, k1, v1, k2, v2 string) {
		st := Station{Call: call, DXCC: dxcc, GridSquare: grid, ITUZ: ituz, CQZ: cqz, IOTA: iota,
			Fields: map[string]string{k1: v1, k2: v2}}
		err := cfg.ValidateStation(st)
		if err != nil && !errors.Is(err, ErrInvalidStation) {
			t.Fatalf("err = %v, not ErrInvalidStation", err)
		}
		fs, ferr := cfg.stationFields(st)
		if (err == nil) != (ferr == nil) || (err != nil && err.Error() != ferr.Error()) {
			t.Fatalf("ValidateStation = %v, stationFields = %v", err, ferr)
		}
		if err == nil && (len(fs) < 2 || fs[0].name != "CALL" || fs[1].name != "DXCC") {
			t.Fatalf("valid station gives %v", fs)
		}
	})
}
