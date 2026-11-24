package gabbi

import (
	"errors"
	"testing"
	"time"
)

// Cases follow tqsl_initDate (tqsllib.cpp:954-998) and tqsl_isDateValid
// (tqsllib.cpp:777-797).
func TestParseDate(t *testing.T) {
	tests := []struct {
		in      string
		want    Date
		wantErr bool
	}{
		{in: "2020-05-14", want: Date{2020, time.May, 14}},
		{in: "20200514", want: Date{2020, time.May, 14}},
		{in: "2024-02-29", want: Date{2024, time.February, 29}},
		{in: "2023-02-29", wantErr: true},
		{in: "1900-02-29", wantErr: true},
		{in: "2000-02-29", want: Date{2000, time.February, 29}},
		{in: "2020-13-01", wantErr: true},
		{in: "0-01-01", wantErr: true},
		{in: "2020-1", wantErr: true},
		{in: "2020051", wantErr: true},
		// Further tqsl_isDateValid limits.
		{in: "9999-12-31", want: Date{9999, time.December, 31}},
		{in: "10000-01-01", wantErr: true},
		{in: "2020-04-31", wantErr: true},
		{in: "2020-00-10", wantErr: true},
		{in: "2020-01-00", wantErr: true},
		{in: "", wantErr: true},
		{in: "abcdefgh", wantErr: true},
		// tqsl_initDate reads each part with strtol, so the dashed form
		// takes unpadded parts and ignores what follows the day.
		{in: "2020-5-4", want: Date{2020, time.May, 4}},
		{in: "2020-05-14T00:00", want: Date{2020, time.May, 14}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDate(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidDate) {
					t.Fatalf("ParseDate(%q) = %v, %v; want ErrInvalidDate", tt.in, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDate(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ParseDate(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestDateString(t *testing.T) {
	tests := []struct {
		d    Date
		want string
	}{
		{Date{2020, time.May, 14}, "2020-05-14"},
		{Date{1, time.January, 2}, "0001-01-02"},
		{Date{}, "0000-00-00"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestDateOf(t *testing.T) {
	// 23:30 on May 13 at UTC-5 is May 14 in UTC.
	loc := time.FixedZone("UTC-5", -5*3600)
	got := DateOf(time.Date(2020, time.May, 13, 23, 30, 0, 0, loc))
	if want := (Date{2020, time.May, 14}); got != want {
		t.Fatalf("DateOf = %+v, want %+v", got, want)
	}
}

func TestDateCompare(t *testing.T) {
	a := Date{2020, time.May, 14}
	tests := []struct {
		b    Date
		want int
	}{
		{Date{2020, time.May, 14}, 0},
		{Date{2020, time.May, 15}, -1},
		{Date{2020, time.June, 1}, -1},
		{Date{2021, time.January, 1}, -1},
		{Date{2020, time.May, 13}, 1},
		{Date{2020, time.April, 30}, 1},
		{Date{2019, time.December, 31}, 1},
	}
	for _, tt := range tests {
		if got := a.Compare(tt.b); got != tt.want {
			t.Errorf("%v.Compare(%v) = %d, want %d", a, tt.b, got, tt.want)
		}
	}
}

func TestDateIsZero(t *testing.T) {
	if !(Date{}).IsZero() {
		t.Error("Date{}.IsZero() = false")
	}
	if (Date{2020, time.May, 14}).IsZero() {
		t.Error("2020-05-14 IsZero() = true")
	}
}

func FuzzParseDate(f *testing.F) {
	for _, s := range []string{"2020-05-14", "20200514", "2024-02-29", "0-01-01", "2020-1", "", "-", "--", "9999-12-31"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDate(s)
		if err != nil {
			return
		}
		if d.Year < 1 || d.Year > 9999 || d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31 {
			t.Fatalf("ParseDate(%q) = %+v, out of range", s, d)
		}
		back, err := ParseDate(d.String())
		if err != nil || back != d {
			t.Fatalf("round trip of %q: %+v -> %q -> %+v, %v", s, d, d.String(), back, err)
		}
	})
}
