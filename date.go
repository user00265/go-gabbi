package gabbi

import (
	"cmp"
	"fmt"
	"strings"
	"time"
)

// Date is a calendar date with no time of day or time zone. TrustedQSL
// compares QSO dates against a certificate's QSO date range by date alone.
// The zero Date means "not set".
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// ParseDate parses a date the way TrustedQSL's tqsl_initDate does
// (tqsllib.cpp:954-998). It accepts YYYY-MM-DD and the 8-character form
// YYYYMMDD. In the dashed form each part is read like C's strtol, so
// "2020-5-4" is accepted and anything after the day's digits is ignored. The
// result must then pass tqsl_isDateValid (tqsllib.cpp:777-797): year 1 to
// 9999, month 1 to 12, and a day that exists in that month, with Gregorian
// leap years.
func ParseDate(s string) (Date, error) {
	// TrustedQSL works on C strings, so a NUL ends the input.
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	var d Date
	if i := strings.IndexByte(s, '-'); i >= 0 {
		d.Year = strtol(s)
		rest := s[i+1:]
		d.Month = time.Month(strtol(rest))
		j := strings.IndexByte(rest, '-')
		if j < 0 {
			return Date{}, fmt.Errorf("gabbi: invalid date %q", s)
		}
		d.Day = strtol(rest[j+1:])
	} else if len(s) == 8 {
		d.Year = strtol(s[:4])
		d.Month = time.Month(strtol(s[4:6]))
		d.Day = strtol(s[6:])
	} else {
		return Date{}, fmt.Errorf("gabbi: invalid date %q", s)
	}
	if !d.valid() {
		return Date{}, fmt.Errorf("gabbi: invalid date %q", s)
	}
	return d, nil
}

// valid reports whether d passes tqsl_isDateValid (tqsllib.cpp:777-797).
func (d Date) valid() bool {
	if d.Year < 1 || d.Year > 9999 || d.Month < time.January || d.Month > time.December || d.Day < 1 {
		return false
	}
	days := [...]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if d.Year%4 == 0 && (d.Year%100 != 0 || d.Year%400 == 0) {
		days[time.February] = 29
	}
	return d.Day <= days[d.Month]
}

// DateOf returns the UTC calendar date of t.
func DateOf(t time.Time) Date {
	y, m, d := t.UTC().Date()
	return Date{Year: y, Month: m, Day: d}
}

// String returns the date as YYYY-MM-DD.
func (d Date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day)
}

// Compare returns -1 if d is before e, 0 if they are the same date and +1 if
// d is after e.
func (d Date) Compare(e Date) int {
	if c := cmp.Compare(d.Year, e.Year); c != 0 {
		return c
	}
	if c := cmp.Compare(d.Month, e.Month); c != 0 {
		return c
	}
	return cmp.Compare(d.Day, e.Day)
}

// IsZero reports whether d is the zero Date, which means "not set".
func (d Date) IsZero() bool {
	return d == Date{}
}
