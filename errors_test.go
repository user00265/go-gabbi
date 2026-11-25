package gabbi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNilQSOError(t *testing.T) {
	var err *QSOError
	if got := err.Error(); got == "" {
		t.Fatal("nil QSOError returned an empty message")
	}
	if got := err.Unwrap(); got != nil {
		t.Fatalf("nil QSOError unwrapped to %v", got)
	}
}

func TestQSOErrorIs(t *testing.T) {
	e := &QSOError{Index: 3, Field: "BAND", Err: ErrInvalidQSO}
	if !errors.Is(e, ErrInvalidQSO) {
		t.Fatalf("errors.Is(%v, ErrInvalidQSO) = false, want true", e)
	}
	if errors.Is(e, ErrDateRange) {
		t.Fatalf("errors.Is(%v, ErrDateRange) = true, want false", e)
	}
}

func TestQSOErrorAs(t *testing.T) {
	e := &QSOError{Index: 3, Field: "BAND", Err: ErrInvalidQSO}
	wrapped := fmt.Errorf("x: %w", e)

	var got *QSOError
	if !errors.As(wrapped, &got) {
		t.Fatalf("errors.As(%v, *QSOError) = false, want true", wrapped)
	}
	if got.Index != 3 {
		t.Errorf("Index = %d, want 3", got.Index)
	}
	if !errors.Is(wrapped, ErrInvalidQSO) {
		t.Errorf("errors.Is through wrap = false, want true")
	}
}

func TestQSOErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		err  *QSOError
		want []string
	}{
		{
			name: "no detail",
			err:  &QSOError{Index: 3, Field: "BAND", Err: ErrInvalidQSO},
			want: []string{"QSO 3", "BAND"},
		},
		{
			name: "with detail",
			err:  &QSOError{Index: 3, Field: "BAND", Err: ErrInvalidQSO, Detail: "unknown band 7M"},
			want: []string{"QSO 3", "BAND", "unknown band 7M"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, w := range tt.want {
				if !strings.Contains(msg, w) {
					t.Errorf("Error() = %q, want it to contain %q", msg, w)
				}
			}
		})
	}
}

func TestSentinelPrefix(t *testing.T) {
	sentinels := []error{
		ErrPassword, ErrNoCertificate, ErrNoKey, ErrUnsupportedKey, ErrCertMismatch,
		ErrDateRange, ErrInvalidDate, ErrExpired, ErrInvalidQSO, ErrInvalidStation, ErrConfig,
		ErrConfigOutdated, ErrDuplicate, ErrNoQSOs, ErrRestart,
	}
	seen := make(map[string]bool, len(sentinels))
	for _, s := range sentinels {
		msg := s.Error()
		if !strings.HasPrefix(msg, "gabbi: ") {
			t.Errorf("sentinel %q lacks the %q prefix", msg, "gabbi: ")
		}
		if seen[msg] {
			t.Errorf("duplicate sentinel message %q", msg)
		}
		seen[msg] = true
	}
}
