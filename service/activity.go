package service

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Activity holds the service's user activity or an unchanged indication.
type Activity struct {
	NotModified bool
	Users       []UserActivity
}

// UserActivity is a callsign and its most recent upload time.
type UserActivity struct {
	Callsign   string
	LastUpload time.Time
}

// UserActivity retrieves activity updated since the supplied time.
func (c *Client) UserActivity(ctx context.Context, since time.Time) (Activity, error) {
	req, err := c.request(ctx, http.MethodGet, "/lotw-user-activity.csv", nil, nil)
	if err != nil {
		return Activity{}, err
	}
	if !since.IsZero() {
		req.Header.Set("If-Modified-Since", since.UTC().Format(http.TimeFormat))
	}
	resp, err := c.do(req, "user activity")
	if err != nil {
		return Activity{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		return Activity{NotModified: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Activity{}, ErrUnexpectedResponse
	}
	limited := &io.LimitedReader{R: resp.Body, N: 64<<20 + 1}
	users, err := parseActivity(limited)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Activity{}, transportError(ctx, "user activity", err)
		}
		return Activity{}, err
	}
	if limited.N == 0 {
		return Activity{}, ErrUnexpectedResponse
	}
	return Activity{Users: users}, nil
}

func parseActivity(input io.Reader) ([]UserActivity, error) {
	r := csv.NewReader(input)
	r.FieldsPerRecord = 3
	var users []UserActivity
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return users, nil
		}
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, context.Canceled
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, context.DeadlineExceeded
			}
			var pe *csv.ParseError
			if !errors.As(err, &pe) {
				return nil, fmt.Errorf("activity response: %w", ErrTransport)
			}
			return nil, fmt.Errorf("activity line %d: %w", pe.Line, ErrUnexpectedResponse)
		}
		line, _ := r.FieldPos(0)
		date, err := time.Parse("2006-01-02 15:04:05", row[1]+" "+row[2])
		if err != nil || row[0] == "" {
			return nil, fmt.Errorf("activity line %d: %w", line, ErrUnexpectedResponse)
		}
		users = append(users, UserActivity{Callsign: row[0], LastUpload: date})
	}
}
