package service

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ReportQuery selects confirmation records. Dates and times are formatted in UTC.
type ReportQuery struct {
	Login, Password                        string
	QSLOnly                                *bool
	QSLSince, QSORxSince                   time.Time
	OwnCall, Callsign, Mode, Band          string
	DXCC                                   int
	StartDate, EndDate, StartTime, EndTime time.Time
	MyDetail, QSLDetail, WithOwn           bool
}

// Confirmations returns the unparsed report stream. The caller must close it.
// Its Referer is limited to the configured origin. A caller's redirect policy
// or transport can change headers, and redirect destinations can contain
// credentials supplied by the server.
func (c *Client) Confirmations(ctx context.Context, q ReportQuery) (io.ReadCloser, error) {
	v := url.Values{"login": {q.Login}, "password": {q.Password}, "qso_query": {"1"}}
	if q.QSLOnly != nil {
		if *q.QSLOnly {
			v.Set("qso_qsl", "yes")
		} else {
			v.Set("qso_qsl", "no")
		}
	}
	for k, s := range map[string]string{"qso_owncall": q.OwnCall, "qso_callsign": q.Callsign, "qso_mode": q.Mode, "qso_band": q.Band} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if q.DXCC != 0 {
		v.Set("qso_dxcc", strconv.Itoa(q.DXCC))
	}
	for _, d := range []struct {
		k, layout string
		t         time.Time
	}{{"qso_qslsince", "2006-01-02 15:04:05", q.QSLSince}, {"qso_qsorxsince", "2006-01-02 15:04:05", q.QSORxSince}, {"qso_startdate", "2006-01-02", q.StartDate}, {"qso_enddate", "2006-01-02", q.EndDate}, {"qso_starttime", "15:04:05", q.StartTime}, {"qso_endtime", "15:04:05", q.EndTime}} {
		if !d.t.IsZero() {
			v.Set(d.k, d.t.UTC().Format(d.layout))
		}
	}
	for k, b := range map[string]bool{"qso_mydetail": q.MyDetail, "qso_qsldetail": q.QSLDetail, "qso_withown": q.WithOwn} {
		if b {
			v.Set(k, "yes")
		}
	}
	req, err := c.request(ctx, http.MethodGet, "/lotwuser/lotwreport.adi", v, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Referer", req.URL.Scheme+"://"+req.URL.Host+"/")
	resp, err := c.do(req, "confirmations")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, ErrUnexpectedResponse
	}
	reader := bufio.NewReader(resp.Body)
	const prefix = "ARRL Logbook of the World Status Report"
	p, err := reader.Peek(len(prefix))
	if err == nil && string(p) == prefix {
		return &reportBody{reader: reader, body: resp.Body, ctx: ctx}, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		_ = resp.Body.Close()
		return nil, transportError(ctx, "confirmations response", err)
	}
	b, readErr := io.ReadAll(io.LimitReader(reader, 6000))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, transportError(ctx, "confirmations response", readErr)
	}
	if strings.Contains(string(b), "Username/password incorrect</I>") {
		return nil, ErrBadLogin
	}
	if strings.Contains(string(b), "Page Request Limit!</B>") {
		return nil, ErrRateLimited
	}
	return nil, ErrUnexpectedResponse
}

type reportBody struct {
	reader io.Reader
	body   io.Closer
	ctx    context.Context
}

func (r *reportBody) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		return n, transportError(r.ctx, "confirmations response", err)
	}
	return n, err
}
func (r *reportBody) Close() error {
	if err := r.body.Close(); err != nil {
		return transportError(r.ctx, "confirmations response", err)
	}
	return nil
}
