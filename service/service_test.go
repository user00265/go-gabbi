package service

import (
	"context"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUpload(t *testing.T) {
	cases := []struct {
		name, response string
		status         int
		want           string
		target         error
	}{
		// synthetic: format from TrustedQSL apps/tqsl.cpp:3246-3305.
		{"accepted", "<!-- .UPL. accepted -->\n<!-- .UPLMESSAGE. File queued -->", 200, "File queued", nil},
		{"rejected", "<!-- .UPL. rejected -->\n<!-- .UPLMESSAGE. Invalid file -->", 200, "Invalid file", ErrRejected},
		{"missing", "no marker", 200, "", ErrUnexpectedResponse},
		{"status ignored", "<!-- .UPL. accepted -->", 500, "", nil},
		{"request error", "<!-- .UPL. accepted -->\n<!-- .UPLMESSAGE. Started processing...\nYour certificate request contains error -->", 200, "", ErrRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/lotw/upload" || r.UserAgent() != "test-agent" {
					t.Errorf("request: %s %s %s", r.Method, r.URL.Path, r.UserAgent())
				}
				mr, err := r.MultipartReader()
				if err != nil {
					t.Error(err)
					return
				}
				p, err := mr.NextPart()
				if err != nil {
					t.Error(err)
					return
				}
				b, _ := io.ReadAll(p)
				if p.FormName() != "upfile" || p.FileName() != "test.tq5" || p.Header.Get("Content-Type") != "application/octet-stream" || string(b) != "payload" {
					t.Errorf("part: %q %q %q %q", p.FormName(), p.FileName(), p.Header.Get("Content-Type"), b)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.response)
			}))
			defer s.Close()
			c := Client{HTTP: s.Client(), BaseURL: s.URL, UserAgent: "test-agent"}
			got, err := c.Upload(context.Background(), strings.NewReader("payload"), "test.tq5")
			if !errors.Is(err, tc.target) {
				t.Fatalf("error %v, want %v", err, tc.target)
			}
			if tc.target == nil && got.Message != tc.want {
				t.Errorf("message %q", got.Message)
			}
			if errors.Is(tc.target, ErrRejected) {
				var rejected *RejectedError
				if !errors.As(err, &rejected) {
					t.Errorf("missing RejectedError: %v", err)
				} else if tc.want != "" && rejected.Message != tc.want {
					t.Errorf("message %q", rejected.Message)
				}
			}
		})
	}
}

func TestCertStatus(t *testing.T) {
	// synthetic: format from TrustedQSL apps/tqsl.cpp:3408-3423; root is unverified.
	for _, tc := range []struct {
		body string
		want CertStatus
		err  error
	}{{"<root><Status>Unrevoked</Status></root>", Unrevoked, nil}, {"<root><Status>Superceded</Status></root>", Superseded, nil}, {"<root><Status>Expired</Status></root>", Expired, nil}, {"<root><Status>Bad serial</Status></root>", BadSerial, nil}, {"<root><Status>new</Status></root>", 0, ErrUnexpectedResponse}, {"<root><Status>Expired", 0, ErrUnexpectedResponse}} {
		t.Run(tc.body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/lotw/crl" || r.URL.RawQuery != "serial=724071" {
					t.Errorf("query %s", r.URL.String())
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			c := Client{HTTP: s.Client(), BaseURL: s.URL}
			got, err := c.CertStatus(context.Background(), big.NewInt(724071))
			if !errors.Is(err, tc.err) || (err == nil && got != tc.want) {
				t.Errorf("got %v, %v", got, err)
			}
		})
	}
}

func TestConfirmations(t *testing.T) {
	// synthetic: format from k0swe/lotw-qsl api/openapi.yaml and TrustedQSL apps/tqsl.cpp.
	const body = "ARRL Logbook of the World Status Report\n<eoh>\n<eor>"
	z := time.FixedZone("offset", 3600)
	when := time.Date(2024, 2, 3, 4, 5, 6, 0, z)
	yes := true
	q := ReportQuery{Login: "user", Password: "secret", QSLOnly: &yes, QSLSince: when, QSORxSince: when, OwnCall: "K1A", Callsign: "K2B", Mode: "CW", Band: "20M", DXCC: 291, StartDate: when, EndDate: when, StartTime: when, EndTime: when, MyDetail: true, QSLDetail: true, WithOwn: true}
	want := url.Values{"login": {"user"}, "password": {"secret"}, "qso_query": {"1"}, "qso_qsl": {"yes"}, "qso_qslsince": {"2024-02-03 03:05:06"}, "qso_qsorxsince": {"2024-02-03 03:05:06"}, "qso_owncall": {"K1A"}, "qso_callsign": {"K2B"}, "qso_mode": {"CW"}, "qso_band": {"20M"}, "qso_dxcc": {"291"}, "qso_startdate": {"2024-02-03"}, "qso_enddate": {"2024-02-03"}, "qso_starttime": {"03:05:06"}, "qso_endtime": {"03:05:06"}, "qso_mydetail": {"yes"}, "qso_qsldetail": {"yes"}, "qso_withown": {"yes"}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lotwuser/lotwreport.adi" || !reflect.DeepEqual(r.URL.Query(), want) {
			t.Errorf("unexpected query: %v", r.URL.Query())
		}
		_, _ = io.WriteString(w, body)
	}))
	defer s.Close()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	result, err := c.Confirmations(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = result.Close() }()
	b, err := io.ReadAll(result)
	if err != nil || string(b) != body {
		t.Errorf("body %q: %v", b, err)
	}
}

func TestConfirmationResponses(t *testing.T) {
	// synthetic: format from TrustedQSL apps/tqsl.cpp and k0swe/lotw-qsl api/openapi.yaml.
	for _, tc := range []struct {
		body   string
		target error
	}{{"<I>Username/password incorrect</I>", ErrBadLogin}, {"<B>Page Request Limit!</B>", ErrRateLimited}, {"other", ErrUnexpectedResponse}} {
		t.Run(tc.body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !reflect.DeepEqual(r.URL.Query(), url.Values{"login": {"a"}, "password": {"b"}, "qso_query": {"1"}}) {
					t.Errorf("query %v", r.URL.Query())
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			c := Client{HTTP: s.Client(), BaseURL: s.URL}
			_, err := c.Confirmations(context.Background(), ReportQuery{Login: "a", Password: "b"})
			if !errors.Is(err, tc.target) {
				t.Errorf("error %v", err)
			}
		})
	}
}

func TestUserActivity(t *testing.T) {
	// synthetic: inferred format from docs/knowledge.md §21.4; not a recorded response.
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		body   string
		status int
		target error
		line   bool
	}{{"K1ABC,2024-02-03,04:05:06\nK2XYZ,2024-02-04,05:06:07\n", 200, nil, false}, {"", 304, nil, false}, {"K1ABC,invalid,time\n", 200, ErrUnexpectedResponse, true}, {"failure", 500, ErrUnexpectedResponse, false}} {
		t.Run(tc.body+string(rune(tc.status)), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/lotw-user-activity.csv" || r.Header.Get("If-Modified-Since") != since.Format(http.TimeFormat) {
					t.Errorf("request %v", r)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			c := Client{HTTP: s.Client(), BaseURL: s.URL}
			got, err := c.UserActivity(context.Background(), since)
			if !errors.Is(err, tc.target) {
				t.Fatalf("error %v", err)
			}
			if tc.line && !strings.Contains(err.Error(), "line 1") {
				t.Errorf("missing line: %v", err)
			}
			if tc.status == 304 && !got.NotModified {
				t.Error("not modified missing")
			}
			if tc.status == 200 && err == nil && (len(got.Users) != 2 || got.Users[0].Callsign != "K1ABC" || got.Users[0].LastUpload != time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)) {
				t.Errorf("activity %+v", got)
			}
		})
	}
}

func TestTransportErrorHidesURL(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	s.Close()
	_, err := c.Confirmations(context.Background(), ReportQuery{Password: "s3cr3t"})
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "password=") || strings.Contains(err.Error(), s.URL) {
		t.Fatalf("error %v", err)
	}
}
func TestClientChecks(t *testing.T) {
	var c Client
	if _, err := c.UserActivity(context.Background(), time.Time{}); !errors.Is(err, ErrNoClient) {
		t.Errorf("nil client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.HTTP = http.DefaultClient
	if _, err := c.UserActivity(ctx, time.Time{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDefaultEndpointAndAgent(t *testing.T) {
	c := Client{HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://lotw.arrl.org/lotw-user-activity.csv" || r.UserAgent() != "go-gabbi" || r.Header.Get("If-Modified-Since") != "" {
			t.Errorf("unexpected default request: %s %s", r.URL, r.UserAgent())
		}
		// synthetic: inferred format from docs/knowledge.md §21.4.
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("K1ABC,2024-02-03,04:05:06\n")), Header: make(http.Header)}, nil
	})}}
	if _, err := c.UserActivity(context.Background(), time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestCertStatusRejectsTrailingXML(t *testing.T) {
	// synthetic: format from TrustedQSL apps/tqsl.cpp:3408-3423.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<root><Status>Unrevoked</Status></root><broken")
	}))
	defer s.Close()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	if _, err := c.CertStatus(context.Background(), big.NewInt(1)); !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("got %v", err)
	}
}

func TestUploadRequestErrorOnlyForTQ5(t *testing.T) {
	// synthetic: format from TrustedQSL apps/tqsl.cpp:3252,3268-3274.
	body := "<!-- .UPL. accepted -->\n<!-- .UPLMESSAGE. Started processing...\nYour certificate request contains error -->"
	if _, err := parseUploadResponse(body, "file.tq8"); err != nil {
		t.Fatalf("tq8: %v", err)
	}
}

func TestConfirmationsExplicitQSLNo(t *testing.T) {
	no := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("qso_qsl") != "no" {
			t.Errorf("qso_qsl: %q", r.URL.Query().Get("qso_qsl"))
		}
		// synthetic: format from k0swe/lotw-qsl api/openapi.yaml.
		_, _ = io.WriteString(w, "ARRL Logbook of the World Status Report")
	}))
	defer s.Close()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	b, err := c.Confirmations(context.Background(), ReportQuery{QSLOnly: &no})
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
}

func TestUploadCancelledBeforeReadingInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &countingReader{}
	c := Client{HTTP: http.DefaultClient}
	_, err := c.Upload(ctx, reader, "test.tq8")
	if !errors.Is(err, context.Canceled) || reader.reads != 0 {
		t.Fatalf("error %v, reads %d", err, reader.reads)
	}
}

type countingReader struct{ reads int }

func (r *countingReader) Read([]byte) (int, error) { r.reads++; return 0, io.EOF }
