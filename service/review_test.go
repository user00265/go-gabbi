package service

import (
	"context"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfirmationsRedirectDoesNotLeakReferer(t *testing.T) {
	seen := make(chan string, 1)
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Referer()
		// synthetic: k0swe/lotw-qsl api/openapi.yaml.
		_, _ = io.WriteString(w, "ARRL Logbook of the World Status Report")
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/report", http.StatusFound)
	}))
	defer source.Close()
	c := Client{HTTP: source.Client(), BaseURL: source.URL}
	response, err := c.Confirmations(context.Background(), ReportQuery{Login: "tester", Password: "s3cr3t"})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Close()
	referer := <-seen
	if strings.Contains(referer, "s3cr3t") || strings.Contains(referer, "password=") {
		t.Fatalf("credential in Referer: %q", referer)
	}
}

func TestResponseBodyCancellation(t *testing.T) {
	for _, operation := range []string{"upload", "status", "activity", "report-prefix", "report-stream"} {
		for _, deadline := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/cancel", true: "/deadline"}[deadline], func(t *testing.T) {
				bodyRead := make(chan struct{})
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// synthetic: k0swe/lotw-qsl api/openapi.yaml; TrustedQSL apps/tqsl.cpp:3246-3305,3408-3423; activity inferred in knowledge §21.4.
					if operation == "report-stream" {
						_, _ = io.WriteString(w, "ARRL Logbook of the World Status Report")
					}
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				defer s.Close()
				var ctx context.Context
				var cancel context.CancelFunc
				if deadline {
					ctx, cancel = context.WithTimeout(context.Background(), 400*time.Millisecond)
				} else {
					ctx, cancel = context.WithCancel(context.Background())
				}
				defer cancel()
				httpClient := s.Client()
				originalTransport := httpClient.Transport
				httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					resp, err := originalTransport.RoundTrip(r)
					if err == nil {
						resp.Body = &observedBody{ReadCloser: resp.Body, started: bodyRead}
					}
					return resp, err
				})
				c := Client{HTTP: httpClient, BaseURL: s.URL}
				result := make(chan error, 1)
				go func() {
					var err error
					switch operation {
					case "upload":
						_, err = c.Upload(ctx, strings.NewReader("x"), "file.tq8")
					case "status":
						_, err = c.CertStatus(ctx, big.NewInt(1))
					case "activity":
						_, err = c.UserActivity(ctx, time.Time{})
					default:
						var body io.ReadCloser
						body, err = c.Confirmations(ctx, ReportQuery{Password: "s3cr3t"})
						if err == nil {
							_, err = io.ReadAll(body)
							_ = body.Close()
						}
					}
					result <- err
				}()
				select {
				case <-bodyRead:
				case <-time.After(3 * time.Second):
					t.Fatal("response body read did not start")
				}
				if !deadline {
					cancel()
				}
				select {
				case err := <-result:
					want := context.Canceled
					if deadline {
						want = context.DeadlineExceeded
					}
					if !errors.Is(err, want) || !errors.Is(err, ErrTransport) {
						t.Errorf("got %v, want %v and ErrTransport", err, want)
					}
					if err != nil && (strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), s.URL)) {
						t.Errorf("sensitive error: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("operation did not return")
				}
			})
		}
	}
}

type observedBody struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (b *observedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.ReadCloser.Read(p)
}

type gatedUploadReader struct {
	count    int
	consumed <-chan struct{}
}

func (r *gatedUploadReader) Read(p []byte) (int, error) {
	r.count++
	if r.count == 1 {
		for i := range p {
			p[i] = 'x'
		}
		return len(p), nil
	}
	if r.count == 2 {
		select {
		case <-r.consumed:
		case <-time.After(time.Second):
			return 0, errors.New("server did not receive streaming body")
		}
	}
	if r.count > 257 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestUploadStreamsBeforeInputEOF(t *testing.T) {
	consumed := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			return
		}
		part, err := mr.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		buf := make([]byte, 1024)
		if _, err = io.ReadFull(part, buf); err != nil {
			t.Error(err)
			return
		}
		close(consumed)
		n, err := io.Copy(io.Discard, part)
		if err != nil {
			t.Error(err)
		}
		if n < 1<<20 {
			t.Errorf("only %d bytes", n)
		}
		// synthetic: format from TrustedQSL apps/tqsl.cpp:3246-3305.
		_, _ = io.WriteString(w, "<!-- .UPL. accepted -->")
	}))
	defer s.Close()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	_, err := c.Upload(context.Background(), &gatedUploadReader{consumed: consumed}, "large.tq8")
	if err != nil {
		t.Fatal(err)
	}
}

type cancelUploadReader struct {
	cancel context.CancelFunc
	reads  atomic.Int32
}

func (r *cancelUploadReader) Read(p []byte) (int, error) {
	n := r.reads.Add(1)
	if n == 3 {
		r.cancel()
	}
	if n > 100 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestUploadCancellationStopsInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancelUploadReader{cancel: cancel}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { _, _ = io.Copy(io.Discard, req.Body) }))
	defer s.Close()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	_, err := c.Upload(ctx, r, "file.tq8")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v", err)
	}
	if n := r.reads.Load(); n > 4 {
		t.Fatalf("read %d times after cancellation", n)
	}
}

type failedUploadReader struct{}

func (failedUploadReader) Read([]byte) (int, error) {
	return 0, errors.New("s3cr3t https://example.invalid")
}

func TestUploadInputReadErrorSanitized(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer s.Close()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	_, err := c.Upload(context.Background(), failedUploadReader{}, "x.tq8")
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("error %v", err)
	}
}

type endlessUploadReader struct{ calls atomic.Int32 }

func (r *endlessUploadReader) Read(p []byte) (int, error) {
	r.calls.Add(1)
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestUploadEarlyResponseStopsProducer(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// synthetic: format from TrustedQSL apps/tqsl.cpp:3246-3305.
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "<!-- .UPL. accepted -->")
		w.(http.Flusher).Flush()
	}))
	defer s.Close()
	r := &endlessUploadReader{}
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.Upload(ctx, r, "x.tq8")
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("early response error %v", err)
	}
	before := r.calls.Load()
	time.Sleep(100 * time.Millisecond)
	after := r.calls.Load()
	if after > before+1 {
		t.Errorf("input still being read: %d -> %d", before, after)
	}
}

type blockingUploadReader struct{ entered, release, exited chan struct{} }

func (r *blockingUploadReader) Read([]byte) (int, error) {
	close(r.entered)
	<-r.release
	close(r.exited)
	return 0, io.EOF
}

type contextUploadReader struct {
	entered, release, exited chan struct{}
	closed                   atomic.Bool
}

func (r *contextUploadReader) Read([]byte) (int, error) {
	return 0, errors.New("ReadContext was not used")
}
func (r *contextUploadReader) Close() error { r.closed.Store(true); return nil }
func (r *contextUploadReader) ReadContext(ctx context.Context, _ []byte) (int, error) {
	close(r.entered)
	defer close(r.exited)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-r.release:
		return 0, io.EOF
	}
}

func TestUploadContextReaderReturnsBeforeRelease(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			r := &contextUploadReader{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			var release sync.Once
			defer release.Do(func() { close(r.release) })
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { _, _ = io.Copy(io.Discard, req.Body) }))
			defer s.Close()
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			c := Client{HTTP: s.Client(), BaseURL: s.URL}
			done := make(chan error, 1)
			go func() { _, err := c.Upload(ctx, r, "x.tq8"); done <- err }()
			select {
			case <-r.entered:
			case err := <-done:
				t.Fatalf("returned before ReadContext: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("reader did not start")
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				want := context.Canceled
				if deadline {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) || !errors.Is(err, ErrTransport) {
					t.Fatalf("error %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("upload did not return before releasing input")
			}
			select {
			case <-r.exited:
			default:
				t.Fatal("reader still active after Upload returned")
			}
			if r.closed.Load() {
				t.Fatal("caller-owned reader closed")
			}
		})
	}
}

func TestUploadContextReaderStopsOnEarlyResponse(t *testing.T) {
	r := &contextUploadReader{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(r.release) })
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-r.entered:
		case <-time.After(3 * time.Second):
			t.Error("input did not start")
			return
		}
		// synthetic: format from TrustedQSL apps/tqsl.cpp:3246-3305.
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "<!-- .UPL. accepted -->")
		w.(http.Flusher).Flush()
	}))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	_, err := c.Upload(ctx, r, "x.tq8")
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("error %v", err)
	}
	select {
	case <-r.exited:
	case <-time.After(3 * time.Second):
		t.Fatal("reader did not stop after response")
	}
	if r.closed.Load() {
		t.Fatal("caller-owned reader closed")
	}
}

type slowStoppingReader struct{ entered, stopping, release, exited chan struct{} }

func (r *slowStoppingReader) Read([]byte) (int, error) { return 0, errors.New("unexpected Read") }
func (r *slowStoppingReader) ReadContext(ctx context.Context, _ []byte) (int, error) {
	close(r.entered)
	<-ctx.Done()
	close(r.stopping)
	<-r.release
	close(r.exited)
	return 0, ctx.Err()
}

func TestUploadWaitsForContextReaderBeforeReturn(t *testing.T) {
	r := &slowStoppingReader{entered: make(chan struct{}), stopping: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(r.release) })
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		go func() { _, _ = io.Copy(io.Discard, req.Body); _ = req.Body.Close() }()
		<-r.entered
		// synthetic: format from TrustedQSL apps/tqsl.cpp:3246-3305.
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<!-- .UPL. accepted -->")), Header: make(http.Header)}, nil
	})}
	c := Client{HTTP: httpClient, BaseURL: "https://example.invalid"}
	done := make(chan error, 1)
	go func() { _, err := c.Upload(context.Background(), r, "x.tq8"); done <- err }()
	select {
	case <-r.stopping:
	case <-time.After(3 * time.Second):
		t.Fatal("reader not cancelled")
	}
	select {
	case err := <-done:
		t.Fatalf("returned while reader active: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release.Do(func() { close(r.release) })
	select {
	case <-r.exited:
	case <-time.After(3 * time.Second):
		t.Fatal("reader did not exit")
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("error %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upload did not return")
	}
}

func TestUploadBlockedReaderCanFinishAfterCancellation(t *testing.T) {
	r := &blockingUploadReader{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { _, _ = io.Copy(io.Discard, req.Body) }))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := Client{HTTP: s.Client(), BaseURL: s.URL}
	done := make(chan error, 1)
	go func() { _, err := c.Upload(ctx, r, "x.tq8"); done <- err }()
	select {
	case <-r.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("reader not started")
	}
	cancel()
	close(r.release)
	select {
	case <-r.exited:
	case <-time.After(3 * time.Second):
		t.Fatal("reader did not exit after release")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upload did not finish")
	}
}

type deadlineBody struct{}

func (deadlineBody) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }
func (deadlineBody) Close() error             { return nil }

func TestResponseDeadlineErrorWithoutContextExpiry(t *testing.T) {
	c := Client{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: deadlineBody{}, Header: make(http.Header)}, nil
	})}, BaseURL: "https://example.invalid"}
	_, err := c.CertStatus(context.Background(), big.NewInt(1))
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrTransport) {
		t.Fatalf("error %v", err)
	}
}

func TestCertStatusDuplicateStatus(t *testing.T) {
	for _, body := range []string{
		// synthetic: format from TrustedQSL apps/tqsl.cpp:3408-3423.
		"<root><Status>Expired</Status><Status>Unrevoked</Status></root>",
		"<root><Status>Unrevoked</Status><Status>Expired</Status></root>",
		"<root><Status>Unrevoked</Status><Status>Unrevoked</Status></root>",
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		c := Client{HTTP: s.Client(), BaseURL: s.URL}
		_, err := c.CertStatus(context.Background(), big.NewInt(1))
		s.Close()
		if !errors.Is(err, ErrUnexpectedResponse) {
			t.Errorf("%q: %v", body, err)
		}
	}
}
