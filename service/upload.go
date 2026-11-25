package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// UploadResult contains the service's upload message.
type UploadResult struct{ Message string }

// ContextReader is an io.Reader that also supports cancellation of an active
// read. ReadContext must return promptly when its context is cancelled. Upload
// calls ReadContext instead of Read when the input implements this interface.
// ReadContext must not retain its buffer after it returns.
type ContextReader interface {
	io.Reader
	ReadContext(context.Context, []byte) (int, error)
}

// Upload sends a file to the service using bounded buffering. Cancellation
// stops further reads. An input implementing ContextReader can interrupt a
// blocked read on cancellation or when the transport closes the request body;
// Upload waits for any active ReadContext to finish before returning.
// An ordinary io.Reader cannot be interrupted: its blocked Read can delay
// Upload or retain a transport goroutine until the caller unblocks it. The
// caller must not reuse the input while a read remains active. Upload never
// closes the input. Streaming bodies cannot be replayed for 307/308 redirects.
func (c *Client) Upload(ctx context.Context, r io.Reader, filename string) (UploadResult, error) {
	if c == nil || c.HTTP == nil {
		return UploadResult{}, ErrNoClient
	}
	if ctx == nil {
		return UploadResult{}, fmt.Errorf("upload: %w", ErrTransport)
	}
	if err := ctx.Err(); err != nil {
		return UploadResult{}, fmt.Errorf("upload: %w: %w", ErrTransport, err)
	}
	if r == nil {
		return UploadResult{}, fmt.Errorf("upload input: %w", ErrTransport)
	}
	var framing bytes.Buffer
	mw := multipart.NewWriter(&framing)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="upfile"; filename="%s"`, strings.NewReplacer("\\", "\\\\", `"`, `\"`, "\r", "", "\n", "").Replace(filename)))
	h.Set("Content-Type", "application/octet-stream")
	_, err := mw.CreatePart(h)
	prefix := append([]byte(nil), framing.Bytes()...)
	framing.Reset()
	if err == nil {
		err = mw.Close()
	}
	if err != nil {
		return UploadResult{}, fmt.Errorf("upload input: %w", ErrTransport)
	}
	inputCtx, cancelInput := context.WithCancel(ctx)
	_, cooperative := r.(ContextReader)
	body := &uploadBody{ctx: inputCtx, cancel: cancelInput, cooperative: cooperative, reader: io.MultiReader(bytes.NewReader(prefix), &uploadInput{ctx: inputCtx, reader: r}, bytes.NewReader(framing.Bytes()))}
	defer func() { _ = body.Close(); body.wait() }()
	req, err := c.request(ctx, http.MethodPost, "/lotw/upload", nil, body)
	if err != nil {
		return UploadResult{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.do(req, "upload")
	_ = body.Close()
	if err != nil {
		return UploadResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if !body.complete.Load() {
		return UploadResult{}, transportError(ctx, "upload input", nil)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return UploadResult{}, transportError(ctx, "upload response", err)
	}
	if len(b) > 1<<20 {
		return UploadResult{}, fmt.Errorf("upload response: %w", ErrUnexpectedResponse)
	}
	return parseUploadResponse(string(b), filename)
}

type uploadInput struct {
	ctx    context.Context
	reader io.Reader
}

func (r *uploadInput) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	var n int
	var err error
	if reader, ok := r.reader.(ContextReader); ok {
		n, err = reader.ReadContext(r.ctx, p)
	} else {
		n, err = r.reader.Read(p)
	}
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	return n, err
}

type uploadBody struct {
	ctx         context.Context
	cancel      context.CancelFunc
	reader      io.Reader
	closed      atomic.Bool
	complete    atomic.Bool
	cooperative bool
	mu          sync.Mutex
	stopped     bool
}

func (b *uploadBody) Read(p []byte) (int, error) {
	if b.cooperative {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.stopped {
			return 0, io.ErrClosedPipe
		}
	}
	if b.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := b.reader.Read(p)
	if err == io.EOF {
		b.complete.Store(true)
	}
	return n, err
}

func (b *uploadBody) Close() error { b.closed.Store(true); b.cancel(); return nil }

func (b *uploadBody) wait() {
	if b.cooperative {
		b.mu.Lock()
		b.stopped = true
		b.mu.Unlock()
	}
}

func parseUploadResponse(body, filename string) (UploadResult, error) {
	status := regexp.MustCompile(`(?i)<!--\s*\.UPL\.\s*([^-]+?)\s*-->`).FindStringSubmatch(body)
	message := regexp.MustCompile(`(?is)<!--\s*\.UPLMESSAGE\.\s*(.*?)\s*-->`).FindStringSubmatch(body)
	text := ""
	if len(message) > 1 {
		text = strings.TrimSpace(regexp.MustCompile(`\n +`).ReplaceAllString(message[1], " "))
	}
	if len(status) < 2 {
		return UploadResult{}, ErrUnexpectedResponse
	}
	if !strings.EqualFold(strings.TrimSpace(status[1]), "accepted") || (strings.EqualFold(filenameExtension(filename), ".tq5") && regexp.MustCompile(`(?s)Started processing[^\n]*\n[^\n]*Your certificate request contains error`).MatchString(text)) {
		return UploadResult{}, &RejectedError{Message: text}
	}
	return UploadResult{Message: text}, nil
}

func filenameExtension(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return name[i:]
}
