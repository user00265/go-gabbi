package service

import (
	"strings"
	"testing"
)

func FuzzUploadResponse(f *testing.F) {
	// synthetic: format from TrustedQSL apps/tqsl.cpp:3246-3305.
	f.Add("<!-- .UPL. accepted -->\n<!-- .UPLMESSAGE. File queued -->", "file.tq8")
	f.Add("<!-- .UPL. rejected -->", "file.tq5")
	f.Fuzz(func(t *testing.T, body, filename string) { _, _ = parseUploadResponse(body, filename) })
}

func FuzzActivityCSV(f *testing.F) {
	// synthetic: inferred format from docs/knowledge.md §21.4.
	f.Add("K1ABC,2024-02-03,04:05:06\n")
	f.Add("bad,row\n")
	f.Fuzz(func(t *testing.T, body string) { _, _ = parseActivity(strings.NewReader(body)) })
}

func FuzzCertStatus(f *testing.F) {
	// synthetic: format from TrustedQSL apps/tqsl.cpp:3408-3423.
	f.Add([]byte("<root><Status>Unrevoked</Status></root>"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseCertStatus(data) })
}
