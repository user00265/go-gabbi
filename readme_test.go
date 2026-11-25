package gabbi_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	gabbi "github.com/user00265/go-gabbi"
)

// TestReadmeSketchSyntax extracts the actual README example; the Go compiler
// independently checks the mirrored external-package example below.
func TestReadmeSketchSyntax(t *testing.T) {
	if err := readmeSketch(context.Background(), io.Discard, nil, nil, nil); err == nil {
		t.Fatal("README sketch accepted an empty configuration")
	}
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(data), "```go\n")
	if !found {
		t.Fatal("README has no Go example")
	}
	sketch, _, found := strings.Cut(rest, "\n```")
	if !found {
		t.Fatal("README Go example is not closed")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "README.md", "package example\nfunc sketch(){\n"+sketch+"\n}", 0)
	if err != nil {
		t.Fatalf("README sketch: %v", err)
	}
	testFile, err := parser.ParseFile(fset, "readme_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mirror *ast.FuncDecl
	for _, decl := range testFile.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "readmeSketch" {
			mirror = fn
		}
	}
	if mirror == nil || len(mirror.Body.List) == 0 {
		t.Fatal("compiled README sketch is missing")
	}
	var want, got bytes.Buffer
	for _, stmt := range file.Decls[0].(*ast.FuncDecl).Body.List {
		if err := format.Node(&want, fset, stmt); err != nil {
			t.Fatal(err)
		}
		want.WriteByte('\n')
	}
	for _, stmt := range mirror.Body.List {
		if err := format.Node(&got, fset, stmt); err != nil {
			t.Fatal(err)
		}
		got.WriteByte('\n')
	}
	if !bytes.Equal(want.Bytes(), got.Bytes()) {
		t.Fatal("README sketch differs from the compiled readmeSketch function")
	}
}

func readmeSketch(ctx context.Context, out io.Writer, storedConfig, p12Bytes []byte, store gabbi.DupeStore) error {
	cfg, err := gabbi.ParseConfig(bytes.NewReader(storedConfig))
	if err != nil {
		return err
	}
	cred, _, err := gabbi.LoadPKCS12(p12Bytes, "")
	if err != nil {
		return err
	}
	creds := []gabbi.Credential{cred}

	st := gabbi.Station{
		Call:       "KF0TST",
		DXCC:       291,
		GridSquare: "EM10dh",
		Fields:     map[string]string{"US_STATE": "TX", "US_COUNTY": "Travis"},
	}
	qsos := []gabbi.QSO{{Call: "W1AW", Band: "20M", Mode: "SSB", Freq: "14.250",
		Time: time.Date(2026, 11, 1, 15, 30, 0, 0, time.UTC)}}

	zw := gzip.NewWriter(out)
	report, err := gabbi.Sign(ctx, zw, cfg, creds, st, slices.Values(qsos),
		gabbi.SignOptions{Action: gabbi.Compliant, Dupes: store})
	if err == nil {
		err = zw.Close()
	}
	_ = report.Commit
	return err
}
