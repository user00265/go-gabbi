package gabbi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// readTestdata returns the bytes of testdata/name.
func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return b
}

// loadTestConfig parses testdata/name with ParseConfig and fails the test on
// any error.
func loadTestConfig(t testing.TB, name string) *Config {
	t.Helper()
	cfg, err := ParseConfig(bytes.NewReader(readTestdata(t, name)))
	if err != nil {
		t.Fatalf("ParseConfig(testdata/%s): %v", name, err)
	}
	return cfg
}
