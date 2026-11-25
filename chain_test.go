package gabbi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

var chainTestNow = time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)

func chainTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func chainTestCert(t *testing.T, name string, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, before, after time.Time, ca bool, serial int64) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: before, NotAfter: after, BasicConstraintsValid: true, IsCA: ca,
	}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func chainTestFixture(t *testing.T) (leaf, ca, root *x509.Certificate) {
	t.Helper()
	rootKey, caKey, leafKey := chainTestKey(t), chainTestKey(t), chainTestKey(t)
	root = chainTestCert(t, "root", rootKey, nil, nil, chainTestNow.AddDate(-5, 0, 0), chainTestNow.AddDate(5, 0, 0), true, 1)
	ca = chainTestCert(t, "CA", caKey, root, rootKey, chainTestNow.AddDate(-4, 0, 0), chainTestNow.AddDate(1, 0, 0), true, 2)
	leaf = chainTestCert(t, "leaf", leafKey, ca, caKey, chainTestNow.AddDate(-2, 0, 0), chainTestNow.AddDate(2, 0, 0), false, 3)
	return
}

func TestVerifyChainStrict(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	chain, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 || !bytes.Equal(chain[0].Raw, leaf.Raw) || !bytes.Equal(chain[1].Raw, ca.Raw) || !bytes.Equal(chain[2].Raw, root.Raw) {
		t.Fatalf("chain = %v, want the supplied leaf, CA and root", chain)
	}
}

func TestVerifyChainExpiredCA(t *testing.T) {
	// Production CA 0a expires before some issued leaves (knowledge §21.2).
	// TrustedQSL's tqsl_expired_is_ok accepts expired certificates:
	// openssl_cert.cpp:4335-4341, commit 9b30153.
	leaf, ca, root := chainTestFixture(t)
	now := chainTestNow.AddDate(1, 1, 0)
	_, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: now})
	if !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "depth 1") || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("strict expired CA: %v", err)
	}
	chain, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: now, AllowExpiredCA: true})
	if err != nil || len(chain) != 3 || !bytes.Equal(chain[1].Raw, ca.Raw) {
		t.Fatalf("allowed expired CA: chain %v, error %v", chain, err)
	}
}

func TestVerifyChainExpiredLeaf(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	now := chainTestNow.AddDate(3, 0, 0)
	for _, tt := range []struct {
		name string
		opt  VerifyOptions
		ok   bool
	}{
		{"strict", VerifyOptions{Now: now}, false},
		{"CA only", VerifyOptions{Now: now, AllowExpiredCA: true}, false},
		{"leaf only with expired CA", VerifyOptions{Now: now, AllowExpiredLeaf: true}, false},
		{"both", VerifyOptions{Now: now, AllowExpiredLeaf: true, AllowExpiredCA: true}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, tt.opt)
			if tt.ok && err != nil || !tt.ok && !errors.Is(err, ErrChain) {
				t.Fatalf("error = %v, success = %v", err, tt.ok)
			}
		})
	}
}

func TestVerifyChainExpiredRoot(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	now := chainTestNow.AddDate(6, 0, 0)
	_, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: now, AllowExpiredLeaf: true})
	if !errors.Is(err, ErrChain) {
		t.Fatalf("expired root and CA: %v", err)
	}
	chain, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: now, AllowExpiredLeaf: true, AllowExpiredCA: true})
	if err != nil || len(chain) != 3 || !bytes.Equal(chain[2].Raw, root.Raw) {
		t.Fatalf("allowed expired root: %v, %v", chain, err)
	}
}

func TestVerifyChainNotYetValid(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	for _, now := range []time.Time{leaf.NotBefore.Add(-time.Second), ca.NotBefore.Add(-time.Second), root.NotBefore.Add(-time.Second)} {
		_, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: now, AllowExpiredLeaf: true, AllowExpiredCA: true})
		if !errors.Is(err, ErrChain) {
			t.Fatalf("not yet valid at %s: %v", now, err)
		}
	}
}

func TestVerifyChainNotYetValidCA(t *testing.T) {
	rootKey, caKey, leafKey := chainTestKey(t), chainTestKey(t), chainTestKey(t)
	root := chainTestCert(t, "root", rootKey, nil, nil, chainTestNow.AddDate(-3, 0, 0), chainTestNow.AddDate(3, 0, 0), true, 1)
	ca := chainTestCert(t, "future CA", caKey, root, rootKey, chainTestNow.AddDate(0, 1, 0), chainTestNow.AddDate(2, 0, 0), true, 2)
	leaf := chainTestCert(t, "leaf", leafKey, ca, caKey, chainTestNow.AddDate(-1, 0, 0), chainTestNow.AddDate(1, 0, 0), false, 3)
	_, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow, AllowExpiredLeaf: true, AllowExpiredCA: true})
	if !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "depth 1") || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("future CA accepted: %v", err)
	}
}

func TestVerifyChainNotYetValidRoot(t *testing.T) {
	rootKey, caKey, leafKey := chainTestKey(t), chainTestKey(t), chainTestKey(t)
	root := chainTestCert(t, "future root", rootKey, nil, nil, chainTestNow.AddDate(0, 1, 0), chainTestNow.AddDate(3, 0, 0), true, 1)
	ca := chainTestCert(t, "CA", caKey, root, rootKey, chainTestNow.AddDate(-2, 0, 0), chainTestNow.AddDate(2, 0, 0), true, 2)
	leaf := chainTestCert(t, "leaf", leafKey, ca, caKey, chainTestNow.AddDate(-1, 0, 0), chainTestNow.AddDate(1, 0, 0), false, 3)
	_, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow, AllowExpiredCA: true, AllowExpiredLeaf: true})
	if !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "depth 2") || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("future root: %v", err)
	}
}

func TestVerifyChainExpiredLeafOnly(t *testing.T) {
	rootKey, caKey, leafKey := chainTestKey(t), chainTestKey(t), chainTestKey(t)
	root := chainTestCert(t, "root", rootKey, nil, nil, chainTestNow.AddDate(-5, 0, 0), chainTestNow.AddDate(5, 0, 0), true, 1)
	ca := chainTestCert(t, "CA", caKey, root, rootKey, chainTestNow.AddDate(-4, 0, 0), chainTestNow.AddDate(4, 0, 0), true, 2)
	leaf := chainTestCert(t, "leaf", leafKey, ca, caKey, chainTestNow.AddDate(-2, 0, 0), chainTestNow.AddDate(-1, 0, 0), false, 3)
	chain, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow, AllowExpiredLeaf: true})
	if err != nil || len(chain) != 3 || !bytes.Equal(chain[0].Raw, leaf.Raw) {
		t.Fatalf("allowed expired leaf: %v, %v", chain, err)
	}
}

func TestVerifyChainRejectsMutatedCertificateFields(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	// The certificate's signed DER, rather than caller-editable decoded fields,
	// decides its validity and signing key.
	ca.NotAfter = chainTestNow.AddDate(20, 0, 0)
	ca.PublicKey = root.PublicKey
	_, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow.AddDate(1, 1, 0)})
	if !errors.Is(err, ErrChain) {
		t.Fatalf("modified decoded fields bypassed expiry: %v", err)
	}
}

func TestVerifyChainReturnsSignedCertificateFields(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	ca.NotBefore = chainTestNow.AddDate(20, 0, 0)
	chain, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow})
	if err != nil || len(chain) != 3 || chain[1].NotBefore.After(chainTestNow) {
		t.Fatalf("chain exposes mutated fields: %v, %v", chain, err)
	}
}

func TestVerifyChainValidityBoundaries(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	for _, now := range []time.Time{leaf.NotBefore, ca.NotAfter} {
		if _, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: now}); err != nil {
			t.Fatalf("inclusive boundary %s: %v", now, err)
		}
	}
}

func TestVerifyChainNonOverlappingValidity(t *testing.T) {
	rootKey, caKey, leafKey := chainTestKey(t), chainTestKey(t), chainTestKey(t)
	root := chainTestCert(t, "root", rootKey, nil, nil, chainTestNow.AddDate(-5, 0, 0), chainTestNow.AddDate(5, 0, 0), true, 1)
	ca := chainTestCert(t, "expired CA", caKey, root, rootKey, chainTestNow.AddDate(-4, 0, 0), chainTestNow.AddDate(-2, 0, 0), true, 2)
	leaf := chainTestCert(t, "leaf", leafKey, ca, caKey, chainTestNow.AddDate(-1, 0, 0), chainTestNow.AddDate(1, 0, 0), false, 3)
	chain, err := VerifyChain(leaf, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow, AllowExpiredCA: true})
	if err != nil || len(chain) != 3 || !bytes.Equal(chain[1].Raw, ca.Raw) {
		t.Fatalf("non-overlapping chain: %v, %v", chain, err)
	}
}

func TestVerifyChainAlternativePaths(t *testing.T) {
	rootKey, caKey, leafKey := chainTestKey(t), chainTestKey(t), chainTestKey(t)
	root := chainTestCert(t, "root", rootKey, nil, nil, chainTestNow.AddDate(-5, 0, 0), chainTestNow.AddDate(5, 0, 0), true, 1)
	bad := chainTestCert(t, "CA", caKey, root, rootKey, chainTestNow.AddDate(0, 1, 0), chainTestNow.AddDate(2, 0, 0), true, 2)
	good := chainTestCert(t, "CA", caKey, root, rootKey, chainTestNow.AddDate(-2, 0, 0), chainTestNow.AddDate(-1, 0, 0), true, 3)
	leaf := chainTestCert(t, "leaf", leafKey, good, caKey, chainTestNow.AddDate(-1, 0, 0), chainTestNow.AddDate(1, 0, 0), false, 4)
	chain, err := VerifyChain(leaf, []*x509.Certificate{bad, good}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow, AllowExpiredCA: true})
	if err != nil || len(chain) != 3 || !bytes.Equal(chain[1].Raw, good.Raw) {
		t.Fatalf("alternative chain = %v, error %v", chain, err)
	}
}

func TestVerifyChainCorruptedSignatureWithExpiryAllowed(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	der := bytes.Clone(leaf.Raw)
	der[len(der)-1] ^= 1
	tampered, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyChain(tampered, []*x509.Certificate{ca}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow.AddDate(3, 0, 0), AllowExpiredCA: true, AllowExpiredLeaf: true})
	if !errors.Is(err, ErrChain) {
		t.Fatalf("corrupted signature accepted: %v", err)
	}
}

func TestVerifyChainConstraintsWithExpiryAllowed(t *testing.T) {
	rootKey, issuerKey, leafKey := chainTestKey(t), chainTestKey(t), chainTestKey(t)
	root := chainTestCert(t, "root", rootKey, nil, nil, chainTestNow.AddDate(-5, 0, 0), chainTestNow.AddDate(5, 0, 0), true, 1)
	issuer := chainTestCert(t, "not a CA", issuerKey, root, rootKey, chainTestNow.AddDate(-4, 0, 0), chainTestNow.AddDate(-2, 0, 0), false, 2)
	leaf := chainTestCert(t, "leaf", leafKey, issuer, issuerKey, chainTestNow.AddDate(-1, 0, 0), chainTestNow.AddDate(1, 0, 0), false, 3)
	_, err := VerifyChain(leaf, []*x509.Certificate{issuer}, []*x509.Certificate{root}, VerifyOptions{Now: chainTestNow, AllowExpiredCA: true})
	if !errors.Is(err, ErrChain) {
		t.Fatalf("non-CA issuer accepted: %v", err)
	}
}

func TestVerifyChainDirectTrustUsesLeafExpiryPolicy(t *testing.T) {
	leaf, _, _ := chainTestFixture(t)
	now := leaf.NotAfter.Add(time.Second)
	_, err := VerifyChain(leaf, nil, []*x509.Certificate{leaf}, VerifyOptions{Now: now, AllowExpiredCA: true})
	if !errors.Is(err, ErrChain) {
		t.Fatalf("CA allowance accepted expired trusted leaf: %v", err)
	}
	chain, err := VerifyChain(leaf, nil, []*x509.Certificate{leaf}, VerifyOptions{Now: now, AllowExpiredLeaf: true})
	if err != nil || len(chain) != 1 || !bytes.Equal(chain[0].Raw, leaf.Raw) {
		t.Fatalf("leaf allowance: %v, %v", chain, err)
	}
}

func TestVerifyChainInvalidInputs(t *testing.T) {
	leaf, ca, root := chainTestFixture(t)
	other, _, _ := chainTestFixture(t)
	for _, tt := range []struct {
		name         string
		leaf         *x509.Certificate
		inter, roots []*x509.Certificate
	}{
		{"nil leaf", nil, nil, []*x509.Certificate{root}},
		{"no roots", leaf, []*x509.Certificate{ca}, nil},
		{"nil root", leaf, nil, []*x509.Certificate{nil}},
		{"nil intermediate", leaf, []*x509.Certificate{nil}, []*x509.Certificate{root}},
		{"malformed leaf", &x509.Certificate{}, nil, []*x509.Certificate{root}},
		{"malformed CA", leaf, []*x509.Certificate{{Raw: []byte{1}}}, []*x509.Certificate{root}},
		{"malformed root", leaf, nil, []*x509.Certificate{{Raw: []byte{1}}}},
		{"unknown root", leaf, []*x509.Certificate{ca}, []*x509.Certificate{other}},
		{"bad signature", other, []*x509.Certificate{ca}, []*x509.Certificate{root}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyChain(tt.leaf, tt.inter, tt.roots, VerifyOptions{Now: chainTestNow, AllowExpiredCA: true, AllowExpiredLeaf: true})
			if !errors.Is(err, ErrChain) {
				t.Fatalf("got %v, want ErrChain", err)
			}
		})
	}
}

func TestVerifyChainZeroNow(t *testing.T) {
	key := chainTestKey(t)
	now := time.Now()
	root := chainTestCert(t, "root", key, nil, nil, now.Add(-time.Hour), now.Add(time.Hour), true, 1)
	if _, err := VerifyChain(root, nil, []*x509.Certificate{root}, VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}
