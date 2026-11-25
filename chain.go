package gabbi

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// VerifyOptions controls certificate validity checks. Its zero value verifies
// every certificate at the current time without allowing expired certificates.
type VerifyOptions struct {
	// Now is the verification time. Zero uses the current time.
	Now time.Time
	// AllowExpiredCA permits expired intermediates and roots.
	AllowExpiredCA bool
	// AllowExpiredLeaf permits an expired leaf.
	AllowExpiredLeaf bool
}

// VerifyChain verifies leaf against the caller's roots and intermediates and
// returns a chain in leaf-to-root order. Roots are never taken from the system.
// Not-yet-valid certificates are rejected even when expiry is allowed. The
// expiry options affect validity dates only, not signatures or constraints.
// Failure details identify a candidate chain's depth when available. Other
// failures report that depth is unavailable and retain the X.509 error.
// Go's X.509 verifier rejects SHA-1-signed certificates and does not check
// revocation.
//
// Public ARRL certificate SHA-256 fingerprints of DER certificates, for
// callers choosing to pin certificates, are:
//
//   - Root E7B27BA978517C65, SKI prefix AE:00:0C:A4: 26f7c8633f1e47438129254a05190dbaed5f9a068a519caf69b32240cf95bff4
//   - Root 83FF0D4BEDE0CB43, SKI prefix C7:FC:CA:C2: 2e35f96ef18626dc901a2cf31bfb56dafadc7030d733d9b307d0db8e87c79a0f
//   - Root B6DC0911164D9C51, SKI prefix 4B:76:1F:EE: 0fb96275eaca03ef29ff509d9e545b1f3861f4468f0687becc593ed00604b2e6
//   - Production CA ending B788: 0f15c6fb0530be02e63225a8fbf4cef69ae6da88ec6a7d01e20527cf3838de47
//   - Production CA ending B789: a689d0b4edc4f1afdd2c62c501c8136e1f354c9d7ded064d91c9d62af8bdec93
//   - Production CA 0A, SKI B6:8E:C8:49:C4:0B:4A:DC:15:2B:FE:FF:CA:D2:54:94:06:2A:E8:BC: 98ea7dc6b14d8ea6a5b726830d45e2b5a5e0ed5b5db9b126e8ad132d335d9a8c
//
// Production CA 0A is an intermediate, not a root. Its expiry is 2027-06-29.
// The caller chooses which certificates to trust.
func VerifyChain(leaf *x509.Certificate, intermediates, roots []*x509.Certificate, opt VerifyOptions) ([]*x509.Certificate, error) {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	if leaf == nil {
		return nil, fmt.Errorf("%w: nil leaf", ErrChain)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: no roots supplied", ErrChain)
	}

	// Reparse signed DER to avoid trusting mutable fields on caller certificates.
	// Temporarily extend only allowed expirations in these private parsed copies.
	// The signature and all other X.509 checks still use the original signed DER.
	parse := func(cert *x509.Certificate, label string) (*x509.Certificate, error) {
		if cert == nil {
			return nil, fmt.Errorf("%w: %s is nil", ErrChain, label)
		}
		parsed, err := x509.ParseCertificate(bytes.Clone(cert.Raw))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrChain, label, err)
		}
		if parsed.NotAfter.Before(parsed.NotBefore) {
			return nil, fmt.Errorf("%w: %s: invalid validity interval", ErrChain, label)
		}
		return parsed, nil
	}

	rootPool, intermediatePool := x509.NewCertPool(), x509.NewCertPool()
	parsedRoots := make([]*x509.Certificate, 0, len(roots))
	parsedIntermediates := make([]*x509.Certificate, 0, len(intermediates))
	addForVerification := func(pool *x509.CertPool, cert *x509.Certificate, allowExpired bool) {
		copyCert := *cert
		if allowExpired && now.After(copyCert.NotAfter) && !now.Before(copyCert.NotBefore) {
			copyCert.NotAfter = now
		}
		pool.AddCert(&copyCert)
	}
	for i, cert := range roots {
		parsed, err := parse(cert, fmt.Sprintf("root %d", i))
		if err != nil {
			return nil, err
		}
		parsedRoots = append(parsedRoots, parsed)
		addForVerification(rootPool, parsed, opt.AllowExpiredCA)
	}
	for i, cert := range intermediates {
		parsed, err := parse(cert, fmt.Sprintf("intermediate %d", i))
		if err != nil {
			return nil, err
		}
		parsedIntermediates = append(parsedIntermediates, parsed)
		addForVerification(intermediatePool, parsed, opt.AllowExpiredCA)
	}
	parsedLeaf, err := parse(leaf, "leaf")
	if err != nil {
		return nil, err
	}

	verifyOptions := x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	verifyLeaf := *parsedLeaf
	if opt.AllowExpiredLeaf && now.After(verifyLeaf.NotAfter) && !now.Before(verifyLeaf.NotBefore) {
		verifyLeaf.NotAfter = now
	}
	chains, err := verifyLeaf.Verify(verifyOptions)
	if err != nil {
		// Verify checks the leaf first. An Expired error naming the leaf is
		// unambiguous even if no issuer can be verified.
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.Expired && invalid.Cert != nil && bytes.Equal(invalid.Cert.Raw, parsedLeaf.Raw) {
			if now.Before(parsedLeaf.NotBefore) {
				return nil, fmt.Errorf("%w: depth 0: certificate not yet valid: %w", ErrChain, err)
			}
			if now.After(parsedLeaf.NotAfter) && !opt.AllowExpiredLeaf {
				return nil, fmt.Errorf("%w: depth 0: certificate expired: %w", ErrChain, err)
			}
		}
		// Relax all dates only for a diagnostic path, never for acceptance.
		diagnosticLeaf := *parsedLeaf
		diagnosticLeaf.NotBefore, diagnosticLeaf.NotAfter = now, now
		diagnosticRoots, diagnosticIntermediates := x509.NewCertPool(), x509.NewCertPool()
		for _, group := range []struct {
			certs []*x509.Certificate
			pool  *x509.CertPool
		}{{parsedRoots, diagnosticRoots}, {parsedIntermediates, diagnosticIntermediates}} {
			for _, cert := range group.certs {
				copyCert := *cert
				copyCert.NotBefore, copyCert.NotAfter = now, now
				group.pool.AddCert(&copyCert)
			}
		}
		verifyOptions.Roots, verifyOptions.Intermediates = diagnosticRoots, diagnosticIntermediates
		if diagnosticChains, diagnosticErr := diagnosticLeaf.Verify(verifyOptions); diagnosticErr == nil {
			for depth, cert := range diagnosticChains[0] {
				original, parseErr := x509.ParseCertificate(cert.Raw)
				if parseErr != nil {
					return nil, fmt.Errorf("%w: depth %d: %w", ErrChain, depth, parseErr)
				}
				if now.Before(original.NotBefore) {
					return nil, fmt.Errorf("%w: candidate chain depth %d: certificate not yet valid: %w", ErrChain, depth, err)
				}
				if now.After(original.NotAfter) && (depth == 0 && !opt.AllowExpiredLeaf || depth > 0 && !opt.AllowExpiredCA) {
					return nil, fmt.Errorf("%w: candidate chain depth %d: certificate expired: %w", ErrChain, depth, err)
				}
			}
		}
		return nil, fmt.Errorf("%w: depth unavailable: verification error: %w", ErrChain, err)
	}
	chain := make([]*x509.Certificate, len(chains[0]))
	for i, cert := range chains[0] {
		chain[i], err = x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("%w: depth %d: %w", ErrChain, i, err)
		}
	}
	return chain, nil
}
