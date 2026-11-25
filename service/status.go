package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

// CertStatus is the service's status for a certificate.
type CertStatus int

// Certificate statuses returned by the service.
const (
	Unrevoked CertStatus = iota
	Superseded
	Expired
	BadSerial
)

// CertStatus looks up a certificate by its decimal serial number.
func (c *Client) CertStatus(ctx context.Context, serial *big.Int) (CertStatus, error) {
	if c == nil || c.HTTP == nil {
		return 0, ErrNoClient
	}
	if serial == nil {
		return 0, fmt.Errorf("serial: %w", ErrUnexpectedResponse)
	}
	req, err := c.request(ctx, http.MethodGet, "/lotw/crl", url.Values{"serial": {serial.String()}}, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.do(req, "certificate status")
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, ErrUnexpectedResponse
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return 0, transportError(ctx, "certificate status", err)
	}
	if len(b) > 1<<20 {
		return 0, ErrUnexpectedResponse
	}
	return parseCertStatus(b)
}

func parseCertStatus(b []byte) (CertStatus, error) {
	var result struct {
		Status []string `xml:"Status"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(b))
	if decoder.Decode(&result) != nil {
		return 0, ErrUnexpectedResponse
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, ErrUnexpectedResponse
		}
		switch t := token.(type) {
		case xml.Comment, xml.ProcInst:
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return 0, ErrUnexpectedResponse
			}
		default:
			return 0, ErrUnexpectedResponse
		}
	}
	if len(result.Status) != 1 {
		return 0, ErrUnexpectedResponse
	}
	switch result.Status[0] {
	case "Unrevoked":
		return Unrevoked, nil
	case "Superceded":
		return Superseded, nil
	case "Expired":
		return Expired, nil
	case "Bad serial":
		return BadSerial, nil
	default:
		return 0, ErrUnexpectedResponse
	}
}
