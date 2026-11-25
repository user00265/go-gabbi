package service

import "errors"

// Network and response errors returned by Client.
var (
	ErrRejected           = errors.New("upload rejected")
	ErrUnexpectedResponse = errors.New("unexpected response")
	ErrBadLogin           = errors.New("bad login")
	ErrRateLimited        = errors.New("rate limited")
	ErrTransport          = errors.New("transport error")
	ErrNoClient           = errors.New("HTTP client required")
)

// RejectedError describes an upload rejected by the service.
type RejectedError struct{ Message string }

// Error returns a safe description of the rejection.
func (e *RejectedError) Error() string { return ErrRejected.Error() }

// Unwrap identifies the rejection.
func (e *RejectedError) Unwrap() error { return ErrRejected }
