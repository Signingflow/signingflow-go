package signingflow

import "errors"

// info holds the fields of every SDK error. The name is not Error, so the Error method stays in the method set.
type info struct {
	Message         string
	StatusCode      int
	GRPCCode        int
	HasGRPCCode     bool
	TraceCode       string
	RequestID       string
	IdempotencyKey  string
	Capability      string
	ResourceName    string
	EnvelopeName    string
	RetryAfter      string
	FieldViolations []FieldViolation
}

func (e *info) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Error is the common field set. errors.As matches it for every SDK error.
type Error struct{ *info }

// FieldViolation is one field error from the API, with secrets removed.
type FieldViolation struct {
	Field       string
	Description string
}

// AuthenticationError is HTTP 401.
type AuthenticationError struct{ *info }

func (e *AuthenticationError) Unwrap() error { return &Error{info: e.info} }

// PermissionError is HTTP 403.
type PermissionError struct{ *info }

func (e *PermissionError) Unwrap() error { return &Error{info: e.info} }

// IdempotencyError is HTTP 409 when the body says the key was already used.
type IdempotencyError struct{ *info }

func (e *IdempotencyError) Unwrap() error { return &Error{info: e.info} }

// RateLimitError is HTTP 429.
type RateLimitError struct{ *info }

func (e *RateLimitError) Unwrap() error { return &Error{info: e.info} }

// InvalidRequestError is any other HTTP 4xx, or a rejected caller argument.
type InvalidRequestError struct{ *info }

func (e *InvalidRequestError) Unwrap() error { return &Error{info: e.info} }

// APIError is an HTTP 5xx or a response the client will not parse.
type APIError struct{ *info }

func (e *APIError) Unwrap() error { return &Error{info: e.info} }

// ConnectionError means the API was not reached, including a timeout.
type ConnectionError struct{ *info }

func (e *ConnectionError) Unwrap() error { return &Error{info: e.info} }

// SignatureVerificationError means a webhook MAC did not match.
type SignatureVerificationError struct{ *info }

func (e *SignatureVerificationError) Unwrap() error { return &Error{info: e.info} }

func invalid(message string) *InvalidRequestError {
	return &InvalidRequestError{info: &info{Message: message}}
}

func attach(err error, envelopeName string) error {
	var base *Error
	if errors.As(err, &base) && base != nil && base.info != nil {
		base.EnvelopeName = envelopeName
	}
	return err
}
