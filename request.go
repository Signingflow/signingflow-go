package signingflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const maxResponseBytes = 8 * 1024 * 1024

var idempotencyUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var timeNow = time.Now

var sleepFor = func(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type sender struct {
	cfg    *config
	client *http.Client
}

func newSender(cfg *config) *sender {
	return &sender{cfg: cfg, client: buildClient(cfg.timeout, cfg.httpClient)}
}

func buildClient(timeout time.Duration, base *http.Client) *http.Client {
	var roundTripper http.RoundTripper
	if base != nil && base.Transport != nil {
		roundTripper = base.Transport
	} else {
		roundTripper = http.DefaultTransport
	}
	if transport, ok := roundTripper.(*http.Transport); ok {
		cloned := transport.Clone()
		cloned.DisableCompression = true
		if cloned.TLSClientConfig == nil {
			cloned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		roundTripper = cloned
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     identityTransport{base: roundTripper},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type identityTransport struct {
	base http.RoundTripper
}

func (t identityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	cloned.Header.Set("Accept-Encoding", "identity")
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(cloned)
}

type call struct {
	operation      Operation
	pathParams     map[string]string
	query          map[string]string
	body           map[string]any
	idempotencyKey string
}

func (s *sender) call(ctx context.Context, input call) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var key string
	payload := input.body
	if input.operation.Idempotent {
		var err error
		key, err = keyFor(input.idempotencyKey, input.body)
		if err != nil {
			return nil, err
		}
		payload = cloneMap(input.body)
		payload["idempotencyKey"] = key
	}
	if input.operation.HTTP == http.MethodGet {
		payload = nil
	}
	path, err := fillPath(input.operation.Path, input.pathParams)
	if err != nil {
		return nil, &InvalidRequestError{info: &info{Message: err.Error(), IdempotencyKey: key}}
	}
	uri, err := resolveURL(s.cfg.baseURL, path, input.query)
	if err != nil {
		return nil, &InvalidRequestError{info: &info{Message: "invalid path", IdempotencyKey: key}}
	}
	if queryContainsSecret(uri.RawQuery, s.cfg.apiKey) {
		return nil, &InvalidRequestError{info: &info{Message: "The API key must not be sent in the query string.", IdempotencyKey: key}}
	}
	retries := 0
	if input.operation.HTTP == http.MethodGet || input.operation.Idempotent {
		retries = s.cfg.retries
	}
	var encoded []byte
	if payload != nil {
		encoded, err = json.Marshal(payload)
		if err != nil {
			return nil, invalid("invalid request body")
		}
	}
	attempt := 0
	for {
		header := s.headers(input.operation.HTTP)
		resp, err := s.do(ctx, uri.String(), input.operation.HTTP, encoded, header)
		if err != nil {
			var sdk *Error
			if errors.As(err, &sdk) {
				return nil, err
			}
			if attempt < retries && ctx.Err() == nil {
				attempt++
				continue
			}
			return nil, connectionError(err, key)
		}
		body, err := readLimited(resp)
		if err != nil {
			var sdk *Error
			if errors.As(err, &sdk) {
				return nil, err
			}
			if attempt < retries && ctx.Err() == nil {
				attempt++
				continue
			}
			return nil, connectionError(err, key)
		}
		status := resp.StatusCode
		if status >= 200 && status < 300 {
			return parseSuccess(status, resp.Header.Get("Content-Type"), body)
		}
		if attempt < retries && retryable(status) {
			attempt++
			delay := retryDelay(resp.Header.Get("Rate-Limit-Retry-After"), resp.Header.Get("Rate-Limit-Reset-After"), timeNow())
			if err := sleepFor(ctx, delay); err != nil {
				return nil, connectionError(err, key)
			}
			continue
		}
		return nil, failure(status, resp.Header, body, input.operation.Capability, key)
	}
}

func (s *sender) putBytes(ctx context.Context, uri, contentType string, data []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	retries := s.cfg.retries
	attempt := 0
	for {
		resp, err := s.do(ctx, uri, http.MethodPut, data, map[string]string{
			"Content-Type":               contentType,
			"x-goog-if-generation-match": "0",
		})
		if err != nil {
			var sdk *Error
			if errors.As(err, &sdk) {
				return err
			}
			if attempt < retries && ctx.Err() == nil {
				attempt++
				continue
			}
			return &ConnectionError{info: &info{Message: "The upload could not be reached.", StatusCode: 0}}
		}
		if _, err := readLimited(resp); err != nil {
			var sdk *Error
			if errors.As(err, &sdk) {
				return err
			}
			if attempt < retries && ctx.Err() == nil {
				attempt++
				continue
			}
			return &ConnectionError{info: &info{Message: "The upload could not be reached.", StatusCode: 0}}
		}
		status := resp.StatusCode
		if (status >= 200 && status < 300) || status == http.StatusPreconditionFailed {
			return nil
		}
		if attempt < retries && status >= 500 {
			attempt++
			continue
		}
		return &APIError{info: &info{Message: "Uploading the file to storage failed.", StatusCode: status}}
	}
}

func (s *sender) headers(method string) map[string]string {
	header := map[string]string{
		"Authorization":          "Bearer " + s.cfg.apiKey,
		"X-Request-Workspace-Id": s.cfg.workspaceID,
		"X-Request-Env":          s.cfg.wireEnv,
		"X-Request-Source":       Source,
		"Accept":                 "application/json",
		"User-Agent":             Source,
	}
	if s.cfg.channel != "" {
		header["X-Request-Channel"] = s.cfg.channel
	}
	if s.cfg.funnel != "" {
		header["X-Request-Funnel"] = s.cfg.funnel
	}
	if method != http.MethodGet {
		header["Content-Type"] = "application/json"
	}
	return header
}

func (s *sender) do(ctx context.Context, rawURL, method string, body []byte, header map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	for key, value := range header {
		req.Header.Set(key, value)
	}
	return s.client.Do(req)
}

func readLimited(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxResponseBytes {
		return nil, &APIError{info: &info{Message: "The API response is larger than 8 MB.", StatusCode: resp.StatusCode}}
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxResponseBytes {
		return nil, &APIError{info: &info{Message: "The API response is larger than 8 MB.", StatusCode: resp.StatusCode}}
	}
	return buf, nil
}

func parseSuccess(status int, contentType string, body []byte) (any, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return map[string]any{}, nil
	}
	if contentType != "" && !strings.Contains(contentType, "json") && !strings.Contains(contentType, "text/") {
		return nil, &APIError{info: &info{Message: "The API returned a non-JSON body.", StatusCode: status}}
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, &APIError{info: &info{Message: "The API returned invalid JSON.", StatusCode: status}}
	}
	return decoded, nil
}

func failure(status int, header http.Header, body []byte, capability, key string) error {
	var parsed any = string(body)
	if len(bytes.TrimSpace(body)) != 0 {
		var decoded any
		if err := json.Unmarshal(body, &decoded); err == nil {
			parsed = decoded
		}
	}
	message := serverMessage(parsed)
	if message == "" {
		if len(body) == 0 {
			message = fmt.Sprintf("Request failed with status %d.", status)
		} else {
			message = string(body)
		}
	}
	fields := &info{
		Message:         redactMessage(message),
		StatusCode:      status,
		TraceCode:       traceCode(parsed),
		RequestID:       header.Get("X-Request-Id"),
		IdempotencyKey:  key,
		Capability:      capability,
		FieldViolations: redactViolations(fieldViolations(parsed)),
		RetryAfter:      firstHeader(header, "Rate-Limit-Retry-After", "Rate-Limit-Reset-After"),
	}
	if code, ok := grpcCode(parsed); ok {
		fields.GRPCCode = code
		fields.HasGRPCCode = true
	}
	switch {
	case status == http.StatusUnauthorized:
		return &AuthenticationError{info: fields}
	case status == http.StatusForbidden:
		return &PermissionError{info: fields}
	case status == http.StatusConflict && mentionsIdempotency(parsed):
		fields.ResourceName = resourceName(parsed)
		return &IdempotencyError{info: fields}
	case status == http.StatusTooManyRequests:
		return &RateLimitError{info: fields}
	case status >= 400 && status < 500:
		return &InvalidRequestError{info: fields}
	default:
		return &APIError{info: fields}
	}
}

func firstHeader(header http.Header, names ...string) string {
	for _, name := range names {
		if value := header.Get(name); value != "" {
			return value
		}
	}
	return ""
}

func retryable(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

func connectionError(err error, key string) error {
	status := 0
	message := "The API could not be reached."
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		status = http.StatusRequestTimeout
		message = "The API timed out."
	}
	return &ConnectionError{info: &info{Message: message, StatusCode: status, IdempotencyKey: key}}
}

func keyFor(supplied string, body map[string]any) (string, error) {
	raw := strings.TrimSpace(supplied)
	if raw == "" && body != nil {
		raw = strings.TrimSpace(str(body["idempotencyKey"]))
	}
	if raw == "" {
		return newUUID(), nil
	}
	if !idempotencyUUID.MatchString(raw) {
		return "", invalid("idempotencyKey must be a UUID.")
	}
	return raw, nil
}

func newUUID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

func cloneMap(body map[string]any) map[string]any {
	out := make(map[string]any, len(body)+1)
	for key, value := range body {
		out[key] = value
	}
	return out
}
