package signingflow

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testID       = "11111111-1111-4111-8111-111111111111"
	testEnvelope = "envelopes/" + testID
	testTemplate = "templates/" + testID
	testStorage  = "storages/" + testID
	testHook     = "webhookUrls/" + testID
	testDelivery = "webhooks/" + testID
)

func TestConfigRejectsUnsafeValues(t *testing.T) {
	if _, err := NewClient("", WithWorkspace("ws"), WithEnv(Sandbox)); err == nil {
		t.Fatal("missing key")
	}
	if _, err := NewClient(" key ", WithWorkspace(" "), WithEnv(Sandbox)); err == nil {
		t.Fatal("missing workspace")
	}
	if _, err := NewClient("key", WithWorkspace("ws")); err == nil {
		t.Fatal("missing env")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv("prod")); err == nil {
		t.Fatal("bad env")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithBaseURL("http://api.signingflow.com")); err == nil {
		t.Fatal("http")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithBaseURL("https://user:pass@api.signingflow.com")); err == nil {
		t.Fatal("userinfo")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithBaseURL("https://example.com")); err == nil {
		t.Fatal("host")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithBaseURL("https://API.SIGNINGFLOW.COM")); err == nil {
		t.Fatal("uppercase host")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithBaseURL("not a url")); err == nil {
		t.Fatal("bad url")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithTimeout(0)); err == nil {
		t.Fatal("timeout")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithMaxNetworkRetries(-1)); err == nil {
		t.Fatal("retries")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv(Live), WithUploadHosts([]string{"com"})); err == nil {
		t.Fatal("suffix")
	}
	if _, err := NewClient("ke\ny", WithWorkspace("ws"), WithEnv(Live)); err == nil {
		t.Fatal("newline key")
	}
	if _, err := NewClient("key", WithWorkspace("ws"), WithEnv("SANDBOX"), WithBaseURL("https://example.com/"), WithAllowCustomBaseURL(), WithChannel(" ads "), WithFunnel(" ")); err != nil {
		t.Fatal(err)
	}
	if len(operations) != 15 || !operations["EnvelopeService_SendEnvelope"].Idempotent || operations["EnvelopeService_UpdateEnvelope"].Idempotent || operations["EnvelopeService_RemindEnvelopeSigners"].Idempotent {
		t.Fatalf("allowlist = %#v", operations["EnvelopeService_SendEnvelope"])
	}
}

func TestHeadersQueryAndRedaction(t *testing.T) {
	var got *http.Request
	var body []byte
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		body, _ = io.ReadAll(r.Body)
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{"name": testEnvelope, "displayName": "NDA"})
			return
		}
		writeJSON(w, 400, map[string]any{
			"code":     3,
			"message":  "bad Bearer " + r.Header.Get("Authorization") + " and df_sk_live",
			"metadata": map[string]any{"trace_code": "trace-1"},
			"details": []any{map[string]any{"fieldViolations": []any{map[string]any{
				"field": "token", "description": "see ?X-Goog-Signature=abc",
			}}}},
		})
	})
	envelope, err := client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{ReadMask: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	if envelope.DisplayName != "NDA" || got.Header.Get("Accept-Encoding") != "identity" || got.Header.Get("X-Request-Env") != "SANDBOX" || got.Header.Get("Authorization") != "Bearer df_sk_test" {
		t.Fatalf("headers env=%s auth=%s enc=%s name=%s", got.Header.Get("X-Request-Env"), got.Header.Get("Authorization"), got.Header.Get("Accept-Encoding"), envelope.DisplayName)
	}
	if !strings.Contains(got.URL.RawQuery, "readMask=documents") {
		t.Fatal(got.URL.RawQuery)
	}
	err = must(client.Envelopes.Create(context.Background(), EnvelopeCreateParams{DisplayName: "NDA", StorageID: testID})).(error)
	var invalidErr *InvalidRequestError
	if !errors.As(err, &invalidErr) || invalidErr.GRPCCode != 3 || invalidErr.TraceCode != "trace-1" || strings.Contains(invalidErr.Message, "df_sk_test") || !strings.Contains(invalidErr.Message, "df_sk_redacted") || !strings.Contains(invalidErr.FieldViolations[0].Description, "[redacted]") {
		t.Fatalf("%v grpc=%d trace=%s violations=%v", invalidErr, invalidErr.GRPCCode, invalidErr.TraceCode, invalidErr.FieldViolations)
	}
	if len(body) == 0 || !strings.Contains(string(body), "display_name") {
		t.Fatal(string(body))
	}
}

func TestStatusMappingRetriesAndIdempotency(t *testing.T) {
	statuses := map[int]func(error) bool{
		401: func(err error) bool { var target *AuthenticationError; return errors.As(err, &target) },
		403: func(err error) bool { var target *PermissionError; return errors.As(err, &target) },
		429: func(err error) bool { var target *RateLimitError; return errors.As(err, &target) },
		500: func(err error) bool { var target *APIError; return errors.As(err, &target) },
	}
	for status, match := range statuses {
		client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-Id", "req-1")
			writeJSON(w, status, map[string]any{"message": "nope"})
		})
		_, err := client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{})
		if !match(err) {
			t.Fatalf("status %d: %T %v", status, err, err)
		}
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 409, map[string]any{"message": "conflict"})
	})
	_, err := client.Envelopes.Send(context.Background(), testEnvelope, "")
	var invalidErr *InvalidRequestError
	if !errors.As(err, &invalidErr) {
		t.Fatalf("plain 409 = %T", err)
	}
	var keys []string
	var calls int
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		keys = append(keys, str(payload["idempotencyKey"]))
		if calls == 1 {
			w.Header().Set("Rate-Limit-Retry-After", time.Now().Add(-time.Hour).Format(time.RFC3339))
			writeJSON(w, 500, map[string]any{"message": "later"})
			return
		}
		writeJSON(w, 200, map[string]any{"name": testEnvelope})
	}, WithMaxNetworkRetries(1))
	if _, err := client.Envelopes.Send(context.Background(), testEnvelope, ""); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("calls=%d keys=%v", calls, keys)
	}
	calls = 0
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeJSON(w, 500, map[string]any{"message": "no"})
	}, WithMaxNetworkRetries(2))
	_, _ = client.Envelopes.Update(context.Background(), testEnvelope, map[string]any{"description": "x"})
	if calls != 1 {
		t.Fatalf("update retries = %d", calls)
	}
	_, err = client.Envelopes.Send(context.Background(), testEnvelope, "not-a-uuid")
	if err == nil || !strings.Contains(err.Error(), "UUID") {
		t.Fatal(err)
	}
	_, err = client.Envelopes.List(context.Background(), EnvelopeListParams{Directory: "needAction", ReadMask: "df_sk_test"})
	if err == nil || !strings.Contains(err.Error(), "query string") {
		t.Fatal(err)
	}
}

func TestEncodedAPIKeyIsNotSentInTheQuery(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	t.Cleanup(srv.Close)
	key := "df_sk_a/b c+"
	client, err := NewClient(key,
		WithWorkspace("ws"),
		WithEnv(Sandbox),
		WithBaseURL(srv.URL),
		WithAllowCustomBaseURL(),
		WithHTTPClient(srv.Client()),
		WithMaxNetworkRetries(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, params := range []EnvelopeListParams{
		{Directory: "needAction", ReadMask: key},
		{Directory: key},
		{Directory: "needAction", PageToken: key},
		{Directory: "needAction", ReadMask: "prefix " + key},
	} {
		_, err = client.Envelopes.List(context.Background(), params)
		if err == nil || !strings.Contains(err.Error(), "query string") {
			t.Fatal(err)
		}
	}
	if calls != 0 {
		t.Fatalf("requests sent: %d", calls)
	}
	if queryContainsSecret("readMask=documents", key) {
		t.Fatal("unrelated query was treated as the key")
	}
	if !queryContainsSecret("readMask=df_sk_a%2Fb+c%2B", key) {
		t.Fatal("encoded key was missed")
	}
	if !queryContainsSecret("readMask=%zz", key) {
		t.Fatal("malformed query was not refused")
	}
}

func TestRetryDelayIsCapped(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	originalNow := timeNow
	originalSleep := sleepFor
	timeNow = func() time.Time { return fixed }
	var slept time.Duration
	sleepFor = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() {
		timeNow = originalNow
		sleepFor = originalSleep
	})
	sleepFor = func(_ context.Context, delay time.Duration) error {
		slept = delay
		return nil
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if slept == 0 && r.Header.Get("X-Retry") == "" {
			w.Header().Set("Rate-Limit-Reset-After", fixed.Add(2*time.Hour).Format(time.RFC3339))
			writeJSON(w, 429, map[string]any{"message": "wait"})
			return
		}
		writeJSON(w, 200, map[string]any{"name": testEnvelope})
	}, WithMaxNetworkRetries(1))
	if _, err := client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{}); err != nil {
		t.Fatal(err)
	}
	if slept != time.Minute {
		t.Fatalf("slept %s", slept)
	}
}

func TestBodyLimitsGzipAndRedirect(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "8388609")
		w.WriteHeader(200)
	})
	_, err := client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.Contains(err.Error(), "8 MB") {
		t.Fatal(err)
	}
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("hijack")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n")
		chunk := bytes.Repeat([]byte("a"), 1024*1024)
		for i := 0; i < 9; i++ {
			_, _ = buf.WriteString("100000\r\n")
			_, _ = buf.Write(chunk)
			_, _ = buf.WriteString("\r\n")
			_ = buf.Flush()
		}
		_, _ = buf.WriteString("0\r\n\r\n")
		_ = buf.Flush()
	})
	_, err = client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{})
	if !errors.As(err, &apiErr) || !strings.Contains(err.Error(), "8 MB") {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write([]byte(`{"ok":true}`))
	_ = zw.Close()
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	})
	_, err = client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatal(err)
	}
	var secretHits int
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "secret") {
			secretHits++
		}
		http.Redirect(w, r, "/secret", http.StatusFound)
	})
	_, err = client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{})
	if err == nil || secretHits != 0 {
		t.Fatalf("err=%v hits=%d", err, secretHits)
	}
}

func TestUploadSendAndJail(t *testing.T) {
	var srv *httptest.Server
	var putBody []byte
	var putAuth string
	var putGen string
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "batchAddStorage"):
			writeJSON(w, 200, map[string]any{"storages": []any{map[string]any{"name": testStorage, "pre_signed_url": srv.URL + "/upload"}}})
		case r.URL.Path == "/upload":
			putAuth = r.Header.Get("Authorization")
			putGen = r.Header.Get("X-Goog-If-Generation-Match")
			putBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusPreconditionFailed)
		case strings.Contains(r.URL.Path, "batchAcknowledgeUpload"):
			writeJSON(w, 200, map[string]any{})
		case strings.Contains(r.URL.Path, "addEnvelope"):
			writeJSON(w, 200, map[string]any{"envelope": map[string]any{"name": testEnvelope, "uid": testID}})
		case strings.Contains(r.URL.RawQuery, "readMask=documents"):
			writeJSON(w, 200, map[string]any{"name": testEnvelope, "display_name": "NDA", "documents": []any{map[string]any{"uid": "doc-1", "display_name": "NDA"}}, "compliance": map[string]any{"profile": "QES"}})
		case r.Method == http.MethodPatch:
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			docs, _ := payload["documents"].([]any)
			first, _ := docs[0].(map[string]any)
			people, _ := first["participants"].([]any)
			person, _ := people[0].(map[string]any)
			if person["role"] != "SIGNER" || person["alternate_email"] != "ada@example.com" {
				t.Fatalf("patch %#v", payload)
			}
			writeJSON(w, 200, map[string]any{"name": testEnvelope})
		case strings.Contains(r.URL.Path, ":send"):
			writeJSON(w, 200, map[string]any{"name": testEnvelope})
		default:
			http.NotFound(w, r)
		}
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	client := clientFor(t, srv, WithUploadHosts([]string{"127.0.0.1"}))
	envelope, err := client.Envelopes.SendDocument(context.Background(), SendDocumentParams{
		Title: "NDA", File: []byte("%PDF"), Filename: "contract.pdf",
		Recipients: []Recipient{{Name: "Ada Lovelace", Email: "ada@example.com"}}, Message: "Please sign",
	})
	if err != nil || envelope.Name != testEnvelope || putAuth != "" || putGen != "0" || string(putBody) != "%PDF" {
		t.Fatalf("err=%v env=%s auth=%q gen=%s body=%s", err, envelope.Name, putAuth, putGen, putBody)
	}
	_, err = client.Files.Create(context.Background(), FileCreateParams{})
	if err == nil {
		t.Fatal("missing file")
	}
	_, err = client.Files.Create(context.Background(), FileCreateParams{File: []byte("x"), Path: "a.pdf", Filename: "a.pdf"})
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatal(err)
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.pdf")
	if err := os.WriteFile(outside, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "ok.pdf")
	if err := os.WriteFile(inside, []byte("OK"), 0o600); err != nil {
		t.Fatal(err)
	}
	jailed := clientFor(t, srv, WithUploadHosts([]string{"127.0.0.1"}), WithUploadRoot(root))
	if _, err := jailed.Files.Create(context.Background(), FileCreateParams{Path: "ok.pdf"}); err != nil {
		t.Fatal(err)
	}
	_, err = jailed.Files.Create(context.Background(), FileCreateParams{Path: "../secret.pdf"})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatal(err)
	}
	if err := os.Link(inside, filepath.Join(root, "hard.pdf")); err != nil {
		t.Fatal(err)
	}
	_, err = jailed.Files.Create(context.Background(), FileCreateParams{Path: "hard.pdf"})
	if err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "alias.pdf")); err != nil {
		t.Fatal(err)
	}
	_, err = jailed.Files.Create(context.Background(), FileCreateParams{Path: "alias.pdf"})
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatal(err)
	}
	big := filepath.Join(root, "big.pdf")
	file, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxUploadBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	_, err = jailed.Files.Create(context.Background(), FileCreateParams{Path: "big.pdf"})
	if err == nil || !strings.Contains(err.Error(), "25 MB") {
		t.Fatal(err)
	}
	_, err = client.Files.Create(context.Background(), FileCreateParams{Path: "ok.pdf"})
	if err == nil || !strings.Contains(err.Error(), "uploadRoot") {
		t.Fatal(err)
	}
}

func TestSendRecoveryDownloadAndPaging(t *testing.T) {
	client := templateServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, ":send") {
			return false
		}
		if strings.Contains(r.URL.Path, ":view") && !strings.Contains(r.URL.RawQuery, "readMask") {
			writeJSON(w, 200, map[string]any{"name": testEnvelope, "sent_time": time.Now().UTC().Format(time.RFC3339Nano), "progress": map[string]any{"state": "COMPLETED"}})
			return true
		}
		return false
	}, &deadlineTripper{})
	envelope, err := client.Envelopes.SendFromTemplate(context.Background(), SendFromTemplateParams{
		Template: testTemplate, Recipients: []Recipient{{Name: "Ada", Email: "ada@example.com"}},
	})
	if err != nil || envelope.Name != testEnvelope {
		t.Fatal(err)
	}
	old := templateServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, ":send") {
			return false
		}
		if strings.Contains(r.URL.Path, ":view") && !strings.Contains(r.URL.RawQuery, "readMask") {
			writeJSON(w, 200, map[string]any{"name": testEnvelope, "sentTime": "2000-01-01T00:00:00Z"})
			return true
		}
		return false
	}, &deadlineTripper{})
	_, err = old.Envelopes.SendFromTemplate(context.Background(), SendFromTemplateParams{Template: testTemplate, Recipients: []Recipient{{Name: "Ada", Email: "ada@example.com"}}})
	var base *Error
	if !errors.As(err, &base) || base.EnvelopeName != testEnvelope {
		t.Fatal(err)
	}
	future := templateServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, ":send") {
			return false
		}
		if strings.Contains(r.URL.Path, ":view") && !strings.Contains(r.URL.RawQuery, "readMask") {
			writeJSON(w, 200, map[string]any{"name": testEnvelope, "sent_time": "2099-01-01T00:00:00Z"})
			return true
		}
		return false
	}, &deadlineTripper{})
	_, err = future.Envelopes.SendFromTemplate(context.Background(), SendFromTemplateParams{Template: testTemplate, Recipients: []Recipient{{Name: "Ada", Email: "ada@example.com"}}})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatal(err)
	}
	replay := templateServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, ":send") {
			writeJSON(w, 409, map[string]any{"message": "idempotency key used", "metadata": map[string]any{"resource_url": testEnvelope}})
			return true
		}
		if strings.Contains(r.URL.Path, ":view") && !strings.Contains(r.URL.RawQuery, "readMask") {
			writeJSON(w, 200, map[string]any{"name": testEnvelope, "display_name": "From view"})
			return true
		}
		return false
	}, nil)
	envelope, err = replay.Envelopes.SendFromTemplate(context.Background(), SendFromTemplateParams{Template: testTemplate, Recipients: []Recipient{{Name: "Ada", Email: "ada@example.com"}}})
	if err != nil || envelope.DisplayName != "From view" {
		t.Fatalf("%v %#v", err, envelope)
	}
	var pages int
	client = testClient(t, func(w http.ResponseWriter, r *http.Request) {
		pages++
		token := "same"
		if pages == 1 {
			token = "same"
		}
		writeJSON(w, 200, map[string]any{"envelopes": []any{map[string]any{"name": testEnvelope}}, "nextPageToken": token})
	})
	list, err := client.Envelopes.List(context.Background(), EnvelopeListParams{Directory: "needAction", PageSize: 10, ReadMask: "name"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for item, err := range list.All(context.Background()) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, item.Name)
	}
	if len(names) != 2 {
		t.Fatalf("names=%v pages=%d", names, pages)
	}
	downloadClient := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ":download") {
			writeJSON(w, 200, map[string]any{"uri": "https://files.example/a", "download_time": "2026-01-01T00:00:00Z", "etag": "abc"})
			return
		}
		writeJSON(w, 200, map[string]any{"name": testEnvelope, "state": "COMPLETED"})
	})
	downloaded, err := downloadClient.Envelopes.DownloadCompleted(context.Background(), testEnvelope)
	if err != nil || downloaded.URI != "https://files.example/a" || downloaded.ETag != "abc" {
		t.Fatal(err, downloaded)
	}
	waiting := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"progress_status": "WAITING"})
	})
	_, err = waiting.Envelopes.DownloadCompleted(context.Background(), testEnvelope)
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatal(err)
	}
}

func TestWebhooks(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ":add"):
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			url := payload["webhookUrl"].(map[string]any)
			if url["displayName"] != "Envelope events" || url["httpRequestUri"] == "" {
				t.Fatalf("%#v", payload)
			}
			writeJSON(w, 200, map[string]any{"name": testHook, "signingSecret": "whsec_123", "events": []any{"DOC_ENVELOPE_COMPLETED"}})
		case strings.Contains(r.URL.Path, ":view") && strings.Contains(r.URL.Path, "webhookUrls"):
			writeJSON(w, 200, map[string]any{"name": testHook, "signingSecret": "whsec_123", "signing_secret": "whsec_123"})
		case strings.Contains(r.URL.Path, ":test"):
			writeJSON(w, 200, map[string]any{"name": testHook})
		case strings.Contains(r.URL.Path, ":view"):
			writeJSON(w, 200, map[string]any{"name": testDelivery, "event": "DOC_ENVELOPE_COMPLETED"})
		default:
			writeJSON(w, 200, map[string]any{"webhooks": []any{map[string]any{"name": testDelivery, "event": "DOC_ENVELOPE_COMPLETED"}}, "next_page_token": ""})
		}
	})
	created, err := client.WebhookURLs.Create(context.Background(), WebhookURLCreateParams{
		DisplayName: "Envelope events", HTTPRequestURI: "https://example.com/hooks", Events: []string{"DOC_ENVELOPE_COMPLETED"},
	})
	if err != nil || created.SigningSecret != "whsec_123" {
		t.Fatal(err, created)
	}
	viewed, err := client.WebhookURLs.Retrieve(context.Background(), testHook)
	if err != nil || viewed.SigningSecret != "" {
		t.Fatal(err, viewed)
	}
	if _, err := client.WebhookURLs.Test(context.Background(), testHook); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WebhookURLs.Create(context.Background(), WebhookURLCreateParams{DisplayName: "x", HTTPRequestURI: "https://example.com", Events: []string{"E"}, HTTPConfig: &HTTPConfig{Auth: "NONE"}}); err == nil {
		t.Fatal("none")
	}
	if _, err := client.WebhookURLs.Create(context.Background(), WebhookURLCreateParams{DisplayName: "x", HTTPRequestURI: "http://example.com", Events: []string{"E"}}); err == nil {
		t.Fatal("http")
	}
	deliveries, err := client.WebhookDeliveries.List(context.Background(), WebhookListParams{})
	if err != nil || len(deliveries.Data) != 1 {
		t.Fatal(err, deliveries)
	}
	delivery, err := client.WebhookDeliveries.Retrieve(context.Background(), testDelivery)
	if err != nil || delivery.Event != "DOC_ENVELOPE_COMPLETED" {
		t.Fatal(err)
	}
	body := []byte(`{"event":"DOC_ENVELOPE_COMPLETED"}`)
	macSum := hmac.New(sha256.New, []byte("secret"))
	_, _ = macSum.Write(body)
	signature := hex.EncodeToString(macSum.Sum(nil))
	event, err := ConstructEvent(body, strings.ToUpper(signature), "secret", ConstructOptions{})
	if err != nil || event.BodySHA256 == "" {
		t.Fatal(err)
	}
	prev := hmac.New(sha256.New, []byte("old"))
	_, _ = prev.Write(body)
	if _, err := ConstructEvent(body, "nope", "secret", ConstructOptions{PreviousSecret: "old", PreviousSignature: hex.EncodeToString(prev.Sum(nil))}); err != nil {
		t.Fatal(err)
	}
	if _, err := ConstructEvent(body, "nope", "secret", ConstructOptions{}); err == nil {
		t.Fatal("bad mac")
	}
	if _, err := ConstructEvent([]byte("[]"), signature, "secret", ConstructOptions{}); err == nil {
		t.Fatal("not object wait array is json")
	}
	if _, err := ConstructEvent([]byte("{"), signature, "secret", ConstructOptions{}); err == nil {
		t.Fatal("bad json")
	}
	if _, err := ConstructEvent(nil, signature, "secret", ConstructOptions{}); err == nil {
		t.Fatal("nil")
	}
	if SigningSecretOf(map[string]any{"signing_secret": "a"}) != "a" {
		t.Fatal("secret")
	}
}

func TestRemainingPaths(t *testing.T) {
	var sends int
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "batchAddStorage"):
			writeJSON(w, 200, map[string]any{"storages": []any{map[string]any{"name": testStorage, "preSignedUrl": srv.URL + "/upload"}}})
		case r.URL.Path == "/upload":
			if r.Header.Get("X-Goog-If-Generation-Match") == "" {
				t.Fatal("generation")
			}
			w.WriteHeader(200)
		case strings.Contains(r.URL.Path, "batchAcknowledge"):
			writeJSON(w, 200, map[string]any{})
		case strings.Contains(r.URL.Path, "addEnvelope"):
			writeJSON(w, 200, map[string]any{"uid": testID})
		case strings.Contains(r.URL.Path, ":remind"):
			writeJSON(w, 200, map[string]any{"displayName": "NDA"})
		case strings.Contains(r.URL.Path, ":download"):
			writeJSON(w, 200, map[string]any{"uri": "https://files.example/b", "downloadTime": "2026-01-01T00:00:00Z"})
		case strings.Contains(r.URL.Path, ":send"):
			sends++
			writeJSON(w, 200, map[string]any{})
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("nope"))
		}
	}))
	t.Cleanup(srv.Close)
	client := clientFor(t, srv, WithUploadHosts([]string{"127.0.0.1"}), WithChannel("ads"), WithFunnel("spring"))
	draft, err := client.Envelopes.PrepareDraft(context.Background(), PrepareDraftParams{Title: "NDA", File: []byte("%PDF"), Filename: "a.pdf", Message: "note"})
	if err != nil || draft.Name != testEnvelope || sends != 0 {
		t.Fatalf("draft %v %#v sends=%d", err, draft, sends)
	}
	reminded, err := client.Envelopes.Remind(context.Background(), testEnvelope)
	if err != nil || reminded.DisplayName != "NDA" {
		t.Fatal(err)
	}
	downloaded, err := client.Envelopes.Download(context.Background(), testEnvelope)
	if err != nil || downloaded.DownloadTime == "" {
		t.Fatal(err, downloaded)
	}
	_, err = client.Envelopes.Retrieve(context.Background(), testEnvelope, RetrieveParams{})
	if err == nil || !strings.Contains(err.Error(), "non-JSON") {
		t.Fatal(err)
	}
	if _, err := client.Envelopes.PrepareDraft(context.Background(), PrepareDraftParams{File: []byte("x")}); err == nil {
		t.Fatal("title")
	}
	if _, err := client.Files.Create(context.Background(), FileCreateParams{File: []byte("x")}); err == nil {
		t.Fatal("filename")
	}
	if _, err := client.Envelopes.List(context.Background(), EnvelopeListParams{}); err == nil {
		t.Fatal("directory")
	}
	if _, err := client.Templates.Use(context.Background(), "templates/nope", ""); err == nil {
		t.Fatal("template")
	}
	if _, err := client.WebhookURLs.Retrieve(context.Background(), "webhookUrls/nope"); err == nil {
		t.Fatal("hook")
	}
	if _, err := client.WebhookDeliveries.Retrieve(context.Background(), "webhooks/nope"); err == nil {
		t.Fatal("delivery")
	}
	if _, err := client.WebhookURLs.Create(context.Background(), WebhookURLCreateParams{DisplayName: "", HTTPRequestURI: "https://example.com", Events: []string{"E"}}); err == nil {
		t.Fatal("name")
	}
	if _, err := client.WebhookURLs.Create(context.Background(), WebhookURLCreateParams{DisplayName: "ok", HTTPRequestURI: "https://example.com", Events: []string{"E"}, HTTPConfig: &HTTPConfig{Auth: "BASIC"}}); err == nil {
		t.Fatal("config")
	}
	evil := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"storages": []any{map[string]any{"name": testStorage, "pre_signed_url": "https://evil.example/file"}}})
	})
	_, err = evil.Files.Create(context.Background(), FileCreateParams{File: []byte("x"), Filename: "a.pdf"})
	if err == nil || !strings.Contains(err.Error(), "upload host") {
		t.Fatal(err)
	}
	if resourceName(map[string]any{"metadata": map[string]any{"resource_id": testID}}) != testID {
		t.Fatal("resource id")
	}
	if _, ok := asInt("3"); !ok {
		t.Fatal("int")
	}
	if _, ok := asInt(json.Number("4")); !ok {
		t.Fatal("number")
	}
	if nextToken(map[string]any{"next_page_token": "abc"}) != "abc" {
		t.Fatal("token")
	}
	if envelopeState(Envelope{Condition: "WAITING"}) != "WAITING" {
		t.Fatal("state")
	}
	if createdEnvelope(map[string]any{"uid": testID}).Name != testEnvelope {
		t.Fatal("uid name")
	}
}

func TestHelpers(t *testing.T) {
	if _, err := fillPath("/v1/{name}:send", map[string]string{}); err == nil {
		t.Fatal("missing")
	}
	if _, err := fillPath("/v1/{name}:send", map[string]string{"name": "envelopes/bad name"}); err == nil {
		t.Fatal("invalid")
	}
	if _, err := allowedUploadURL("http://storage.googleapis.com/a", defaultUploadHosts); err == nil {
		t.Fatal("http upload")
	}
	if _, err := allowedUploadURL("https://user:pass@storage.googleapis.com/a", defaultUploadHosts); err == nil {
		t.Fatal("userinfo upload")
	}
	if _, err := allowedUploadURL("https://evil.example/a", defaultUploadHosts); err == nil {
		t.Fatal("host")
	}
	if _, err := allowedUploadURL("https://bucket.storage.googleapis.com/a", defaultUploadHosts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(redactMessage("Bearer "+strings.Repeat("a", 600)+" df_sk_live"), "df_sk_redacted") {
		t.Fatal("redact")
	}
	if _, err := pageSizeOf(1001); err == nil {
		t.Fatal("page")
	}
	if _, err := requireEnvelopeName("nope"); err == nil {
		t.Fatal("name")
	}
	if _, err := cleanRecipients([]Recipient{{Name: "", Email: "nope"}}); err == nil {
		t.Fatal("people")
	}
	if retryDelay("nope", "", time.Now()) != 0 {
		t.Fatal("delay")
	}
}

type deadlineTripper struct{}

func (deadlineTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

func (deadlineTripper) Timeout() bool   { return true }
func (deadlineTripper) Temporary() bool { return true }
func (deadlineTripper) Error() string   { return context.DeadlineExceeded.Error() }

func testClient(t *testing.T, handler http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return clientFor(t, srv, opts...)
}

func clientFor(t *testing.T, srv *httptest.Server, opts ...Option) *Client {
	t.Helper()
	base := []Option{
		WithWorkspace("ws"),
		WithEnv(Sandbox),
		WithBaseURL(srv.URL),
		WithAllowCustomBaseURL(),
		WithHTTPClient(srv.Client()),
		WithMaxNetworkRetries(0),
		WithTimeout(2 * time.Second),
	}
	client, err := NewClient("df_sk_test", append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func templateServer(t *testing.T, extra func(http.ResponseWriter, *http.Request) bool, transport http.RoundTripper) *Client {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extra != nil && extra(w, r) {
			return
		}
		switch {
		case strings.Contains(r.URL.Path, ":use"):
			writeJSON(w, 200, map[string]any{"envelope": map[string]any{"name": testEnvelope}})
		case strings.Contains(r.URL.RawQuery, "readMask"):
			writeJSON(w, 200, map[string]any{"name": testEnvelope, "documents": []any{map[string]any{"uid": "doc-1"}}, "compliance": map[string]any{"profile": "STANDARD"}})
		case r.Method == http.MethodPatch:
			writeJSON(w, 200, map[string]any{"name": testEnvelope})
		case strings.Contains(r.URL.Path, ":send"):
			writeJSON(w, 200, map[string]any{"name": testEnvelope})
		default:
			writeJSON(w, 200, map[string]any{"name": testEnvelope})
		}
	}))
	t.Cleanup(srv.Close)
	baseTransport := transport
	if baseTransport == nil {
		baseTransport = srv.Client().Transport
	} else {
		baseTransport = &swapTripper{inner: transport, next: srv.Client().Transport, once: true}
	}
	httpClient := &http.Client{Transport: baseTransport}
	return clientFor(t, srv, WithHTTPClient(httpClient), WithMaxNetworkRetries(0))
}

type swapTripper struct {
	inner http.RoundTripper
	next  http.RoundTripper
	once  bool
	used  bool
}

func (s *swapTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, ":send") && !s.used {
		s.used = true
		return s.inner.RoundTrip(req)
	}
	return s.next.RoundTrip(req)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func must(args ...any) any {
	if len(args) == 0 {
		return nil
	}
	return args[len(args)-1]
}
