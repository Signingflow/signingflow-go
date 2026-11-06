package signingflow

import (
	"context"
	"net/url"
	"strings"
)

// HTTPConfig is rejected. Leave it nil so the destination uses HMAC.
type HTTPConfig struct {
	Auth string
}

// WebhookURL is a webhook destination. SigningSecret is returned once, from Create.
type WebhookURL struct {
	Name           string
	DisplayName    string
	HTTPRequestURI string
	Events         []string
	SigningSecret  string
}

// WebhookURLCreateParams creates a destination.
type WebhookURLCreateParams struct {
	DisplayName    string
	HTTPRequestURI string
	Events         []string
	IdempotencyKey string
	HTTPConfig     *HTTPConfig
}

// WebhookDelivery is one stored webhook delivery.
type WebhookDelivery struct {
	Name  string
	Event string
}

// WebhookListParams selects one page of deliveries.
type WebhookListParams struct {
	PageSize  int
	PageToken string
}

// WebhookURLs manages destinations.
type WebhookURLs struct {
	sender *sender
}

// Create registers an HTTPS destination. Do not set HTTPConfig.
func (w *WebhookURLs) Create(ctx context.Context, params WebhookURLCreateParams) (WebhookURL, error) {
	displayName := strings.TrimSpace(params.DisplayName)
	if len(displayName) < 1 || len(displayName) > 100 {
		return WebhookURL{}, invalid("displayName must be 1 to 100 characters.")
	}
	parsed, err := url.Parse(params.HTTPRequestURI)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
		return WebhookURL{}, invalid("httpRequestUri must be an https URL.")
	}
	if len(params.Events) == 0 {
		return WebhookURL{}, invalid("events is required.")
	}
	if params.HTTPConfig != nil && strings.EqualFold(params.HTTPConfig.Auth, "NONE") {
		return WebhookURL{}, invalid("auth NONE has no signature. Leave httpConfig empty.")
	}
	if params.HTTPConfig != nil {
		return WebhookURL{}, invalid("Leave httpConfig empty so the destination uses HMAC.")
	}
	created, err := w.sender.call(ctx, call{
		operation:      operation("WebhookUrlService_AddWebhookUrl"),
		idempotencyKey: params.IdempotencyKey,
		body: map[string]any{
			"webhookUrl": map[string]any{
				"displayName":    displayName,
				"httpRequestUri": params.HTTPRequestURI,
				"events":         params.Events,
			},
		},
	})
	if err != nil {
		return WebhookURL{}, err
	}
	return decodeWebhookURL(created, false), nil
}

// Retrieve reads a destination and omits the signing secret.
func (w *WebhookURLs) Retrieve(ctx context.Context, name string) (WebhookURL, error) {
	destination, err := requireResourceName(name, webhookNamePattern, "webhook url must look like webhookUrls/{id}.")
	if err != nil {
		return WebhookURL{}, err
	}
	viewed, err := w.sender.call(ctx, call{
		operation:  operation("WebhookUrlService_ViewWebhookUrl"),
		pathParams: map[string]string{"name": destination},
	})
	if err != nil {
		return WebhookURL{}, err
	}
	return decodeWebhookURL(viewed, true), nil
}

// Test asks the API to send a sample event. The call is not retried.
func (w *WebhookURLs) Test(ctx context.Context, name string) (WebhookURL, error) {
	destination, err := requireResourceName(name, webhookNamePattern, "webhook url must look like webhookUrls/{id}.")
	if err != nil {
		return WebhookURL{}, err
	}
	tested, err := w.sender.call(ctx, call{
		operation:  operation("WebhookUrlService_TestWebhookUrl"),
		pathParams: map[string]string{"name": destination},
		body:       map[string]any{},
	})
	if err != nil {
		return WebhookURL{}, err
	}
	return decodeWebhookURL(tested, false), nil
}

// WebhookDeliveries reads stored deliveries.
type WebhookDeliveries struct {
	sender *sender
}

// List reads one page of deliveries.
func (w *WebhookDeliveries) List(ctx context.Context, params WebhookListParams) (List[WebhookDelivery], error) {
	pageSize, err := pageSizeOf(params.PageSize)
	if err != nil {
		return List[WebhookDelivery]{}, err
	}
	load := func(ctx context.Context, token string) (List[WebhookDelivery], error) {
		return w.listPage(ctx, pageSize, token)
	}
	page, err := load(ctx, params.PageToken)
	if err != nil {
		return List[WebhookDelivery]{}, err
	}
	page.load = load
	return page, nil
}

// Retrieve reads one delivery.
func (w *WebhookDeliveries) Retrieve(ctx context.Context, name string) (WebhookDelivery, error) {
	delivery, err := requireResourceName(name, deliveryNamePattern, "webhook delivery must look like webhooks/{id}.")
	if err != nil {
		return WebhookDelivery{}, err
	}
	viewed, err := w.sender.call(ctx, call{
		operation:  operation("WebhookService_ViewWebhook"),
		pathParams: map[string]string{"name": delivery},
	})
	if err != nil {
		return WebhookDelivery{}, err
	}
	return decodeDelivery(viewed), nil
}

func (w *WebhookDeliveries) listPage(ctx context.Context, pageSize int, pageToken string) (List[WebhookDelivery], error) {
	body, err := w.sender.call(ctx, call{
		operation:  operation("WebhookService_ListWebhooks"),
		pathParams: map[string]string{"parent": "webhooks"},
		query: map[string]string{
			"pageSize":  strconvItoa(pageSize),
			"pageToken": pageToken,
		},
	})
	if err != nil {
		return List[WebhookDelivery]{}, err
	}
	record, _ := asMap(body)
	items := listItems(record, "webhooks")
	data := make([]WebhookDelivery, 0, len(items))
	for _, item := range items {
		data = append(data, decodeDelivery(item))
	}
	return List[WebhookDelivery]{Data: data, NextPageToken: nextToken(record)}, nil
}

func decodeWebhookURL(body any, dropSecret bool) WebhookURL {
	record, _ := asMap(body)
	if dropSecret {
		delete(record, "signing_secret")
		delete(record, "signingSecret")
	}
	decoded := WebhookURL{
		Name:           str(record["name"]),
		DisplayName:    firstString(record, "displayName", "display_name"),
		HTTPRequestURI: firstString(record, "httpRequestUri", "http_request_uri"),
		SigningSecret:  SigningSecretOf(record),
	}
	if events, ok := record["events"].([]any); ok {
		for _, event := range events {
			if text := str(event); text != "" {
				decoded.Events = append(decoded.Events, text)
			}
		}
	}
	return decoded
}

func decodeDelivery(body any) WebhookDelivery {
	record, _ := asMap(body)
	return WebhookDelivery{Name: str(record["name"]), Event: str(record["event"])}
}

// SigningSecretOf reads the one-time secret from a create response map.
func SigningSecretOf(body any) string {
	record, ok := asMap(body)
	if !ok {
		return ""
	}
	if value := str(record["signing_secret"]); value != "" {
		return value
	}
	return str(record["signingSecret"])
}
