# signingflow

[![CI](https://github.com/Signingflow/signingflow-go/actions/workflows/ci.yml/badge.svg)](https://github.com/Signingflow/signingflow-go/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Signingflow/signingflow-go/badges/coverage.json)](https://github.com/Signingflow/signingflow-go/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Go SDK for the Signingflow calls used to send a document, read envelope status, and receive webhooks.

The module talks to `https://api.signingflow.com`. Keep the API key on your server. Go 1.26 or newer is required.

```bash
go get github.com/Signingflow/signingflow-go@latest
```

The module path is `github.com/Signingflow/signingflow-go`. Install it from [GitHub](https://github.com/Signingflow/signingflow-go) until a version is tagged.

```go
client, err := signingflow.NewClient(os.Getenv("SIGNINGFLOW_API_KEY"),
    signingflow.WithWorkspace(os.Getenv("SIGNINGFLOW_WORKSPACE_ID")),
    signingflow.WithEnv(signingflow.Sandbox),
)

envelope, err := client.Envelopes.SendDocument(ctx, signingflow.SendDocumentParams{
    Title:      "NDA",
    File:       pdfBytes,
    Filename:   "contract.pdf",
    Recipients: []signingflow.Recipient{{Name: "Ada Lovelace", Email: "ada@example.com"}},
    Message:    "Please sign",
})
```

`File` is the raw bytes. A disk path is `Path`, and it is read only from `UploadRoot`. That directory must be one this process writes. The open refuses a symlink, a hard link, and a path that leaves the directory. If this operating system cannot open a path without following a symlink, the read is refused. Do not pass a path from a request field.

`WithEnv` is `sandbox` or `live`. The client always sends `X-Request-Env`. A missing environment header is treated as live by the API, so the client rejects a missing environment.

`WithBaseURL` must be `https`. The host is `api.signingflow.com` unless `WithAllowCustomBaseURL` is set. A username or password on the URL is rejected. There is no package-level API key.

The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading once an API response passes 8 MB.

## Send and read

`Envelopes.PrepareDraft` stores one PDF and creates a draft. It does not email anyone.

`Envelopes.SendDocument` stores the PDF, creates the draft, adds the recipients to the first document, and sends. `Envelopes.SendFromTemplate` starts from `templates/{id}`.

If update or send fails, the error includes `EnvelopeName` for the draft that was saved. After a timeout, the client returns the envelope only when `sent_time` is within two minutes after the call started and not more than a minute ahead of this clock. An older or far-future timestamp is an error.

`Envelopes.List` with `Directory: "needAction"` or `"waitingOthers"` reads pages of 10. `PageSize` can be from 1 to 1000. `All` walks later pages and stops after 100 follow-up pages or a repeated token.

`Envelopes.DownloadCompleted` reads the envelope first. It requests the download URL only when the state is `COMPLETED`. The download call returns `URI`, `DownloadTime`, and `ETag`. This client does not GET `URI`. Treat that URL as untrusted until your application checks the host. Do not send the API key to it.

`Envelopes.Remind` notifies people who can still sign. The call is not idempotent.

## Idempotency

Creates and sends send a UUID `idempotencyKey` in the JSON body. The same key is stored for the whole environment. A repeat returns HTTP 409 and does not return the original resource. The SDK returns `IdempotencyError` with `ResourceName` when the error includes one. It does not treat that response as success.

Pass the same idempotency key only to retry one request after a timeout. `Update` and `Remind` are not retried automatically.

## Webhooks

```go
destination, err := client.WebhookURLs.Create(ctx, signingflow.WebhookURLCreateParams{
    DisplayName:    "Envelope events",
    HTTPRequestURI: "https://example.com/webhooks/signingflow",
    Events:         []string{"DOC_ENVELOPE_COMPLETED"},
})
```

Store `destination.SigningSecret` from that response. A later `Retrieve` does not include it. Do not set `HTTPConfig`. `Auth: "NONE"` is rejected.

```go
event, err := signingflow.ConstructEvent(rawBody, signatureHeader, secret, signingflow.ConstructOptions{
    PreviousSecret:    previousSecret,
    PreviousSignature: previousSignature,
})
```

The signature is lowercase hex HMAC-SHA256 of the raw body. There is no timestamp. Compare `X-Signingflow-Signature` or `X-Webhook-Signature`. During a grace window, also pass the previous header and secret. Parse JSON only after the MAC matches. `BodySHA256` is the SHA-256 of those raw bytes. Store it and reject a delivery you have already seen. Do not hash a re-serialized body. A captured request stays valid until you record that hash or the secret rotates.

## Errors

Use `errors.As`. Every SDK error also matches `*signingflow.Error`.

| Type | When |
| --- | --- |
| `AuthenticationError` | HTTP 401 |
| `PermissionError` | HTTP 403 |
| `IdempotencyError` | HTTP 409 whose body says the key was already used |
| `RateLimitError` | HTTP 429 |
| `InvalidRequestError` | Any other HTTP 4xx, or a rejected argument |
| `APIError` | HTTP 5xx, or a body the client will not parse |
| `ConnectionError` | The API was not reached, including a timeout |
| `SignatureVerificationError` | A webhook MAC did not match |
