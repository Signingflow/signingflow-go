package signingflow

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	sendWindow = 2 * time.Minute
	sendSkew   = time.Minute
)

// EnvelopeCreateParams creates a draft from a stored file.
type EnvelopeCreateParams struct {
	DisplayName    string
	Description    string
	StorageID      string
	IdempotencyKey string
}

// RetrieveParams selects the view mask.
type RetrieveParams struct {
	ReadMask string
}

// EnvelopeListParams selects one page of envelopes.
type EnvelopeListParams struct {
	Directory string
	PageSize  int
	PageToken string
	ReadMask  string
}

// PrepareDraftParams stores a PDF and creates a draft. It does not send.
type PrepareDraftParams struct {
	Title    string
	File     []byte
	Path     string
	Filename string
	Message  string
}

// SendDocumentParams stores a PDF, addresses it, and sends it.
type SendDocumentParams struct {
	Title      string
	File       []byte
	Path       string
	Filename   string
	Recipients []Recipient
	Message    string
}

// SendFromTemplateParams creates an envelope from a template and sends it.
type SendFromTemplateParams struct {
	Template   string
	Recipients []Recipient
	Message    string
}

// Envelopes creates, sends, and reads envelopes.
type Envelopes struct {
	sender    *sender
	files     *Files
	templates *Templates
}

// Create stores a draft envelope.
func (e *Envelopes) Create(ctx context.Context, params EnvelopeCreateParams) (Envelope, error) {
	title := strings.TrimSpace(params.DisplayName)
	if title == "" {
		return Envelope{}, invalid("Name the draft title.")
	}
	storageID := strings.TrimSpace(params.StorageID)
	if storageID == "" {
		return Envelope{}, invalid("storageId is required.")
	}
	created, err := e.sender.call(ctx, call{
		operation:      operation("EnvelopeService_AddEnvelope"),
		idempotencyKey: params.IdempotencyKey,
		body: map[string]any{
			"envelope": map[string]any{
				"display_name": title,
				"description":  strings.TrimSpace(params.Description),
				"documents": []any{map[string]any{
					"display_name": title,
					"attachments":  []any{map[string]any{"storage_id": storageID}},
					"supplemental": false,
				}},
			},
		},
	})
	if err != nil {
		return Envelope{}, err
	}
	return createdEnvelope(created), nil
}

// Retrieve reads one envelope.
func (e *Envelopes) Retrieve(ctx context.Context, name string, params RetrieveParams) (Envelope, error) {
	envelope, err := requireEnvelopeName(name)
	if err != nil {
		return Envelope{}, err
	}
	viewed, err := e.sender.call(ctx, call{
		operation:  operation("EnvelopeService_ViewEnvelope"),
		pathParams: map[string]string{"name": envelope},
		query:      map[string]string{"readMask": params.ReadMask},
	})
	if err != nil {
		return Envelope{}, err
	}
	decoded := decodeEnvelope(viewed)
	if decoded.Name == "" {
		decoded.Name = envelope
	}
	return decoded, nil
}

// Update patches an envelope. The call is not retried.
func (e *Envelopes) Update(ctx context.Context, name string, body map[string]any) (Envelope, error) {
	envelope, err := requireEnvelopeName(name)
	if err != nil {
		return Envelope{}, err
	}
	payload := cloneMap(body)
	if str(payload["name"]) == "" {
		payload["name"] = envelope
	}
	updated, err := e.sender.call(ctx, call{
		operation:  operation("EnvelopeService_UpdateEnvelope"),
		pathParams: map[string]string{"name": envelope},
		body:       payload,
	})
	if err != nil {
		return Envelope{}, err
	}
	return decodeEnvelope(updated), nil
}

// Send emails the envelope.
func (e *Envelopes) Send(ctx context.Context, name string, idempotencyKey string) (Envelope, error) {
	envelope, err := requireEnvelopeName(name)
	if err != nil {
		return Envelope{}, err
	}
	sent, err := e.sender.call(ctx, call{
		operation:      operation("EnvelopeService_SendEnvelope"),
		pathParams:     map[string]string{"name": envelope},
		idempotencyKey: idempotencyKey,
		body:           map[string]any{},
	})
	if err != nil {
		return Envelope{}, err
	}
	decoded := decodeEnvelope(sent)
	if decoded.Name == "" {
		decoded.Name = envelope
	}
	return decoded, nil
}

// List reads one page. Directory values such as needAction stay in API form.
func (e *Envelopes) List(ctx context.Context, params EnvelopeListParams) (List[Envelope], error) {
	directory := strings.TrimSpace(params.Directory)
	if directory == "" {
		return List[Envelope]{}, invalid("directory is required.")
	}
	pageSize, err := pageSizeOf(params.PageSize)
	if err != nil {
		return List[Envelope]{}, err
	}
	load := func(ctx context.Context, token string) (List[Envelope], error) {
		return e.listPage(ctx, directory, pageSize, token, params.ReadMask)
	}
	page, err := load(ctx, params.PageToken)
	if err != nil {
		return List[Envelope]{}, err
	}
	page.load = load
	return page, nil
}

// Remind notifies people who can still sign. The call is not retried.
func (e *Envelopes) Remind(ctx context.Context, name string) (Envelope, error) {
	envelope, err := requireEnvelopeName(name)
	if err != nil {
		return Envelope{}, err
	}
	reminded, err := e.sender.call(ctx, call{
		operation:  operation("EnvelopeService_RemindEnvelopeSigners"),
		pathParams: map[string]string{"name": envelope},
		body:       map[string]any{},
	})
	if err != nil {
		return Envelope{}, err
	}
	decoded := decodeEnvelope(reminded)
	if decoded.Name == "" {
		decoded.Name = envelope
	}
	return decoded, nil
}

// Download returns the download record and does not GET URI.
func (e *Envelopes) Download(ctx context.Context, name string) (Download, error) {
	envelope, err := requireEnvelopeName(name)
	if err != nil {
		return Download{}, err
	}
	downloaded, err := e.sender.call(ctx, call{
		operation:  operation("EnvelopeService_DownloadEnvelope"),
		pathParams: map[string]string{"name": envelope},
	})
	if err != nil {
		return Download{}, err
	}
	record, ok := asMap(downloaded)
	if !ok {
		record = map[string]any{}
	}
	return Download{
		URI:          str(record["uri"]),
		DownloadTime: firstString(record, "download_time", "downloadTime"),
		ETag:         str(record["etag"]),
	}, nil
}

// PrepareDraft stores one PDF and creates a draft. It does not email anyone.
func (e *Envelopes) PrepareDraft(ctx context.Context, params PrepareDraftParams) (Envelope, error) {
	title := strings.TrimSpace(params.Title)
	if title == "" {
		return Envelope{}, invalid("Name the PDF and the draft title.")
	}
	stored, err := e.files.Create(ctx, FileCreateParams{File: params.File, Path: params.Path, Filename: params.Filename})
	if err != nil {
		return Envelope{}, err
	}
	return e.Create(ctx, EnvelopeCreateParams{DisplayName: title, Description: params.Message, StorageID: stored.ID})
}

// SendDocument stores the PDF, addresses the first document, and sends.
func (e *Envelopes) SendDocument(ctx context.Context, params SendDocumentParams) (Envelope, error) {
	title := strings.TrimSpace(params.Title)
	if title == "" {
		return Envelope{}, invalid("Name the PDF, the title, and the recipients.")
	}
	people, err := cleanRecipients(params.Recipients)
	if err != nil {
		return Envelope{}, err
	}
	stored, err := e.files.Create(ctx, FileCreateParams{File: params.File, Path: params.Path, Filename: params.Filename})
	if err != nil {
		return Envelope{}, err
	}
	created, err := e.Create(ctx, EnvelopeCreateParams{DisplayName: title, Description: params.Message, StorageID: stored.ID})
	if err != nil {
		return Envelope{}, err
	}
	return e.finishSend(ctx, created, people, params.Message, title)
}

// SendFromTemplate starts from templates/{id}.
func (e *Envelopes) SendFromTemplate(ctx context.Context, params SendFromTemplateParams) (Envelope, error) {
	template, err := requireTemplateName(params.Template)
	if err != nil {
		return Envelope{}, err
	}
	people, err := cleanRecipients(params.Recipients)
	if err != nil {
		return Envelope{}, err
	}
	created, err := e.templates.Use(ctx, template, "")
	if err != nil {
		return Envelope{}, err
	}
	return e.finishSend(ctx, created, people, params.Message, template)
}

// DownloadCompleted requests the download URL only when the state is COMPLETED.
func (e *Envelopes) DownloadCompleted(ctx context.Context, name string) (Download, error) {
	envelope, err := requireEnvelopeName(name)
	if err != nil {
		return Download{}, err
	}
	viewed, err := e.Retrieve(ctx, envelope, RetrieveParams{})
	if err != nil {
		return Download{}, err
	}
	if strings.ToUpper(strings.TrimSpace(envelopeState(viewed))) != "COMPLETED" {
		err := invalid("The signed file is not ready.")
		err.EnvelopeName = envelope
		return Download{}, err
	}
	return e.Download(ctx, envelope)
}

func (e *Envelopes) listPage(ctx context.Context, directory string, pageSize int, pageToken, readMask string) (List[Envelope], error) {
	body, err := e.sender.call(ctx, call{
		operation:  operation("EnvelopeService_ListEnvelopes"),
		pathParams: map[string]string{"parent": "envelopes"},
		query: map[string]string{
			"directory": directory,
			"pageSize":  strconvItoa(pageSize),
			"pageToken": pageToken,
			"readMask":  readMask,
		},
	})
	if err != nil {
		return List[Envelope]{}, err
	}
	record, _ := asMap(body)
	items := listItems(record, "envelopes")
	data := make([]Envelope, 0, len(items))
	for _, item := range items {
		data = append(data, decodeEnvelope(item))
	}
	return List[Envelope]{Data: data, NextPageToken: nextToken(record)}, nil
}

func (e *Envelopes) finishSend(ctx context.Context, created Envelope, people []Recipient, message, label string) (Envelope, error) {
	name := created.Name
	if _, err := requireEnvelopeName(name); err != nil {
		return Envelope{}, &APIError{info: &info{Message: label + " was saved without an envelope name."}}
	}
	viewed, err := e.Retrieve(ctx, name, RetrieveParams{ReadMask: "documents,compliance"})
	if err != nil {
		return Envelope{}, attach(err, name)
	}
	patched := withRecipients(viewed, people, message)
	if patched == nil {
		err := invalid("The draft has no document to address.")
		err.EnvelopeName = name
		return Envelope{}, err
	}
	if _, err := e.Update(ctx, name, patched); err != nil {
		return Envelope{}, attach(err, name)
	}
	return e.sendOrView(ctx, name)
}

func (e *Envelopes) sendOrView(ctx context.Context, name string) (Envelope, error) {
	started := timeNow()
	sent, err := e.Send(ctx, name, "")
	if err == nil {
		return sent, nil
	}
	var idem *IdempotencyError
	if errors.As(err, &idem) && idem.ResourceName == name {
		viewed, viewErr := e.Retrieve(ctx, name, RetrieveParams{})
		if viewErr == nil {
			return viewed, nil
		}
		return Envelope{}, attach(err, name)
	}
	var conn *ConnectionError
	if errors.As(err, &conn) {
		viewed, viewErr := e.Retrieve(ctx, name, RetrieveParams{})
		if viewErr == nil {
			if when, ok := sentMillis(viewed); ok && sentDuring(when, started, timeNow()) {
				return viewed, nil
			}
		}
	}
	return Envelope{}, attach(err, name)
}

func withRecipients(envelope Envelope, people []Recipient, message string) map[string]any {
	var refs []map[string]string
	for _, item := range envelope.Documents {
		uid := firstString(item, "uid", "id")
		if uid == "" {
			continue
		}
		refs = append(refs, map[string]string{"uid": uid, "display_name": firstString(item, "display_name", "displayName")})
	}
	if len(refs) == 0 {
		return nil
	}
	participants := make([]any, 0, len(people))
	for index, person := range people {
		participants = append(participants, map[string]any{
			"uid":                 newUUID(),
			"display_name":        person.Name,
			"alternate_email":     person.Email,
			"role":                "SIGNER",
			"type":                "PERSONAL",
			"action_order_type":   "SERIAL",
			"action_order_number": index + 1,
		})
	}
	profile := "STANDARD"
	if envelope.Compliance != nil && str(envelope.Compliance["profile"]) != "" {
		profile = str(envelope.Compliance["profile"])
	}
	description := strings.TrimSpace(message)
	if description == "" {
		description = envelope.Description
	}
	documents := make([]any, 0, len(refs))
	for index, document := range refs {
		item := map[string]any{"uid": document["uid"], "display_name": document["display_name"]}
		if index == 0 {
			item["participants"] = participants
		}
		documents = append(documents, item)
	}
	return map[string]any{
		"name":         envelope.Name,
		"display_name": envelope.DisplayName,
		"description":  description,
		"compliance":   map[string]any{"profile": profile},
		"documents":    documents,
	}
}

func sentDuring(sent, started, now time.Time) bool {
	return !sent.Before(started) && !sent.After(started.Add(sendWindow)) && !sent.After(now.Add(sendSkew))
}

func strconvItoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for value > 0 {
		i--
		digits[i] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[i:])
}
