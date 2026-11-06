package signingflow

import (
	"path"
	"regexp"
	"strings"
	"time"
)

var (
	envelopeNamePattern = regexp.MustCompile(`(?i)^envelopes/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	templateNamePattern = regexp.MustCompile(`(?i)^templates/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	webhookNamePattern  = regexp.MustCompile(`(?i)^webhookUrls/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	deliveryNamePattern = regexp.MustCompile(`(?i)^webhooks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	storageIDPattern    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	emailPattern        = regexp.MustCompile(`^[^\s@]+@[^\s@]+$`)
)

// Recipient is a person who signs.
type Recipient struct {
	Name  string
	Email string
}

// Envelope is a draft or sent envelope.
type Envelope struct {
	Name           string
	UID            string
	DisplayName    string
	Description    string
	ProgressStatus string
	State          string
	Condition      string
	SentTime       string
	Documents      []map[string]any
	Compliance     map[string]any
	Progress       map[string]any
}

// Download is the JSON download record. URI is not fetched.
type Download struct {
	URI          string
	DownloadTime string
	ETag         string
}

func requireEnvelopeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !envelopeNamePattern.MatchString(name) {
		return "", invalid("envelope must look like envelopes/{id}.")
	}
	return name, nil
}

func requireTemplateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !templateNamePattern.MatchString(name) {
		return "", invalid("template must look like templates/{id}.")
	}
	return name, nil
}

func requireResourceName(name string, pattern *regexp.Regexp, message string) (string, error) {
	name = strings.TrimSpace(name)
	if !pattern.MatchString(name) {
		return "", invalid(message)
	}
	return name, nil
}

func cleanRecipients(recipients []Recipient) ([]Recipient, error) {
	people := make([]Recipient, 0, len(recipients))
	for _, person := range recipients {
		people = append(people, Recipient{Name: strings.TrimSpace(person.Name), Email: strings.TrimSpace(person.Email)})
	}
	if len(people) == 0 {
		return nil, invalid("Each recipient needs a name and an email.")
	}
	for _, person := range people {
		if person.Name == "" || !emailPattern.MatchString(person.Email) {
			return nil, invalid("Each recipient needs a name and an email.")
		}
	}
	return people, nil
}

func decodeEnvelope(body any) Envelope {
	record, ok := asMap(body)
	if !ok {
		return Envelope{}
	}
	if nested, ok := asMap(record["envelope"]); ok {
		record = nested
	}
	envelope := Envelope{
		Name:           str(record["name"]),
		UID:            str(record["uid"]),
		DisplayName:    firstString(record, "display_name", "displayName"),
		Description:    str(record["description"]),
		ProgressStatus: firstString(record, "progress_status", "progressStatus"),
		State:          str(record["state"]),
		Condition:      str(record["condition"]),
		SentTime:       firstString(record, "sent_time", "sentTime"),
		Compliance:     mapOrNil(record["compliance"]),
		Progress:       mapOrNil(record["progress"]),
	}
	if docs, ok := record["documents"].([]any); ok {
		for _, item := range docs {
			if doc, ok := asMap(item); ok {
				envelope.Documents = append(envelope.Documents, doc)
			}
		}
	}
	return envelope
}

func envelopeNameOf(body any) string {
	record, ok := asMap(body)
	if !ok {
		return ""
	}
	nested, _ := asMap(record["envelope"])
	name := ""
	if nested != nil {
		name = str(nested["name"])
	}
	if name == "" {
		name = str(record["name"])
	}
	if strings.HasPrefix(name, "envelopes/") {
		return name
	}
	uid := ""
	if nested != nil {
		uid = str(nested["uid"])
	}
	if uid == "" {
		uid = str(record["uid"])
	}
	if uid == "" {
		return ""
	}
	return "envelopes/" + uid
}

func createdEnvelope(body any) Envelope {
	envelope := decodeEnvelope(body)
	if name := envelopeNameOf(body); name != "" {
		envelope.Name = name
	} else if envelope.Name == "" && envelope.UID != "" {
		envelope.Name = "envelopes/" + envelope.UID
	}
	return envelope
}

func envelopeState(envelope Envelope) string {
	if envelope.Progress != nil {
		if state := str(envelope.Progress["state"]); state != "" {
			return state
		}
	}
	if envelope.ProgressStatus != "" {
		return envelope.ProgressStatus
	}
	if envelope.State != "" {
		return envelope.State
	}
	return envelope.Condition
}

func sentMillis(envelope Envelope) (time.Time, bool) {
	return parseRetry(envelope.SentTime)
}

func firstString(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := str(record[key]); value != "" {
			return value
		}
	}
	return ""
}

func mapOrNil(value any) map[string]any {
	record, ok := asMap(value)
	if !ok {
		return nil
	}
	return record
}

func findStorage(body any) (name, id, rawURL string, ok bool) {
	if record, isMap := asMap(body); isMap {
		if list, exists := record["storages"]; exists {
			if name, id, rawURL, ok = findStorage(list); ok {
				return name, id, rawURL, true
			}
		}
	}
	return findStorageWalk(body)
}

func findStorageWalk(body any) (string, string, string, bool) {
	switch typed := body.(type) {
	case map[string]any:
		rawURL := firstString(typed, "pre_signed_url", "preSignedUrl")
		name := str(typed["name"])
		id := path.Base(name)
		if strings.HasPrefix(name, "storages/") && storageIDPattern.MatchString(id) && rawURL != "" {
			return name, id, rawURL, true
		}
		for key, child := range typed {
			if key == "storages" {
				continue
			}
			if name, id, rawURL, ok := findStorageWalk(child); ok {
				return name, id, rawURL, ok
			}
		}
	case []any:
		for _, child := range typed {
			if name, id, rawURL, ok := findStorageWalk(child); ok {
				return name, id, rawURL, ok
			}
		}
	}
	return "", "", "", false
}
