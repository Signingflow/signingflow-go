package signingflow

// Client calls the Signingflow API. Create it with NewClient. There is no package-level API key.
type Client struct {
	Files             *Files
	Templates         *Templates
	Envelopes         *Envelopes
	WebhookURLs       *WebhookURLs
	WebhookDeliveries *WebhookDeliveries
}

// NewClient checks the API key, workspace, and environment, then builds a client.
// The key is sent only as Authorization: Bearer.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	cfg, err := resolveConfig(apiKey, opts)
	if err != nil {
		return nil, err
	}
	api := newSender(cfg)
	files := &Files{sender: api, cfg: cfg}
	templates := &Templates{sender: api}
	return &Client{
		Files:             files,
		Templates:         templates,
		Envelopes:         &Envelopes{sender: api, files: files, templates: templates},
		WebhookURLs:       &WebhookURLs{sender: api},
		WebhookDeliveries: &WebhookDeliveries{sender: api},
	}, nil
}
