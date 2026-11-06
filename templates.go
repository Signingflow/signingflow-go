package signingflow

import "context"

// Templates starts an envelope from a template.
type Templates struct {
	sender *sender
}

// Use creates an envelope from templates/{id}.
func (t *Templates) Use(ctx context.Context, name string, idempotencyKey string) (Envelope, error) {
	template, err := requireTemplateName(name)
	if err != nil {
		return Envelope{}, err
	}
	used, err := t.sender.call(ctx, call{
		operation:      operation("TemplateService_UseTemplate"),
		pathParams:     map[string]string{"name": template},
		idempotencyKey: idempotencyKey,
		body:           map[string]any{},
	})
	if err != nil {
		return Envelope{}, err
	}
	return createdEnvelope(used), nil
}
