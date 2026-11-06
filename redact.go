package signingflow

import "regexp"

var (
	secretKey   = regexp.MustCompile(`df_sk_[A-Za-z0-9_-]+`)
	bearerToken = regexp.MustCompile(`(?i)Bearer\s+\S+`)
	signedQuery = regexp.MustCompile(`(?i)([?&](?:X-Goog-Signature|Signature|sig|token)=)[^&\s"]+`)
)

func redact(value string) string {
	value = secretKey.ReplaceAllString(value, "df_sk_redacted")
	value = bearerToken.ReplaceAllString(value, "Bearer [redacted]")
	return signedQuery.ReplaceAllString(value, "$1[redacted]")
}

func redactMessage(value string) string {
	cleaned := redact(value)
	if len(cleaned) <= 500 {
		return cleaned
	}
	return cleaned[:500] + "…"
}

func redactViolations(list []FieldViolation) []FieldViolation {
	if len(list) == 0 {
		return nil
	}
	out := make([]FieldViolation, len(list))
	for i, item := range list {
		out[i] = FieldViolation{Field: redactMessage(item.Field), Description: redactMessage(item.Description)}
	}
	return out
}
