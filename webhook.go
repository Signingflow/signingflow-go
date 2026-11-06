package signingflow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ConstructOptions carries the previous webhook secret during a rotation grace window.
type ConstructOptions struct {
	PreviousSecret    string
	PreviousSignature string
}

// Event is a verified webhook. BodySHA256 is the SHA-256 of the raw bytes.
// Store it and reject a delivery you have already seen.
type Event struct {
	Payload    any
	BodySHA256 string
}

// ConstructEvent checks the HMAC of the raw body, then parses JSON.
// Compare X-Signingflow-Signature or X-Webhook-Signature. Pass the previous
// header only together with the previous secret. There is no timestamp.
func ConstructEvent(payload []byte, signature, secret string, options ConstructOptions) (Event, error) {
	if payload == nil {
		return Event{}, &SignatureVerificationError{info: &info{Message: "Pass the raw request body."}}
	}
	if secret == "" {
		return Event{}, &SignatureVerificationError{info: &info{Message: "Webhook secret is required."}}
	}
	current := secret != "" && signature != "" && safeEqual(signature, mac(secret, payload))
	previous := options.PreviousSecret != "" && options.PreviousSignature != "" && safeEqual(options.PreviousSignature, mac(options.PreviousSecret, payload))
	if !current && !previous {
		return Event{}, &SignatureVerificationError{info: &info{Message: "Webhook signature did not match."}}
	}
	sum := sha256.Sum256(payload)
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return Event{}, invalid("The webhook body is not JSON.")
	}
	return Event{Payload: decoded, BodySHA256: hex.EncodeToString(sum[:])}, nil
}

func mac(secret string, body []byte) string {
	hasher := hmac.New(sha256.New, []byte(secret))
	_, _ = hasher.Write(body)
	return hex.EncodeToString(hasher.Sum(nil))
}

func safeEqual(left, right string) bool {
	a := []byte(strings.ToLower(left))
	b := []byte(strings.ToLower(right))
	if len(a) != len(b) {
		return hmac.Equal(a, a) && false
	}
	return hmac.Equal(a, b)
}
