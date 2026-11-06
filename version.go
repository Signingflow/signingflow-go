package signingflow

const (
	// Version is the SDK version sent in X-Request-Source.
	Version = "0.1.0"
	// Source is the X-Request-Source and User-Agent value.
	Source = "signingflow-go/" + Version
)
