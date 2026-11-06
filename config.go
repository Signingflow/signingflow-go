package signingflow

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// Sandbox is the test environment. The client sends X-Request-Env: SANDBOX.
	Sandbox = "sandbox"
	// Live is the production environment. The client sends X-Request-Env: LIVE.
	Live = "live"

	officialHost   = "api.signingflow.com"
	defaultBaseURL = "https://api.signingflow.com"
	defaultTimeout = 30 * time.Second
	defaultRetries = 2
)

var defaultUploadHosts = []string{"storage.googleapis.com"}

// Option configures a Client. The API key is an argument to NewClient, not an option and not a package variable.
type Option func(*config)

// WithWorkspace sets the workspace id sent on every request.
func WithWorkspace(id string) Option {
	return func(cfg *config) { cfg.workspaceID = id }
}

// WithEnv sets sandbox or live. The value is required.
func WithEnv(env string) Option {
	return func(cfg *config) { cfg.env = env }
}

// WithBaseURL overrides the API origin. The host must be api.signingflow.com unless WithAllowCustomBaseURL is set.
func WithBaseURL(baseURL string) Option {
	return func(cfg *config) { cfg.baseURL = baseURL }
}

// WithAllowCustomBaseURL permits a non-official HTTPS host. The API key is sent to that host.
func WithAllowCustomBaseURL() Option {
	return func(cfg *config) { cfg.allowCustom = true }
}

// WithTimeout sets the whole-request timeout. The default is 30 seconds.
func WithTimeout(timeout time.Duration) Option {
	return func(cfg *config) { cfg.timeout = timeout; cfg.timeoutSet = true }
}

// WithMaxNetworkRetries sets retries for GET and idempotent calls. The default is 2.
func WithMaxNetworkRetries(n int) Option {
	return func(cfg *config) { cfg.retries = n; cfg.retriesSet = true }
}

// WithChannel sets the optional X-Request-Channel header.
func WithChannel(channel string) Option {
	return func(cfg *config) { cfg.channel = channel }
}

// WithFunnel sets the optional X-Request-Funnel header.
func WithFunnel(funnel string) Option {
	return func(cfg *config) { cfg.funnel = funnel }
}

// WithUploadHosts replaces the storage host allowlist.
func WithUploadHosts(hosts []string) Option {
	return func(cfg *config) { cfg.uploadHosts = hosts; cfg.uploadHostsSet = true }
}

// WithUploadRoot sets the only directory a Path argument may be read from.
func WithUploadRoot(root string) Option {
	return func(cfg *config) { cfg.uploadRoot = root }
}

// WithHTTPClient supplies a client whose transport is copied. Redirects stay off and gzip stays off.
func WithHTTPClient(client *http.Client) Option {
	return func(cfg *config) { cfg.httpClient = client }
}

type config struct {
	apiKey         string
	workspaceID    string
	env            string
	wireEnv        string
	baseURL        string
	allowCustom    bool
	timeout        time.Duration
	timeoutSet     bool
	retries        int
	retriesSet     bool
	channel        string
	funnel         string
	uploadHosts    []string
	uploadHostsSet bool
	uploadRoot     string
	httpClient     *http.Client
}

func resolveConfig(apiKey string, opts []Option) (*config, error) {
	cfg := &config{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	cfg.apiKey = strings.TrimSpace(apiKey)
	if cfg.apiKey == "" {
		return nil, &Error{info: &info{Message: "API key is required."}}
	}
	cfg.workspaceID = strings.TrimSpace(cfg.workspaceID)
	if cfg.workspaceID == "" {
		return nil, &Error{info: &info{Message: "workspaceId is required."}}
	}
	wire, err := normalizeEnv(cfg.env)
	if err != nil {
		return nil, err
	}
	cfg.wireEnv = wire
	base := strings.TrimSpace(cfg.baseURL)
	if base == "" {
		base = defaultBaseURL
	}
	base = strings.TrimRight(base, "/")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return nil, &Error{info: &info{Message: "baseUrl must be an absolute URL."}}
	}
	if parsed.Scheme != "https" {
		return nil, &Error{info: &info{Message: "baseUrl must be https."}}
	}
	if parsed.User != nil {
		return nil, &Error{info: &info{Message: "baseUrl must not include a username or password."}}
	}
	if parsed.Hostname() != officialHost && !cfg.allowCustom {
		return nil, &Error{info: &info{Message: "baseUrl host must be api.signingflow.com, or set allowCustomBaseUrl."}}
	}
	cfg.baseURL = base
	if !cfg.timeoutSet {
		cfg.timeout = defaultTimeout
	}
	if cfg.timeout <= 0 {
		return nil, &Error{info: &info{Message: "timeout must be positive."}}
	}
	if !cfg.retriesSet {
		cfg.retries = defaultRetries
	}
	if cfg.retries < 0 {
		return nil, &Error{info: &info{Message: "maxNetworkRetries must be a whole number of zero or more."}}
	}
	hosts, err := uploadHostsOf(cfg.uploadHosts, cfg.uploadHostsSet)
	if err != nil {
		return nil, err
	}
	cfg.uploadHosts = hosts
	cfg.channel = blank(cfg.channel)
	cfg.funnel = blank(cfg.funnel)
	cfg.uploadRoot = blank(cfg.uploadRoot)
	if badHeader(cfg.apiKey) || badHeader(cfg.workspaceID) || badHeader(cfg.channel) || badHeader(cfg.funnel) {
		return nil, invalid("invalid header value")
	}
	return cfg, nil
}

func normalizeEnv(env string) (string, error) {
	switch env {
	case Sandbox, "SANDBOX":
		return "SANDBOX", nil
	case Live, "LIVE":
		return "LIVE", nil
	default:
		return "", &Error{info: &info{Message: "env must be sandbox or live."}}
	}
}

func uploadHostsOf(hosts []string, set bool) ([]string, error) {
	if !set {
		hosts = defaultUploadHosts
	}
	list := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		dots := strings.Count(host, ".")
		if dots < 2 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
			return nil, &Error{info: &info{Message: "Each uploadHosts entry must be a specific host, not a public suffix."}}
		}
		list = append(list, host)
	}
	return list, nil
}

func blank(value string) string {
	return strings.TrimSpace(value)
}

func badHeader(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}
