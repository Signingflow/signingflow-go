package signingflow

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	segmentPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	tokenPattern   = regexp.MustCompile(`\{([^}]+)\}`)
)

func fillPath(template string, params map[string]string) (string, error) {
	var failure error
	filled := tokenPattern.ReplaceAllStringFunc(template, func(match string) string {
		if failure != nil {
			return ""
		}
		token := match[1 : len(match)-1]
		name := token
		if cut, _, ok := strings.Cut(token, "="); ok {
			name = cut
		}
		short := name
		if i := strings.LastIndex(name, "."); i >= 0 {
			short = name[i+1:]
		}
		value := params[name]
		if value == "" {
			value = params[short]
		}
		if value == "" && (short == "name" || strings.HasPrefix(short, "name_")) {
			value = params["name"]
		}
		if value == "" {
			failure = fmt.Errorf("missing path param %s", short)
			return ""
		}
		parts := strings.Split(value, "/")
		if len(parts) == 0 {
			failure = fmt.Errorf("invalid path param %s", short)
			return ""
		}
		escaped := make([]string, 0, len(parts))
		for _, part := range parts {
			if !segmentPattern.MatchString(part) {
				failure = fmt.Errorf("invalid path param %s", short)
				return ""
			}
			escaped = append(escaped, url.PathEscape(part))
		}
		return strings.Join(escaped, "/")
	})
	if failure != nil {
		return "", failure
	}
	return filled, nil
}

func resolveURL(baseURL, path string, query map[string]string) (*url.URL, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	ref, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return nil, fmt.Errorf("invalid path")
	}
	values := resolved.Query()
	for key, value := range query {
		if value != "" {
			values.Set(key, value)
		}
	}
	resolved.RawQuery = values.Encode()
	return resolved, nil
}

// queryContainsSecret reports whether the API key would be visible in an encoded query.
// Values.Encode percent-encodes reserved characters, so a raw substring check is not enough.
func queryContainsSecret(rawQuery, secret string) bool {
	if secret == "" || rawQuery == "" {
		return false
	}
	if strings.Contains(rawQuery, secret) || strings.Contains(rawQuery, url.QueryEscape(secret)) {
		return true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return true
	}
	for _, list := range values {
		for _, item := range list {
			if strings.Contains(item, secret) {
				return true
			}
		}
	}
	return false
}

func allowedUploadURL(raw string, hosts []string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return nil, fmt.Errorf("upload url rejected")
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("upload url must be https")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("upload url rejected")
	}
	host := strings.ToLower(parsed.Hostname())
	for _, item := range hosts {
		if host == item || strings.HasSuffix(host, "."+item) {
			return parsed, nil
		}
	}
	return nil, fmt.Errorf("upload host rejected")
}

func retryDelay(retryAfter, resetAfter string, now time.Time) time.Duration {
	when, ok := parseRetry(retryAfter)
	if !ok {
		when, ok = parseRetry(resetAfter)
	}
	if !ok {
		return 0
	}
	delay := when.Sub(now)
	if delay < 0 {
		return 0
	}
	if delay > 60*time.Second {
		return 60 * time.Second
	}
	return delay
}

func parseRetry(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, value)
	}
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
