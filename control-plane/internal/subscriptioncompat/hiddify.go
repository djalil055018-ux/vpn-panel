package subscriptioncompat

import (
	"encoding/base64"
	"net/url"
	"strings"
)

func isHiddify(userAgent string) bool {
	value := strings.ToLower(userAgent)
	for _, prefix := range []string{"hiddify/", "hiddifynext/", "hiddifynextx/"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// Hiddify chooses its XHTTP HTTP version before negotiating TLS. An omitted
// ALPN can select HTTP/1.1 while the browser fingerprint negotiates HTTP/2.
// Adapt only the Hiddify share-link response; keep explicit ALPN and all hosts.
func AdaptHiddifySubscription(raw []byte, format, userAgent string) ([]byte, error) {
	if !isHiddify(userAgent) || format != "XRAY_BASE64" {
		return raw, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, ErrProfile
	}
	lines := strings.Split(string(decoded), "\n")
	changed := false
	for i, line := range lines {
		if !strings.HasPrefix(line, "vless://") {
			continue
		}
		uri, err := url.Parse(line)
		if err != nil {
			return nil, ErrProfile
		}
		query, err := url.ParseQuery(uri.RawQuery)
		if err != nil {
			return nil, ErrProfile
		}
		if query.Get("type") == "xhttp" && query.Get("security") == "tls" && query.Get("alpn") == "" {
			query.Set("alpn", "h2")
			uri.RawQuery = query.Encode()
			lines[i] = uri.String()
			changed = true
		}
	}
	if !changed {
		return raw, nil
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))), nil
}
