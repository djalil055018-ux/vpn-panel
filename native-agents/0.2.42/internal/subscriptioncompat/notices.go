package subscriptioncompat

import "strings"

const noticeCredential = "00000000-0000-0000-0000-000000000000"

// RenderNotices preserves the source's display-only profiles. It cannot accept
// a real endpoint or credential. Render continues rejecting ordinary hosts with
// security=none; this separate entry point constructs every dummy host itself.
func RenderNotices(lines []string, template Options, format string) ([]byte, error) {
	if len(lines) > 30 {
		return nil, ErrProfile
	}
	hosts := make([]Host, 0, len(lines))
	for _, line := range lines {
		if !validPublicText(line, 4096) || strings.HasPrefix(strings.TrimSpace(line), "{\"f") {
			// Embedded arbitrary profiles are absent from the reviewed source.
			return nil, ErrProfile
		}
		hosts = append(hosts, Host{Name: line, Address: "0.0.0.0", Port: 1,
			Protocol: "vless", Transport: "tcp", Security: "none",
			ProtocolOptions:  Options{"encryption": "none", "flow": ""},
			TransportOptions: Options{"header": nil}})
	}
	return renderValidated(hosts, template, format, noticeCredential)
}
