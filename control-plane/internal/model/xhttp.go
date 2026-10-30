package model

import "regexp"

var xhttpServiceID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// XHTTP uses a stable per-service path; no arbitrary header or proxy
// configuration is accepted from tenants or subscription parameters.
func XHTTPPath(serviceID string) (string, bool) {
	if !xhttpServiceID.MatchString(serviceID) {
		return "", false
	}
	return "/vpn/" + serviceID, true
}
