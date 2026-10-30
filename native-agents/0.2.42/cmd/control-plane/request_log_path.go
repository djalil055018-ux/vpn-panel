package main

import (
	"net/http"
	"strings"
)

// Route patterns retain operational context without writing subscription tokens,
// aliases or usernames to access logs. Unmatched paths are untrusted input too.
func safeRequestLogPath(r *http.Request) string {
	if r.Pattern == "" {
		return "<unmatched>"
	}
	if _, pattern, found := strings.Cut(r.Pattern, " "); found {
		return pattern
	}
	return r.Pattern
}
