package main

import (
	"encoding/base64"
	"mime"
	"net/http"
	"strings"
)

// INCY and other subscription clients prefer Profile-Title, then filename.
// Encode non-ASCII names so the header is safe across HTTP proxies.
func setSubscriptionBranding(header http.Header, name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "PAUK"
	}
	title := name
	for _, r := range name {
		if r < 32 || r > 126 {
			title = "base64:" + base64.StdEncoding.EncodeToString([]byte(name))
			break
		}
	}
	header.Set("Profile-Title", title)
	header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
}
