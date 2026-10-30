package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubscriptionRequestLogsContainOnlyRoutePatterns(t *testing.T) {
	var out bytes.Buffer
	original := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(original)
	mux := http.NewServeMux()
	for _, pattern := range []string{"GET /sub/{token}", "GET /api/v1/public/imported-subscriptions/{alias}/{format}",
		"GET " + importedPagePrefix + "/api/sub/{alias}/info", "GET /api/v1/tenant/bot/users/by-username/{username}", "GET /healthz"} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	}
	handler := loggingMiddleware(mux)
	for _, path := range []string{"/sub/private-signed-token", "/api/v1/public/imported-subscriptions/private-alias/json", importedPagePrefix + "/api/sub/private-alias/info",
		"/api/v1/tenant/bot/users/by-username/private-username", "/unmatched/private-token", "/healthz?token=private-query"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	if strings.Contains(out.String(), "private-") || !strings.Contains(out.String(), "/sub/{token}") || !strings.Contains(out.String(), "<unmatched>") || !strings.Contains(out.String(), "/healthz") {
		t.Fatal("request path log disclosure")
	}
}
