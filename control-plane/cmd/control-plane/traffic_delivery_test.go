package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestTrafficDeliveryRejectsMalformedBody(t *testing.T) {
	valid := `{"recorded_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","snapshot":{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"clients":[]}}`
	cases := map[string]string{"empty": "", "null": "null", "missing_time": `{"snapshot":{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1}}`, "unknown": strings.Replace(valid, `"clients":[]`, `"clients":[],"secret":"must-not-echo"`, 1), "trailing": valid + ` {}`, "oversized": `{"padding":"` + strings.Repeat("x", 2<<20) + `"}`}
	cases["future"] = `{"recorded_at":"2999-01-01T00:00:00Z","snapshot":{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1}}`
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/agent/traffic", strings.NewReader(body))
			req = req.WithContext(context.WithValue(req.Context(), nodeContextKey, model.Node{ID: "00000000-0000-4000-8000-000000000001"}))
			response := httptest.NewRecorder()
			(&application{}).receiveTrafficDelivery(response, req)
			if response.Code != 400 || strings.Contains(response.Body.String(), "must-not-echo") {
				t.Fatal("invalid delivery not rejected safely")
			}
		})
	}
}
