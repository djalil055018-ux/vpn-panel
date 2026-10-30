package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubscriptionNameRequestValidation(t *testing.T) {
	app := &application{}
	for _, body := range []string{`{}`, `{"name":null}`, `{"name":"one\ntwo"}`, `{"name":"ok","uuid":"unexpected"}`} {
		req := httptest.NewRequest("PUT", "/", strings.NewReader(body))
		req.SetPathValue("id", "50a85540-9f2c-4aa1-ba50-bc8c4267877d")
		rec := httptest.NewRecorder()
		app.updateVPNServiceSubscriptionName(rec, req)
		if rec.Code != 400 {
			t.Fatalf("invalid input returned %d", rec.Code)
		}
	}
}
