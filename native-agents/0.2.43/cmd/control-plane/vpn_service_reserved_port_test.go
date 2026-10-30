package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateVPNServiceRejectsManagementPortBeforeDatabase(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/node/vpn-services", strings.NewReader(`{"name":"test","protocol":"vless","port":10085,"transport":"tcp","security":"reality"}`))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("id", "node")
	w := httptest.NewRecorder()
	(&application{}).createVPNService(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reserved port status=%d", w.Code)
	}
}
