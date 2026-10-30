package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestRequestNodeRebootRequiresOwner(t *testing.T) {
	app := &application{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/d88503f9-aed9-489f-a599-1e4ccf637c4e/reboot", strings.NewReader(`{"confirm_name":"Finland","confirm_reboot":true}`))
	req.SetPathValue("id", "d88503f9-aed9-489f-a599-1e4ccf637c4e")
	req = req.WithContext(store.WithAdminPrincipal(req.Context(), model.AdminSession{Account: model.AdminAccount{Role: "admin"}}))
	response := httptest.NewRecorder()
	app.requestNodeReboot(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("got %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestRequestNodeRebootRequiresExplicitConfirmation(t *testing.T) {
	app := &application{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/d88503f9-aed9-489f-a599-1e4ccf637c4e/reboot", strings.NewReader(`{"confirm_name":"Finland","confirm_reboot":false}`))
	req.SetPathValue("id", "d88503f9-aed9-489f-a599-1e4ccf637c4e")
	req = req.WithContext(store.WithAdminPrincipal(req.Context(), model.AdminSession{Account: model.AdminAccount{Role: "owner"}}))
	response := httptest.NewRecorder()
	app.requestNodeReboot(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want %d", response.Code, http.StatusBadRequest)
	}
}
