package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVPNServiceSettingsRejectInvalidInput(t *testing.T) {
	app := &application{}
	serviceID := "50a85540-9f2c-4aa1-ba50-bc8c4267877d"
	tests := []struct {
		name string
		body string
	}{
		{name: "missing endpoint", body: `{"name":"New name"}`},
		{name: "missing listener", body: `{"name":"New name","public_address":"vpn.example.test","public_port":443}`},
		{name: "empty name", body: `{"name":" ","public_address":"vpn.example.test","public_port":443}`},
		{name: "multiline name", body: `{"name":"first\nsecond","public_address":"vpn.example.test","public_port":443}`},
		{name: "overlong name", body: `{"name":"` + strings.Repeat("x", 201) + `","public_address":"vpn.example.test","public_port":443}`},
		{name: "URL in address", body: `{"name":"New name","public_address":"https://vpn.example.test/path","public_port":443}`},
		{name: "address with query", body: `{"name":"New name","public_address":"vpn.example.test?next=invalid","public_port":443}`},
		{name: "invalid port", body: `{"name":"New name","public_address":"vpn.example.test","public_port":65536}`},
		{name: "invalid listen address", body: `{"name":"New name","listen":"all interfaces","port":443,"public_address":"vpn.example.test","public_port":443}`},
		{name: "invalid listener port", body: `{"name":"New name","listen":"0.0.0.0","port":0,"public_address":"vpn.example.test","public_port":443}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PATCH", "/", strings.NewReader(tt.body))
			req.SetPathValue("id", serviceID)
			rec := httptest.NewRecorder()
			app.updateVPNServicePublicEndpoint(rec, req)
			if rec.Code != 400 {
				t.Fatalf("invalid input returned %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}
