package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessPlanInput(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `[]`, `{"name":null}`, `{"enabled":null}`, `{"enabled":"true"}`, `{"name":" "}`, `{"code":"/bad"}`, `{"tenant_id":"x"}`, `{"enabled":true} {}`, `{"name":"` + strings.Repeat("x", 17000) + `"}`} {
		r := httptest.NewRequest("PATCH", "/", strings.NewReader(body))
		w := httptest.NewRecorder()
		if _, err := readAccessPlanInput(w, r, false); err == nil {
			t.Errorf("invalid input accepted (length %d)", len(body))
		}
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":" Premium ","code":" PREMIUM-01 ","enabled":false}`))
	input, err := readAccessPlanInput(httptest.NewRecorder(), r, true)
	if err != nil || *input.Name != "Premium" || *input.Code != "premium-01" || *input.Enabled {
		t.Fatal("normalization/default handling failed")
	}
}

func TestAccessPlanRoutesRequireAdmin(t *testing.T) {
	app := &application{adminToken: "unit-test-only"}
	mux := http.NewServeMux()
	app.registerAccessPlanRoutes(mux)
	id := "00000000-0000-0000-0000-000000000001"
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/tenants/" + id + "/access-plans"}, {"POST", "/api/v1/tenants/" + id + "/access-plans"},
		{"GET", "/api/v1/access-plans/" + id}, {"PATCH", "/api/v1/access-plans/" + id}, {"DELETE", "/api/v1/access-plans/" + id},
		{"POST", "/api/v1/access-plans/" + id + "/services/" + id}, {"DELETE", "/api/v1/access-plans/" + id + "/services/" + id},
		{"POST", "/api/v1/access-plans/" + id + "/clients/" + id}, {"DELETE", "/api/v1/access-plans/" + id + "/clients/" + id},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))
		if w.Code != 401 {
			t.Errorf("%s %s = %d", route.method, route.path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/api/v1/access-plans/not-a-uuid", nil)
	r.Header.Set("Authorization", "Bearer unit-test-only")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("malformed UUID = %d", w.Code)
	}
}
