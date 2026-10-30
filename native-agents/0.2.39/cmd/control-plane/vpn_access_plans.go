package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/store"
)

var accessPlanUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var accessPlanCode = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (a *application) registerAccessPlanRoutes(mux *http.ServeMux) {
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"POST /api/v1/tenants/{id}/access-plans", a.createVPNAccessPlan},
		{"GET /api/v1/tenants/{id}/access-plans", a.listVPNAccessPlans},
		{"GET /api/v1/access-plans/{id}", a.getVPNAccessPlan},
		{"PATCH /api/v1/access-plans/{id}", a.updateVPNAccessPlan},
		{"DELETE /api/v1/access-plans/{id}", a.deleteVPNAccessPlan},
		{"POST /api/v1/access-plans/{id}/services/{service_id}", a.setVPNAccessPlanService},
		{"DELETE /api/v1/access-plans/{id}/services/{service_id}", a.setVPNAccessPlanService},
		{"POST /api/v1/access-plans/{id}/clients/{client_id}", a.setVPNClientAccessPlan},
		{"DELETE /api/v1/access-plans/{id}/clients/{client_id}", a.setVPNClientAccessPlan},
	} {
		handler := route.handler
		mux.HandleFunc(route.pattern, a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			for _, key := range []string{"id", "service_id", "client_id"} {
				value := r.PathValue(key)
				if (key == "id" || value != "") && !accessPlanUUID.MatchString(value) {
					writeError(w, 400, "invalid "+key)
					return
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			handler(w, r.WithContext(ctx))
		}))
	}
}

func readAccessPlanInput(w http.ResponseWriter, r *http.Request, create bool) (store.AccessPlanUpdate, error) {
	var input store.AccessPlanUpdate
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	var raw map[string]json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return input, errors.New("invalid JSON body (maximum 16 KiB)")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return input, errors.New("body must contain one JSON object")
	}
	if len(raw) == 0 {
		return input, errors.New("at least one field is required")
	}
	for key, value := range raw {
		if string(value) == "null" {
			return input, errors.New("fields cannot be null")
		}
		switch key {
		case "name":
			var v string
			if json.Unmarshal(value, &v) != nil {
				return input, errors.New("name must be a string")
			}
			v = strings.TrimSpace(v)
			if v == "" || len(v) > 200 {
				return input, errors.New("name must contain 1 to 200 bytes")
			}
			input.Name = &v
		case "code":
			var v string
			if json.Unmarshal(value, &v) != nil {
				return input, errors.New("code must be a string")
			}
			v = strings.ToLower(strings.TrimSpace(v))
			if !accessPlanCode.MatchString(v) {
				return input, errors.New("code must contain 1 to 64 lowercase letters, digits, underscores or hyphens and start with a letter or digit")
			}
			input.Code = &v
		case "enabled":
			var v bool
			if json.Unmarshal(value, &v) != nil {
				return input, errors.New("enabled must be a boolean")
			}
			input.Enabled = &v
		default:
			return input, errors.New("unknown field")
		}
	}
	if create && (input.Name == nil || input.Code == nil) {
		return input, errors.New("name and code are required")
	}
	return input, nil
}

func writeAccessPlanError(w http.ResponseWriter, err error) {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, store.ErrPPTPCapacity):
		writeError(w, 409, "PPTP service client address capacity reached; no changes committed")
	case errors.Is(err, store.ErrTenantQuota):
		writeError(w, 409, "tenant plan limit reached")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "plan, tenant or compatible service/client not found")
	case errors.As(err, &pgErr):
		switch pgErr.Code {
		case "23505":
			writeError(w, 409, "access plan code already exists in this tenant")
		case "23503", "40001", "40P01":
			writeError(w, 409, "concurrent change prevented this operation; retry the request")
		case "23514", "22P02":
			writeError(w, 400, "invalid access plan data")
		default:
			writeError(w, 500, "access plan operation failed")
		}
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, 503, "access plan operation timed out")
	default:
		writeError(w, 500, "access plan operation failed; no partial change was committed")
	}
}

func (a *application) createVPNAccessPlan(w http.ResponseWriter, r *http.Request) {
	input, err := readAccessPlanInput(w, r, true)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	plan, err := a.store.CreateVPNAccessPlan(r.Context(), r.PathValue("id"), *input.Name, *input.Code, enabled)
	if err != nil {
		writeAccessPlanError(w, err)
		return
	}
	writeJSON(w, 201, plan)
}
func (a *application) listVPNAccessPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := a.store.ListVPNAccessPlans(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAccessPlanError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"plans": plans})
}
func (a *application) getVPNAccessPlan(w http.ResponseWriter, r *http.Request) {
	plan, err := a.store.GetVPNAccessPlan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAccessPlanError(w, err)
		return
	}
	writeJSON(w, 200, plan)
}
func (a *application) updateVPNAccessPlan(w http.ResponseWriter, r *http.Request) {
	input, err := readAccessPlanInput(w, r, false)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	result, err := a.store.UpdateVPNAccessPlan(r.Context(), r.PathValue("id"), input)
	if err != nil {
		writeAccessPlanError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (a *application) deleteVPNAccessPlan(w http.ResponseWriter, r *http.Request) {
	result, err := a.store.DeleteVPNAccessPlan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAccessPlanError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (a *application) setVPNAccessPlanService(w http.ResponseWriter, r *http.Request) {
	result, err := a.store.SetVPNAccessPlanService(r.Context(), r.PathValue("id"), r.PathValue("service_id"), r.Method == http.MethodPost)
	if err != nil {
		writeAccessPlanError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (a *application) setVPNClientAccessPlan(w http.ResponseWriter, r *http.Request) {
	result, err := a.store.SetVPNClientAccessPlan(r.Context(), r.PathValue("id"), r.PathValue("client_id"), r.Method == http.MethodPost)
	if err != nil {
		writeAccessPlanError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
