package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func (a *application) registerAdminMFARoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/admin/me/mfa", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if _, ok := store.AdminPrincipal(r.Context()); !ok {
			writeError(w, 401, "personal session required")
			return
		}
		status, err := a.store.OwnAdminMFAStatus(r.Context())
		if err != nil {
			adminAccountError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"status": status, "configured": security.MFAKeyReady(os.Getenv("ADMIN_MFA_ENCRYPTION_KEY"))})
	}))
	for _, operation := range []string{"enroll", "confirm", "disable", "recovery-codes"} {
		mux.HandleFunc("POST /api/v1/admin/me/mfa/"+operation, a.requireAdmin(func(w http.ResponseWriter, r *http.Request) { a.changeOwnAdminMFA(w, r, operation) }))
	}
}

func (a *application) changeOwnAdminMFA(w http.ResponseWriter, r *http.Request, operation string) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := store.AdminPrincipal(r.Context())
	if !ok {
		writeError(w, 401, "personal session required")
		return
	}
	var input struct {
		Password     string `json:"password"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if tenantReadJSON(w, r, &input) != nil || input.Password == "" || len(input.Password) > 1024 || len(input.Code) > 6 || len(input.RecoveryCode) > 64 {
		writeError(w, 400, "invalid MFA request")
		return
	}
	if !admitAdminLogin(principal.Account.Username) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "try again later")
		return
	}
	if !acquirePasswordWork(w) {
		return
	}
	defer func() { <-passwordWork }()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	_, hash, err := a.store.AdminLoginRecord(ctx, principal.Account.Username)
	if err != nil || !security.VerifyPassword(input.Password, store.AdminPasswordForVerification(hash)) {
		writeError(w, 401, "current password is invalid")
		return
	}
	master := os.Getenv("ADMIN_MFA_ENCRYPTION_KEY")
	var result any
	var nextToken string
	if operation == "confirm" || operation == "recovery-codes" {
		nextToken, err = security.NewToken(32)
		if err != nil {
			adminAccountError(w, err)
			return
		}
		nextToken = "vpa1_" + nextToken
	}
	switch operation {
	case "enroll":
		result, err = a.store.BeginOwnAdminMFA(ctx, hash, master)
	case "confirm":
		var codes []string
		codes, err = a.store.ConfirmOwnAdminMFA(ctx, hash, input.Code, master, security.HashToken(nextToken))
		result = map[string]any{"recovery_codes": codes}
	case "disable":
		err = a.store.DisableOwnAdminMFA(ctx, hash, input.Code, input.RecoveryCode, master)
	case "recovery-codes":
		var codes []string
		codes, err = a.store.RotateOwnAdminRecoveryCodes(ctx, hash, input.Code, input.RecoveryCode, master, security.HashToken(nextToken))
		result = map[string]any{"recovery_codes": codes}
	default:
		writeError(w, 404, "unknown MFA operation")
		return
	}
	if errors.Is(err, store.ErrAdminMFAInvalid) {
		writeError(w, 400, "second factor is invalid, expired or already used")
		return
	}
	if err != nil {
		adminAccountError(w, err)
		return
	}
	if nextToken != "" {
		nextSession, err := a.store.AuthenticateAdminSession(ctx, security.HashToken(nextToken))
		if err != nil {
			adminAccountError(w, err)
			return
		}
		response := result.(map[string]any)
		response["session_token"] = nextToken
		response["session"] = nextSession
	}
	if result == nil {
		w.WriteHeader(204)
		return
	}
	writeJSON(w, 200, result)
}
