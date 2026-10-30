package main

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

var adminSessionPattern = regexp.MustCompile(`^vpa1_[A-Za-z0-9_-]{43}$`)
var passwordWork = make(chan struct{}, 2)

type loginWindow struct {
	start time.Time
	count int
}

var loginThrottle = struct {
	sync.Mutex
	windows map[string]loginWindow
}{windows: map[string]loginWindow{}}

func admitAdminLogin(username string) bool {
	loginThrottle.Lock()
	defer loginThrottle.Unlock()
	now := time.Now()
	key := security.HashToken(strings.ToLower(username))
	if len(loginThrottle.windows) >= 4096 {
		for key, value := range loginThrottle.windows {
			if now.Sub(value.start) >= time.Minute {
				delete(loginThrottle.windows, key)
			}
		}
	}
	value, exists := loginThrottle.windows[key]
	if !exists && len(loginThrottle.windows) >= 4096 {
		return false
	}
	if now.Sub(value.start) >= time.Minute {
		value = loginWindow{start: now}
	}
	if value.count >= 10 {
		return false
	}
	value.count++
	loginThrottle.windows[key] = value
	return true
}
func acquirePasswordWork(w http.ResponseWriter) bool {
	select {
	case passwordWork <- struct{}{}:
		return true
	default:
		w.Header().Set("Retry-After", "2")
		writeError(w, 503, "authentication busy; retry shortly")
		return false
	}
}

func (a *application) requireRoot(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !security.EqualSecret(bearerToken(r), a.adminToken) || bearerToken(r) == "" {
			writeError(w, 401, "invalid administrative credential")
			return
		}
		next(w, r)
	}
}
func adminOwnerRequired(w http.ResponseWriter, r *http.Request) bool {
	if s, ok := store.AdminPrincipal(r.Context()); ok && s.Account.Role != "owner" {
		writeError(w, 403, "owner role required")
		return false
	}
	return true
}
func adminAccountError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "account unavailable")
	case errors.Is(err, store.ErrAdminPermission):
		writeError(w, 403, "permission denied")
	case errors.Is(err, store.ErrLastOwner):
		writeError(w, 409, "at least one enabled owner is required")
	case errors.Is(err, store.ErrAdminConflict):
		writeError(w, 409, "account data conflict")
	default:
		writeError(w, 503, "account service unavailable")
	}
}

func (a *application) registerAdminAccountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/admin/bootstrap", a.requireRoot(a.bootstrapAdminOwner))
	mux.HandleFunc("POST /api/v1/admin/login", a.requireRoot(a.loginAdministrator))
	mux.HandleFunc("GET /api/v1/admin/me", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		s, ok := store.AdminPrincipal(r.Context())
		if !ok {
			writeError(w, 401, "personal session required")
			return
		}
		writeJSON(w, 200, s)
	}))
	mux.HandleFunc("POST /api/v1/admin/logout", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		s, ok := store.AdminPrincipal(r.Context())
		if !ok {
			writeError(w, 401, "personal session required")
			return
		}
		if err := a.store.RevokeAdminSession(r.Context(), s.ID); err != nil {
			adminAccountError(w, err)
			return
		}
		w.WriteHeader(204)
	}))
	mux.HandleFunc("PUT /api/v1/admin/me/password", a.requireAdmin(a.changeOwnAdminPassword))
	mux.HandleFunc("GET /api/v1/admin/accounts", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !adminOwnerRequired(w, r) {
			return
		}
		items, err := a.store.ListAdminAccounts(r.Context())
		if err != nil {
			adminAccountError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"accounts": items})
	}))
	mux.HandleFunc("POST /api/v1/admin/accounts", a.requireAdmin(a.createAdministrator))
	mux.HandleFunc("PATCH /api/v1/admin/accounts/{id}", a.requireAdmin(a.updateAdministrator))
	mux.HandleFunc("PUT /api/v1/admin/accounts/{id}/password", a.requireAdmin(a.resetAdminPassword))
}

func (a *application) bootstrapAdminOwner(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input struct {
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
	}
	if tenantReadJSON(w, r, &input) != nil {
		writeError(w, 400, "invalid bootstrap request")
		return
	}
	owner, err := a.store.BootstrapAdminOwner(r.Context(), strings.TrimSpace(input.Username), input.PasswordHash)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": true, "owner": owner})
}

func (a *application) loginAdministrator(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if tenantReadJSON(w, r, &input) != nil {
		writeError(w, 400, "invalid login request")
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if !store.ValidAdminUsername(input.Username) || input.Password == "" || len(input.Password) > 1024 || len(input.Code) > 6 || len(input.RecoveryCode) > 64 {
		writeError(w, 401, "invalid login credentials")
		return
	}
	if !admitAdminLogin(input.Username) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "try again later")
		return
	}
	if !acquirePasswordWork(w) {
		return
	}
	defer func() { <-passwordWork }()
	account, hash, err := a.store.AdminLoginRecord(r.Context(), input.Username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		adminAccountError(w, err)
		return
	}
	if !security.VerifyPassword(input.Password, store.AdminPasswordForVerification(hash)) || err != nil {
		writeError(w, 401, "invalid login credentials")
		return
	}
	newHash := ""
	if security.PasswordNeedsUpgrade(store.AdminPasswordForVerification(hash)) {
		newHash, err = security.RehashVerifiedPassword(input.Password)
		if err != nil {
			adminAccountError(w, err)
			return
		}
	}
	token, err := security.NewToken(32)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	token = "vpa1_" + token
	session, err := a.store.CreateAdminSessionWithMFA(r.Context(), account.ID, hash, newHash, security.HashToken(token), input.Code, input.RecoveryCode, os.Getenv("ADMIN_MFA_ENCRYPTION_KEY"))
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrAdminConflict) || errors.Is(err, store.ErrAdminMFAInvalid) {
		writeError(w, 401, "invalid login credentials")
		return
	}
	if err != nil {
		adminAccountError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"session_token": token, "session": session})
}

func (a *application) createAdministrator(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	var input struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if tenantReadJSON(w, r, &input) != nil || !store.ValidAdminUsername(input.Username) || !store.ValidAdminRole(input.Role) || !security.ValidNewPassword(input.Password) {
		writeError(w, 400, "valid username, role and password of at least 15 characters required")
		return
	}
	if !acquirePasswordWork(w) {
		return
	}
	defer func() { <-passwordWork }()
	hash, err := security.HashPassword(input.Password)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	account, err := a.store.CreateAdminAccount(r.Context(), input.Username, input.Role, hash)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	writeJSON(w, 201, account)
}

func (a *application) updateAdministrator(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	var input struct {
		Role    *string `json:"role"`
		Enabled *bool   `json:"enabled"`
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) || tenantReadJSON(w, r, &input) != nil || (input.Role == nil && input.Enabled == nil) || (input.Role != nil && !store.ValidAdminRole(*input.Role)) {
		writeError(w, 400, "invalid account update")
		return
	}
	account, err := a.store.UpdateAdminAccount(r.Context(), r.PathValue("id"), input.Role, input.Enabled, nil)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	writeJSON(w, 200, account)
}

func (a *application) resetAdminPassword(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) || tenantReadJSON(w, r, &input) != nil || !security.ValidNewPassword(input.Password) {
		writeError(w, 400, "password of at least 15 characters required")
		return
	}
	if !acquirePasswordWork(w) {
		return
	}
	defer func() { <-passwordWork }()
	hash, err := security.HashPassword(input.Password)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	account, err := a.store.UpdateAdminAccount(r.Context(), r.PathValue("id"), nil, nil, &hash)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	writeJSON(w, 200, account)
}

func (a *application) changeOwnAdminPassword(w http.ResponseWriter, r *http.Request) {
	s, ok := store.AdminPrincipal(r.Context())
	if !ok {
		writeError(w, 401, "personal session required")
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if tenantReadJSON(w, r, &input) != nil || len(input.CurrentPassword) > 1024 || !security.ValidNewPassword(input.NewPassword) {
		writeError(w, 400, "valid current and new passwords required")
		return
	}
	if !admitAdminLogin(s.Account.Username) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "try again later")
		return
	}
	if !acquirePasswordWork(w) {
		return
	}
	defer func() { <-passwordWork }()
	_, hash, err := a.store.AdminLoginRecord(r.Context(), s.Account.Username)
	if err != nil || !security.VerifyPassword(input.CurrentPassword, store.AdminPasswordForVerification(hash)) {
		writeError(w, 401, "current password is invalid")
		return
	}
	newHash, err := security.HashPassword(input.NewPassword)
	if err != nil {
		adminAccountError(w, err)
		return
	}
	if err = a.store.ChangeOwnAdminPassword(r.Context(), hash, newHash); err != nil {
		adminAccountError(w, err)
		return
	}
	w.WriteHeader(204)
}

func monitorRouteAllowed(pattern string) bool {
	switch pattern {
	case "GET /api/v1/admin/me/mfa", "POST /api/v1/admin/me/mfa/enroll", "POST /api/v1/admin/me/mfa/confirm", "POST /api/v1/admin/me/mfa/disable", "POST /api/v1/admin/me/mfa/recovery-codes",
		"GET /api/v1/admin/me", "POST /api/v1/admin/logout", "PUT /api/v1/admin/me/password",
		"GET /api/v1/admin/me/sessions", "DELETE /api/v1/admin/me/sessions", "DELETE /api/v1/admin/me/sessions/{id}",
		"GET /api/v1/nodes", "GET /api/v1/nodes/{id}", "GET /api/v1/nodes/{id}/lifecycle", "GET /api/v1/nodes/{id}/metrics",
		"GET /api/v1/operations/status", "GET /api/v1/operations/incidents":
		return true
	default:
		return false
	}
}
