package main

import (
	"encoding/json"
	"net/http"
	"time"
	"vpn-platform/internal/store"
	"vpn-platform/internal/subscriptioncompat"
)

// Point the unchanged subscription page's REMNAWAVE_PANEL_URL to this prefix
// with a viewer token scoped to the imported tenant. Metadata and browser API
// calls require that token. The unchanged source frontend explicitly removes
// Authorization when relaying raw client subscriptions: those two routes use
// the same bearer alias authorization as the canonical public subscription API.
const importedPagePrefix = "/api/v1/tenant/subscription-page"
const controlPlaneVersion = "0.1.139"

func (a *application) registerImportedPageRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+importedPagePrefix+"/api/sub/{alias}", a.getImportedSubscription)
	mux.HandleFunc("GET "+importedPagePrefix+"/api/sub/{alias}/{format}", a.getImportedSubscription)
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET " + importedPagePrefix + "/api/system/metadata", a.importedPageMetadata},
		{"GET " + importedPagePrefix + "/api/subscription-page-configs/{$}", a.importedPageConfigs},
		{"GET " + importedPagePrefix + "/api/subscription-page-configs/{page_id}", a.importedPageConfigs},
		{"GET " + importedPagePrefix + "/api/subscriptions/subpage-config/{alias}", a.importedPageSelection},
		{"GET " + importedPagePrefix + "/api/sub/{alias}/info", a.importedPageInfo},
	} {
		mux.HandleFunc(route.pattern, a.requireTenantAPI("", false, func(w http.ResponseWriter, r *http.Request) {
			principal, ok := store.TenantPrincipal(r.Context())
			if !ok || (principal.Role != "viewer" && principal.Role != "operator") {
				writeError(w, 403, "subscription page reader required")
				return
			}
			route.handler(w, r)
		}))
	}
}
func (a *application) importedPageMetadata(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	// Startup must fail for held/paused public profiles, just like page enumeration.
	if _, err := a.store.ImportedSubscriptionPages(r.Context()); importedSubscriptionError(w, r, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"response": subscriptioncompat.FrontendMetadata(controlPlaneVersion)})
}
func (a *application) importedPageConfigs(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	if id := r.PathValue("page_id"); id != "" && !accessPlanUUID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	pages, err := a.store.ImportedSubscriptionPages(r.Context())
	if importedSubscriptionError(w, r, err) {
		return
	}
	if id := r.PathValue("page_id"); id != "" {
		for _, page := range pages {
			if page.ID == id {
				writeJSON(w, 200, map[string]any{"response": page})
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	writeJSON(w, 200, map[string]any{"response": map[string]any{"total": len(pages), "configs": pages}})
}
func (a *application) importedPageInfo(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	snapshot, err := a.store.ReadImportedSubscription(r.Context(), store.ImportedSubscriptionLookup{Alias: r.PathValue("alias")})
	if importedSubscriptionError(w, r, err) {
		return
	}
	limit, ok := a.checkSubscriptionDevice(w, r, snapshot.ClientID, snapshot.Account.Alias, true)
	if !ok {
		return
	}
	var body []byte
	if limit > 0 {
		body, err = deviceLimitedBrowserBody(snapshot, limit)
	} else {
		body, err = subscriptioncompat.BrowserInfo(snapshot.Policy, snapshot.Account, snapshot.Hosts, snapshot.Credential, time.Now())
	}
	if importedSubscriptionError(w, r, err) {
		return
	}
	writeJSON(w, 200, map[string]any{"response": json.RawMessage(body)})
}
func (a *application) importedPageSelection(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	var request struct {
		Headers map[string]string `json:"requestHeaders"`
	}
	if tenantReadJSON(w, r, &request) != nil || request.Headers == nil {
		writeError(w, 400, "request headers required")
		return
	}
	snapshot, err := a.store.ReadImportedSubscription(r.Context(), store.ImportedSubscriptionLookup{Alias: r.PathValue("alias")})
	if importedSubscriptionError(w, r, err) {
		return
	}
	headers := http.Header{}
	for key, value := range request.Headers {
		headers.Set(key, value)
	}
	selection, err := snapshot.Policy.Select(headers, "")
	if err != nil {
		writeError(w, 400, "invalid page request")
		return
	}
	writeJSON(w, 200, map[string]any{"response": map[string]any{"subpageConfigUuid": snapshot.Policy.PageID, "webpageAllowed": selection.Format == "BROWSER"}})
}
