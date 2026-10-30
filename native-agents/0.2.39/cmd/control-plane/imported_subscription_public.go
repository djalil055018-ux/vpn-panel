package main

import (
	"errors"
	"net/http"
	"regexp"
	"time"
	"vpn-platform/internal/store"
	"vpn-platform/internal/subscriptioncompat"
)

var publicImportedAlias = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func privateSubscriptionHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (a *application) registerImportedSubscriptionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/public/imported-subscriptions/{alias}", a.getImportedSubscription)
	mux.HandleFunc("GET /api/v1/public/imported-subscriptions/{alias}/{format}", a.getImportedSubscription)
}

func (a *application) getImportedSubscription(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	alias := r.PathValue("alias")
	if !publicImportedAlias.MatchString(alias) {
		http.NotFound(w, r)
		return
	}
	native, nativeErr := a.store.ResolveNativeBotAlias(r.Context(), alias)
	if nativeErr == nil {
		a.serveNativeVPNSubscription(w, r, native, alias)
		return
	}
	if !errors.Is(nativeErr, store.ErrNotFound) {
		writeError(w, 503, "subscription unavailable")
		return
	}
	snapshot, err := a.store.ReadImportedSubscription(r.Context(), store.ImportedSubscriptionLookup{Alias: alias})
	if importedSubscriptionError(w, r, err) {
		return
	}
	a.serveImportedSubscription(w, r, snapshot)
}

type subscriptionStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *subscriptionStatusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *subscriptionStatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(body)
}
func (a *application) serveImportedSubscription(w http.ResponseWriter, r *http.Request, snapshot store.ImportedSubscriptionSnapshot) {
	selected, err := snapshot.Policy.Select(r.Header, r.PathValue("format"))
	if err == nil && snapshot.Account.Status == "ACTIVE" && selected.Format != "BLOCK" && selected.Format != "STATUS_CODE_404" && selected.Format != "STATUS_CODE_451" {
		limit, ok := a.checkSubscriptionDevice(w, r, snapshot.ClientID, snapshot.Account.Alias, selected.Format == "BROWSER")
		if !ok {
			return
		}
		if limit > 0 && selected.Format == "BROWSER" {
			writeDeviceLimitedBrowser(w, r, snapshot, limit)
			return
		}
	}
	writeImportedSubscription(w, r, snapshot)
}

func importedSubscriptionError(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
	} else {
		writeError(w, http.StatusServiceUnavailable, "subscription service unavailable")
	}
	return true
}

// The snapshot comes from one authorized native database view. Never derive
// credentials or canonical URLs from the incoming Host, query or user agent.
func writeImportedSubscription(w http.ResponseWriter, r *http.Request, snapshot store.ImportedSubscriptionSnapshot) {
	privateSubscriptionHeaders(w)
	selection, err := snapshot.Policy.Select(r.Header, r.PathValue("format"))
	if err != nil {
		writeError(w, 400, "invalid subscription request")
		return
	}
	switch selection.Format {
	case "BLOCK", "STATUS_CODE_404":
		http.NotFound(w, r)
		return
	case "STATUS_CODE_451":
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
		return
	case "BROWSER":
		body, err := subscriptioncompat.BrowserInfo(snapshot.Policy, snapshot.Account, snapshot.Hosts, snapshot.Credential, time.Now())
		if err != nil {
			writeError(w, 503, "subscription page unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
		return
	}
	headers, err := snapshot.Policy.ResponseHeaders(snapshot.Account)
	if err != nil {
		writeError(w, 503, "subscription profile unavailable")
		return
	}
	template := subscriptioncompat.Options{}
	if selection.Format != "XRAY_BASE64" {
		value, ok := snapshot.Templates[selection.Format]
		if !ok || value.Format != selection.Format {
			writeError(w, 503, "subscription template unavailable")
			return
		}
		template = value.Body
	}
	// Defense in depth: even a malformed caller snapshot cannot put a real
	// endpoint or credential in a disabled/expired/limited account response.
	hosts := snapshot.Hosts
	if snapshot.Account.Status != "ACTIVE" {
		hosts = nil
	}
	autoAdded := false
	if snapshot.Account.Status == "ACTIVE" {
		hosts, autoAdded = subscriptioncompat.WithAuto(hosts, snapshot.Auto, selection.Format)
	}
	lines, err := snapshot.Policy.Notice(snapshot.Account.Status, len(hosts), snapshot.Account.SubscriptionURL)
	var body []byte
	if err == nil {
		if lines != nil {
			body, err = subscriptioncompat.RenderNotices(lines, template, selection.Format)
		} else if len(hosts) > 0 && snapshot.Account.Status == "ACTIVE" {
			body, err = subscriptioncompat.RenderClient(hosts, template, selection.Format, snapshot.Credential)
		} else {
			body, err = subscriptioncompat.RenderNotices([]string{}, template, selection.Format)
		}
	}
	if err == nil {
		body, err = subscriptioncompat.AdaptHiddifySubscription(body, selection.Format, r.UserAgent())
	}
	if err != nil {
		writeError(w, 503, "subscription rendering unavailable")
		return
	}
	for key, values := range headers {
		w.Header()[key] = values
	}
	if snapshot.BrandName != "" {
		setSubscriptionBranding(w.Header(), snapshot.BrandName)
	}
	subscriptioncompat.SetClientNetworkHeaders(w.Header(), r.UserAgent())
	if autoAdded {
		subscriptioncompat.SetAutoNetworkHeaders(w.Header(), r.UserAgent(), selection.Format, snapshot.Auto)
	}
	mime := "application/json"
	switch selection.Format {
	case "XRAY_BASE64":
		mime = "text/plain"
	case "MIHOMO", "STASH", "CLASH":
		mime = "text/yaml"
	}
	w.Header().Set("Content-Type", mime+"; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
