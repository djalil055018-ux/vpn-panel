package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
	"vpn-platform/internal/store"
	"vpn-platform/internal/subscriptioncompat"
)

type subscriptionDeviceProofKey struct{}

func (a *application) registerDeviceRoutes(mux *http.ServeMux) {
	for _, item := range []struct {
		method, path string
		write        bool
		handler      http.HandlerFunc
	}{
		{"GET", "/devices", false, a.getRegisteredDevices},
		{"PUT", "/device-limit", true, a.setRegisteredDeviceLimit},
		{"DELETE", "/devices/{device_id}", true, a.deleteRegisteredDevice},
	} {
		mux.HandleFunc(item.method+" /api/v1/vpn-clients/{id}"+item.path, a.requireAdmin(item.handler))
		mux.HandleFunc(item.method+" /api/v1/tenant/clients/{id}"+item.path, a.requireTenantAPI("client", item.write, item.handler))
	}
}

func registeredDeviceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "client or device not found")
	case errors.Is(err, store.ErrRegisteredDevicesTooMany):
		writeError(w, 409, "remove registered devices before lowering the limit")
	default:
		writeError(w, 503, "device settings unavailable")
	}
}
func registeredDeviceClient(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid client id")
		return false
	}
	return true
}
func (a *application) getRegisteredDevices(w http.ResponseWriter, r *http.Request) {
	if !registeredDeviceClient(w, r) {
		return
	}
	value, err := a.store.RegisteredDevices(r.Context(), r.PathValue("id"))
	if err != nil {
		registeredDeviceError(w, err)
		return
	}
	writeJSON(w, 200, value)
}
func (a *application) setRegisteredDeviceLimit(w http.ResponseWriter, r *http.Request) {
	if !registeredDeviceClient(w, r) {
		return
	}
	var body struct {
		Limit *int `json:"limit"`
	}
	if tenantReadJSON(w, r, &body) != nil || body.Limit == nil || *body.Limit < 0 || *body.Limit > 1000 {
		writeError(w, 400, "limit must be an integer from 0 to 1000; zero disables enforcement")
		return
	}
	value, err := a.store.SetRegisteredDeviceLimit(r.Context(), r.PathValue("id"), *body.Limit)
	if err != nil {
		registeredDeviceError(w, err)
		return
	}
	writeJSON(w, 200, value)
}
func (a *application) deleteRegisteredDevice(w http.ResponseWriter, r *http.Request) {
	if !registeredDeviceClient(w, r) {
		return
	}
	if !accessPlanUUID.MatchString(r.PathValue("device_id")) {
		writeError(w, 400, "invalid device id")
		return
	}
	value, err := a.store.DeleteRegisteredDevice(r.Context(), r.PathValue("id"), r.PathValue("device_id"))
	if err != nil {
		registeredDeviceError(w, err)
		return
	}
	writeJSON(w, 200, value)
}

func (a *application) checkSubscriptionDevice(w http.ResponseWriter, r *http.Request, clientID, alias string, inspectOnly bool) (int, bool) {
	proof, _ := r.Context().Value(subscriptionDeviceProofKey{}).(store.SubscriptionDeviceProof)
	proof.Alias = alias
	device := subscriptioncompat.DeviceFromHeaders(r.Header)
	if len(r.Header.Values("X-Hwid")) != 1 {
		device = nil
	}
	limit, err := a.store.AdmitSubscriptionDevice(r.Context(), clientID, proof, device, inspectOnly || r.Method == http.MethodHead)
	if limit > 0 {
		w.Header().Set("X-Hwid-Active", "true")
		w.Header().Set("X-Hwid-Device-Limit", strconv.Itoa(limit))
	}
	if err == nil {
		return limit, true
	}
	switch {
	case errors.Is(err, store.ErrRegisteredDeviceRequired):
		w.Header().Set("X-Hwid-Not-Supported", "true")
		writeError(w, 404, "open this subscription in an application that supports device registration")
	case errors.Is(err, store.ErrRegisteredDeviceLimit):
		w.Header().Set("X-Hwid-Max-Devices-Reached", "true")
		w.Header().Set("X-Hwid-Limit", "true")
		writeError(w, 404, "device limit reached; remove a registered device first")
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
	default:
		writeError(w, 503, "subscription device check unavailable")
	}
	return limit, false
}

// The public browser response normally contains raw connection links. When a
// limit is enabled, keep account information and the import URL, never raw VPN
// credentials; an application must perform its own identified subscription fetch.
func deviceLimitedBrowserBody(snapshot store.ImportedSubscriptionSnapshot, limit int) ([]byte, error) {
	body, err := subscriptioncompat.BrowserInfo(snapshot.Policy, snapshot.Account, nil, "", time.Now())
	var value map[string]any
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	value["links"] = []string{}
	value["deviceLimit"] = limit
	value["deviceRegistrationRequired"] = true
	value["deviceRegistrationMessage"] = "Откройте подписку в VPN-приложении с поддержкой HWID. Количество привязанных устройств ограничено."
	return json.Marshal(value)
}
func writeDeviceLimitedBrowser(w http.ResponseWriter, r *http.Request, snapshot store.ImportedSubscriptionSnapshot, limit int) {
	body, err := deviceLimitedBrowserBody(snapshot, limit)
	if err != nil {
		writeError(w, 503, "subscription page unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
