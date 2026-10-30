package main

import (
	"net/http"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
	"vpn-platform/internal/subscriptioncompat"
)

// Returning false delegates to the unchanged native URI/file response.
func (a *application) serveNativeAutoSubscription(w http.ResponseWriter, r *http.Request, client model.VPNClient, connections []model.VPNClientConnection) bool {
	profile, err := a.store.SubscriptionAutoForConnections(r.Context(), client.TenantID, client.ID, connections)
	if err != nil {
		writeError(w, 503, "automatic profile unavailable")
		return true
	}
	// A saved full-config URL must keep its format after the owner disables
	// Auto; otherwise the next refresh would replace JSON with URI text.
	if !profile.Enabled && r.PathValue("format") == "" {
		return false
	}
	hosts := []subscriptioncompat.Host{}
	index := map[int]int{}
	for i, c := range connections {
		if c.Protocol == "wireguard" || c.Protocol == "amneziawg" || c.Protocol == "openvpn" || c.Protocol == "pptp" {
			continue
		}
		h, e := store.SubscriptionHost(c)
		if e != nil {
			writeError(w, 503, "subscription rendering unavailable")
			return true
		}
		index[i] = len(hosts)
		hosts = append(hosts, h)
	}
	ids := make([]string, len(hosts))
	for connectionIndex, hostIndex := range index {
		ids[hostIndex] = connections[connectionIndex].ServiceID
	}
	hosts, err = a.store.ApplyClientCascadeDial(r.Context(), client.TenantID, hosts, ids)
	if err != nil {
		writeError(w, 503, "subscription network policy unavailable")
		return true
	}
	candidates := profile.Candidates[:0]
	for _, c := range profile.Candidates {
		if i, ok := index[c.HostIndex]; ok {
			c.HostIndex = i
			candidates = append(candidates, c)
		}
	}
	profile.Candidates = candidates
	if len(hosts) == 0 {
		return false
	}
	format := subscriptioncompat.NativeAutoFormat(r.UserAgent(), r.PathValue("format"))
	hosts, added := subscriptioncompat.WithAuto(hosts, profile, format)
	body, err := subscriptioncompat.RenderClient(hosts, subscriptioncompat.NativeTemplate(format), format, client.VLESSUUID)
	if err == nil {
		body, err = subscriptioncompat.AdaptHiddifySubscription(body, format, r.UserAgent())
	}
	if err != nil {
		writeError(w, 503, "subscription rendering unavailable")
		return true
	}
	if added {
		subscriptioncompat.SetAutoNetworkHeaders(w.Header(), r.UserAgent(), format, profile)
	}
	mime := "application/json"
	if format == "XRAY_BASE64" {
		mime = "text/plain"
	} else if format == "MIHOMO" || format == "STASH" || format == "CLASH" {
		mime = "text/yaml"
	}
	w.Header().Set("Content-Type", mime+"; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}
