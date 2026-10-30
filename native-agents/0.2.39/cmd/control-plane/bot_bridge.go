package main

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/store"
)

func (a *application) registerBotBridgeRoutes(mux *http.ServeMux) {
	for _, r := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /api/v1/tenant/bot/status", a.botStatus},
		{"POST /api/v1/tenant/bot/customer-context", a.customerSubscriptionContext},
		{"POST /api/v1/tenant/bot/customer-renew", a.customerRenewNative},
		{"POST /api/v1/tenant/bot/customer-devices", a.customerNativeDevices},
		{"POST /api/v1/tenant/bot/customer-device-limit", a.customerNativeDeviceLimit},
		{"GET /api/v1/tenant/bot/users/stream", a.botUsers},
		{"POST /api/v1/tenant/bot/users", a.botCreateUser},
		{"PATCH /api/v1/tenant/bot/users", a.botPatchUser},
		{"GET /api/v1/tenant/bot/users/{bot_id}", a.botUser},
		{"GET /api/v1/tenant/bot/users/by-username/{username}", a.botUser},
		{"GET /api/v1/tenant/bot/subscriptions/by-id/{bot_id}", a.botUser},
		{"GET /api/v1/tenant/bot/hwid/devices/{bot_id}", a.botDevices},
		{"GET /api/v1/tenant/bot/nodes", a.botNodes},
		{"POST /api/v1/tenant/bot/users/{bot_id}/actions/{action}", a.botUserAction},
		{"DELETE /api/v1/tenant/bot/users/{bot_id}", a.botUserAction},
		{"POST /api/v1/tenant/bot/hwid/devices/delete", a.botDeleteDevices},
		{"POST /api/v1/tenant/bot/hwid/devices/delete-all", a.botDeleteDevices},
	} {
		mux.HandleFunc(r.pattern, a.requireTenantAPI("", true, r.handler))
	}
}

func (a *application) botNodes(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.BotNodes(r.Context())
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"response": out})
}

func (a *application) botCreateUser(w http.ResponseWriter, r *http.Request) {
	key, err := botOperationKey(r)
	if err != nil {
		botError(w, err)
		return
	}
	var input store.BotCreateInput
	if err = botMutationBody(r, &input, "username", "durationDays", "telegramId", "description", "trafficLimitBytes", "trafficLimitStrategy", "hwidDeviceLimit", "activeInternalSquads"); err != nil {
		botError(w, err)
		return
	}
	out, err := a.store.BotCreateUser(r.Context(), key, input)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, out.Status, out.Body)
}
func (a *application) botPatchUser(w http.ResponseWriter, r *http.Request) {
	key, err := botOperationKey(r)
	if err != nil {
		botError(w, err)
		return
	}
	var input store.BotPatchInput
	if err = botMutationBody(r, &input, "id", "expireAt", "trafficLimitBytes", "hwidDeviceLimit", "description", "activeInternalSquads"); err != nil {
		botError(w, err)
		return
	}
	out, err := a.store.BotPatchUser(r.Context(), key, input)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, out.Status, out.Body)
}

func botMutationBody(r *http.Request, dst any, allowed ...string) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil {
		return store.ErrBotBridgeRequest
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if botbridge.DecodeRequest(raw, dst, allowed...) != nil {
		return store.ErrBotBridgeRequest
	}
	return nil
}
func botOperationKey(r *http.Request) (string, error) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) > 1 {
		return "", store.ErrBotBridgeRequest
	}
	return r.Header.Get("Idempotency-Key"), nil
}
func (a *application) botUserAction(w http.ResponseWriter, r *http.Request) {
	id, err := botNumericID(r.PathValue("bot_id"))
	if err != nil {
		botError(w, err)
		return
	}
	key, err := botOperationKey(r)
	if err != nil {
		botError(w, err)
		return
	}
	action := r.PathValue("action")
	if r.Method == "DELETE" {
		action = "delete"
	}
	var body struct {
		Days int `json:"days"`
	}
	allowed := []string{}
	if action == "extend" {
		allowed = []string{"days"}
	}
	if err = botMutationBody(r, &body, allowed...); err != nil {
		botError(w, err)
		return
	}
	out, err := a.store.BotUserAction(r.Context(), id, action, key, body.Days)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, out.Status, out.Body)
}
func (a *application) botDeleteDevices(w http.ResponseWriter, r *http.Request) {
	key, err := botOperationKey(r)
	if err != nil {
		botError(w, err)
		return
	}
	var body struct {
		UserID int64  `json:"userId"`
		HWID   string `json:"hwid"`
	}
	all := r.URL.Path == "/api/v1/tenant/bot/hwid/devices/delete-all"
	allowed := []string{"userId"}
	if !all {
		allowed = append(allowed, "hwid")
	}
	if err = botMutationBody(r, &body, allowed...); err != nil {
		botError(w, err)
		return
	}
	var hwid *string
	if !all {
		hwid = &body.HWID
	}
	out, err := a.store.BotDeleteDevices(r.Context(), body.UserID, hwid, key)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, out.Status, out.Body)
}
func botError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "account not found")
	case errors.Is(err, store.ErrBotBridgeHeld):
		writeError(w, 409, "bot integration is not active")
	case errors.Is(err, store.ErrBotBridgeRequest):
		writeError(w, 400, "invalid bot request")
	case errors.Is(err, store.ErrBotBridgeConflict):
		writeError(w, 409, "bot operation conflicts with current state")
	case errors.Is(err, store.ErrTenantQuota):
		writeError(w, 409, "tenant resource limit reached")
	default:
		writeError(w, 503, "bot operation unavailable")
	}
}
func botNumericID(raw string) (int64, error) {
	if len(raw) == 0 || len(raw) > 16 || raw[0] == '0' {
		return 0, store.ErrBotBridgeRequest
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, store.ErrBotBridgeRequest
		}
	}
	id, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || id < 1 || id > 9007199254740991 {
		return 0, store.ErrBotBridgeRequest
	}
	return id, nil
}
func (a *application) botStatus(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.BotBridgeStatus(r.Context())
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (a *application) botUser(w http.ResponseWriter, r *http.Request) {
	var name *string
	var id int64
	if s := r.PathValue("username"); s != "" {
		name = &s
	} else {
		var err error
		id, err = botNumericID(r.PathValue("bot_id"))
		if err != nil {
			botError(w, err)
			return
		}
	}
	out, err := a.store.BotUser(r.Context(), id, name)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"response": out})
}
func (a *application) botDevices(w http.ResponseWriter, r *http.Request) {
	id, err := botNumericID(r.PathValue("bot_id"))
	if err != nil {
		botError(w, err)
		return
	}
	out, err := a.store.BotDevices(r.Context(), id)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"response": out})
}
func (a *application) botUsers(w http.ResponseWriter, r *http.Request) {
	f := store.BotUserFilter{Size: 250}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		botError(w, store.ErrBotBridgeRequest)
		return
	}
	for k, v := range query {
		if len(v) != 1 {
			botError(w, store.ErrBotBridgeRequest)
			return
		}
		switch k {
		case "size":
			f.Size, err = strconv.Atoi(v[0])
		case "cursor":
			if v[0] != "0" {
				f.After, err = botNumericID(v[0])
			}
		case "telegramId":
			var n int64
			if v[0] != "0" {
				n, err = botNumericID(v[0])
			}
			f.TelegramID = &n
		case "username":
			f.Username = &v[0]
		case "email":
			f.Email = &v[0]
		default:
			err = store.ErrBotBridgeRequest
		}
		if err != nil {
			botError(w, store.ErrBotBridgeRequest)
			return
		}
	}
	out, err := a.store.BotUsers(r.Context(), f)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"response": out})
}
