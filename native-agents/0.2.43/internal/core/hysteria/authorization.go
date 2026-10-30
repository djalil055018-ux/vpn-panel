// Package hysteria contains the node-local Hysteria runtime adapters.
package hysteria

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
)

var identity = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var credential = regexp.MustCompile(`^[a-zA-Z0-9_-]{32,128}$`)
var ErrClients = errors.New("invalid Hysteria client snapshot")

type Client struct{ ID, Credential string }
type snapshot struct{ allowed map[[32]byte]string }

// Updates are serialized; readers observe a complete immutable snapshot. New
// credentials are not published when any supplied record fails validation.
type Authorizer struct {
	write      sync.Mutex
	current    atomic.Pointer[snapshot]
	persistent *accessJournal
}

func buildSnapshot(clients []Client) (*snapshot, error) {
	next := &snapshot{allowed: make(map[[32]byte]string, len(clients))}
	ids := make(map[string]bool, len(clients))
	if len(clients) > 100000 {
		return nil, ErrClients
	}
	for _, c := range clients {
		if !identity.MatchString(c.ID) || !credential.MatchString(c.Credential) || ids[c.ID] {
			return nil, ErrClients
		}
		hash := sha256.Sum256([]byte(c.Credential))
		if _, exists := next.allowed[hash]; exists {
			return nil, ErrClients
		}
		next.allowed[hash] = c.ID
		ids[c.ID] = true
	}
	return next, nil
}
func (a *Authorizer) Replace(clients []Client) ([]string, error) {
	next, err := buildSnapshot(clients)
	if err != nil {
		return nil, err
	}
	a.write.Lock()
	defer a.write.Unlock()
	if a.persistent != nil {
		return nil, ErrClients
	}
	old := a.current.Swap(next)
	removed := map[string]bool{}
	if old != nil {
		for hash, id := range old.allowed {
			if next.allowed[hash] != id {
				removed[id] = true
			}
		}
	}
	out := make([]string, 0, len(removed))
	for id := range removed {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}
func (a *Authorizer) allowed(value string) (string, bool) {
	if !credential.MatchString(value) {
		return "", false
	}
	s := a.current.Load()
	if s == nil {
		return "", false
	}
	id, ok := s.allowed[sha256.Sum256([]byte(value))]
	return id, ok
}
func (a *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" || r.URL.Path != "/auth" {
		http.NotFound(w, r)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		http.Error(w, "forbidden", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	denied := func() { _, _ = io.WriteString(w, `{"ok":false}`) }
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		denied()
		return
	}
	var input struct {
		Addr string `json:"addr"`
		Auth string `json:"auth"`
		Tx   uint64 `json:"tx"`
	}
	reader := http.MaxBytesReader(w, r.Body, 4096)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		denied()
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		denied()
		return
	}
	if len(input.Addr) > 128 {
		denied()
		return
	}
	id, ok := a.allowed(input.Auth)
	if !ok {
		denied()
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		OK bool   `json:"ok"`
		ID string `json:"id"`
	}{true, id})
}
