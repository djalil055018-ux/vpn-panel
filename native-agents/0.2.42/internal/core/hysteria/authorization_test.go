package hysteria

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func check(a *Authorizer, payload string, remote string) (int, string) {
	r := httptest.NewRequest("POST", "http://localhost/auth", strings.NewReader(payload))
	r.RemoteAddr = remote
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}
func TestSnapshotRevocationRotationAndNoPartialPublish(t *testing.T) {
	var a Authorizer
	x := strings.Repeat("a", 32)
	y := strings.Repeat("b", 32)
	if _, ok := a.allowed(x); ok {
		t.Fatal("empty initial state permits client")
	}
	if removed, e := a.Replace([]Client{{"client-a", x}}); e != nil || len(removed) != 0 {
		t.Fatal("initial publish failed")
	}
	if _, e := a.Replace([]Client{{"client-b", y}, {"bad id", x}}); e == nil {
		t.Fatal("invalid batch accepted")
	}
	if id, ok := a.allowed(x); !ok || id != "client-a" {
		t.Fatal("invalid batch changed current policy")
	}
	removed, e := a.Replace([]Client{{"client-a", y}})
	if e != nil || len(removed) != 1 || removed[0] != "client-a" {
		t.Fatal("credential rotation must kick old connections")
	}
	if _, ok := a.allowed(x); ok {
		t.Fatal("old credential accepted")
	}
	removed, e = a.Replace(nil)
	if e != nil || len(removed) != 1 {
		t.Fatal("deny-all update failed")
	}
	if _, ok := a.allowed(y); ok {
		t.Fatal("deny-all accepted a client")
	}
}
func TestHTTPBoundary(t *testing.T) {
	var a Authorizer
	secret := strings.Repeat("a", 32)
	_, _ = a.Replace([]Client{{"client-a", secret}})
	valid, _ := json.Marshal(map[string]any{"addr": "192.0.2.1:1234", "auth": secret, "tx": 0})
	code, body := check(&a, string(valid), "127.0.0.1:4567")
	if code != 200 || !strings.Contains(body, `"ok":true`) || strings.Contains(body, secret) {
		t.Fatal("valid loopback auth failed or leaked credential")
	}
	for _, payload := range []string{`{}`, string(valid) + `{}`, strings.Replace(string(valid), secret, "wrong", 1), `{"auth":"` + strings.Repeat("a", 5000) + `"}`, `{"unknown":true}`, `{"auth":"` + secret + `","tx":-1}`} {
		code, body = check(&a, payload, "127.0.0.1:4567")
		if code != 200 || body != `{"ok":false}` {
			t.Fatal("malformed request accepted")
		}
	}
	code, _ = check(&a, string(valid), "192.0.2.2:4567")
	if code != 403 {
		t.Fatal("non-loopback caller accepted")
	}
	r := httptest.NewRequest("GET", "http://localhost/auth", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("unexpected method accepted")
	}
}
func TestConcurrentSnapshotReaders(t *testing.T) {
	var a Authorizer
	secret := strings.Repeat("a", 32)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_, _ = a.allowed(secret)
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		_, _ = a.Replace([]Client{{"client-a", secret}})
		_, _ = a.Replace(nil)
	}
	wg.Wait()
}
