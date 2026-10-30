package hysteria

import (
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func clientFor(t *testing.T, s *httptest.Server) *Statistics {
	t.Helper()
	p := s.Listener.Addr().(*net.TCPAddr).Port
	c, e := NewStatistics(p, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal("statistics client failed")
	}
	return c
}
func TestTrafficMappingAndKickWireContract(t *testing.T) {
	kicks := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != strings.Repeat("a", 32) {
			t.Error("stats authentication missing")
		}
		if r.URL.RawQuery != "" {
			t.Error("statistics must never clear counters")
		}
		switch r.URL.Path {
		case "/traffic":
			_, _ = io.WriteString(w, `{"client-a":{"tx":123,"rx":456789}}`)
		case "/kick":
			kicks++
			b, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(b) != `["client-a"]` {
				t.Error("kick payload invalid")
			}
			w.WriteHeader(204)
		default:
			t.Error("unexpected stats route")
		}
	}))
	defer s.Close()
	c := clientFor(t, s)
	counts, e := c.Traffic(context.Background())
	if e != nil || counts["client-a"].UploadBytes != 123 || counts["client-a"].DownloadBytes != 456789 {
		t.Fatal("counter directions incorrect")
	}
	if c.Kick(context.Background(), []string{"client-a"}) != nil || kicks != 1 {
		t.Fatal("kick failed")
	}
	if c.Kick(context.Background(), []string{"bad id"}) == nil || kicks != 1 {
		t.Fatal("invalid kick reached upstream")
	}
}
func TestInvalidStatsResponsesAndRedirects(t *testing.T) {
	for _, payload := range []string{`null`, `{"a":null}`, `{"a":{}}`, `{"a":{"tx":1}}`, `{} {}`, `{"bad id":{"tx":1,"rx":2}}`, `{"a":{"tx":-1,"rx":2}}`, `{"a":{"tx":1,"rx":` + strconv.FormatInt(math.MaxInt64, 10) + `}}`, strings.Repeat("x", 4*1024*1024+1)} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, payload) }))
		c := clientFor(t, s)
		_, e := c.Traffic(context.Background())
		s.Close()
		if e != ErrStatistics {
			t.Fatal("invalid counters accepted or unsafe error")
		}
	}
	for _, status := range []int{302, 401, 500} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://must-not-contact.invalid")
			w.WriteHeader(status)
		}))
		c := clientFor(t, s)
		_, e := c.Traffic(context.Background())
		s.Close()
		if e != ErrStatistics {
			t.Fatal("redirect or upstream failure accepted")
		}
	}
	for _, port := range []int{0, 80, 65536} {
		if _, e := NewStatistics(port, strings.Repeat("a", 32)); e == nil {
			t.Fatal("invalid local stats endpoint accepted")
		}
	}
}
