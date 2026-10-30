package hysteria

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuthorizationServerRealHTTPAndCloseStopsCore(t *testing.T) {
	m, r, _ := managerFixture(t)
	if err := m.Apply(context.Background(), 1, policyA()); err != nil {
		t.Fatal(err)
	}
	s, err := StartAuthorizationServer(0, m)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	address := s.listener.Addr().(*net.TCPAddr)
	if !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("auth bound outside loopback")
	}
	client := &http.Client{Timeout: time.Second}
	for _, credential := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		response, err := client.Post("http://127.0.0.1:"+strconv.Itoa(s.Port())+"/auth", "application/json", strings.NewReader(`{"auth":"`+credential+`","addr":"192.0.2.1:1234","tx":0}`))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || strings.Contains(string(raw), credential) || strings.Contains(string(raw), `"ok":true`) != (credential == strings.Repeat("a", 32)) {
			t.Fatal("HTTP auth result invalid")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if r.running {
		t.Fatal("auth shutdown left core running")
	}
	if conn, err := net.DialTimeout("tcp", address.String(), 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("listener remained open")
	}
}
func TestAuthorizationListenerFailureStopsCoreAndReportsFailure(t *testing.T) {
	m, r, _ := managerFixture(t)
	if err := m.Apply(context.Background(), 1, policyA()); err != nil {
		t.Fatal(err)
	}
	s, err := StartAuthorizationServer(0, m)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Wait(ctx); !errors.Is(err, ErrAuthorizationServer) {
		t.Fatal("listener failure hidden", err)
	}
	if r.running {
		t.Fatal("listener failure left core active")
	}
}
func TestAuthorizationBindFailureStopsCore(t *testing.T) {
	m, r, _ := managerFixture(t)
	if err := m.Apply(context.Background(), 1, policyA()); err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if _, err := StartAuthorizationServer(occupied.Addr().(*net.TCPAddr).Port, m); !errors.Is(err, ErrAuthorizationServer) {
		t.Fatal("bind failure accepted")
	}
	if r.running {
		t.Fatal("auth bind failure left core active")
	}
}
func TestAuthorizationCloseSurfacesUnconfirmedStop(t *testing.T) {
	m, r, _ := managerFixture(t)
	s, err := StartAuthorizationServer(0, m)
	if err != nil {
		t.Fatal(err)
	}
	r.stopError = errors.New("synthetic stop failure")
	if err := s.Close(); !errors.Is(err, ErrRuntimeStop) {
		t.Fatal("stop failure hidden")
	}
}
