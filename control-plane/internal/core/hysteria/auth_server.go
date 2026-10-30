package hysteria

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var ErrAuthorizationServer = errors.New("Hysteria local authorization service unavailable")

// AuthorizationServer owns a loopback-only, bounded HTTP endpoint. Losing this
// endpoint stops the managed core; silently losing new-login checks while old
// connections continue is not treated as a healthy agent. Close completes core
// cleanup before returning, even if the initiating operation was cancelled.
type AuthorizationServer struct {
	server   *http.Server
	listener net.Listener
	manager  *AccessManager
	once     sync.Once
	done     chan struct{}
	err      error
}

// Port zero reserves an OS-selected loopback port for staging. The outer driver
// must compile the runtime config with Port() before starting the core.
func StartAuthorizationServer(port int, manager *AccessManager) (*AuthorizationServer, error) {
	if manager == nil || port < 0 || port > 65535 || (port > 0 && port < 1024) {
		return nil, ErrAuthorizationServer
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		return nil, errors.Join(ErrAuthorizationServer, manager.Shutdown(ctx))
	}
	s := &AuthorizationServer{manager: manager, listener: listener, done: make(chan struct{})}
	s.server = &http.Server{Handler: manager, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		err := s.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		} else {
			err = ErrAuthorizationServer
		}
		s.finish(err)
		close(s.done)
	}()
	return s, nil
}

func (s *AuthorizationServer) Port() int { return s.listener.Addr().(*net.TCPAddr).Port }
func (s *AuthorizationServer) finish(cause error) {
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		stopErr := s.manager.Shutdown(ctx)
		_ = s.server.Close()
		s.err = errors.Join(cause, stopErr)
	})
}
func (s *AuthorizationServer) Close() error { s.finish(nil); <-s.done; return s.err }
func (s *AuthorizationServer) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
