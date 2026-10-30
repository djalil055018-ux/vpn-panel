package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdministrativeWriterPreservesInformationalResponseAndFlush(t *testing.T) {
	receipts := make(chan int, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveAuditedAdminMutation(w, r, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("first"))
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error("flush unavailable")
			}
			_, _ = w.Write([]byte("second"))
		}, func(context.Context, string, string) (string, error) { return "id", nil }, func(ctx context.Context, id string, status int, responded bool) error {
			if !responded {
				t.Error("ordinary response treated as interruption")
			}
			receipts <- status
			return nil
		})
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	response, err := client.Post(server.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || string(body) != "firstsecond" || response.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("writer changed actual HTTP semantics")
	}
	select {
	case status := <-receipts:
		if status != 200 {
			t.Fatal("informational status recorded as final")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing response receipt")
	}
}

func TestAdministrativeResponseReceipt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		status  int
	}{
		{"empty", func(http.ResponseWriter, *http.Request) {}, 200},
		{"body", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }, 200},
		{"asynchronous acceptance", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }, 202},
		{"permission refusal", func(w http.ResponseWriter, r *http.Request) { writeError(w, 403, "denied") }, 403},
		{"service failure", func(w http.ResponseWriter, r *http.Request) { writeError(w, 503, "unavailable") }, 503},
		{"first final wins", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201); w.WriteHeader(500) }, 201},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/v1/nodes/private-id?token=NEVER_AUDIT", nil)
			r.Pattern = "POST /api/v1/nodes/{id}"
			w := httptest.NewRecorder()
			finished := 0
			begin := func(ctx context.Context, method, pattern string) (string, error) {
				if method != "POST" || pattern != "POST /api/v1/nodes/{id}" {
					t.Fatal("actual URL entered audit")
				}
				return "request", nil
			}
			complete := func(ctx context.Context, id string, status int, responded bool) error {
				finished++
				if id != "request" || status != tc.status || !responded {
					t.Fatalf("wrong receipt: %d %v", status, responded)
				}
				return nil
			}
			serveAuditedAdminMutation(w, r, tc.handler, begin, complete)
			if finished != 1 || w.Code != tc.status {
				t.Fatal("response or receipt changed")
			}
		})
	}
}

func TestAdministrativeAuditRequiresDurableIntent(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	serveAuditedAdminMutation(w, r, func(http.ResponseWriter, *http.Request) { t.Fatal("mutation without intent") }, func(context.Context, string, string) (string, error) { return "", errors.New("unavailable") }, func(context.Context, string, int, bool) error { t.Fatal("unexpected completion"); return nil })
	if w.Code != 503 {
		t.Fatal("intent failure must reject mutation")
	}
}

func TestAdministrativeReceiptSurvivesCancellationAndDoesNotRetryMutation(t *testing.T) {
	type key struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "principal"))
	defer cancel()
	r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	serveAuditedAdminMutation(w, r, func(w http.ResponseWriter, r *http.Request) { cancel(); w.WriteHeader(202) }, func(context.Context, string, string) (string, error) { return "id", nil }, func(ctx context.Context, id string, status int, responded bool) error {
		if ctx.Err() != nil || ctx.Value(key{}) != "principal" {
			t.Fatal("completion lost authenticated context")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded completion")
		}
		return errors.New("database unavailable")
	})
	if w.Code != 202 {
		t.Fatal("late audit failure changed accepted mutation response")
	}
}

func TestAdministrativePanicProducesInterruptedReceiptAndPropagates(t *testing.T) {
	completed := false
	defer func() {
		if recover() != "handler panic" || !completed {
			t.Fatal("panic or receipt lost")
		}
	}()
	serveAuditedAdminMutation(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), func(http.ResponseWriter, *http.Request) { panic("handler panic") }, func(context.Context, string, string) (string, error) { return "id", nil }, func(ctx context.Context, id string, status int, responded bool) error {
		completed = true
		if responded {
			t.Fatal("panic reported as response")
		}
		return nil
	})
}
