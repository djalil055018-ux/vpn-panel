package main

import (
	"context"
	"log"
	"net/http"
	"time"
)

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *auditResponseWriter) WriteHeader(code int) {
	// Informational responses do not finish the HTTP response.
	if w.status == 0 && code >= 200 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *auditResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}
func (w *auditResponseWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *auditResponseWriter) Flush() { _ = w.FlushError() }

type beginAdminAudit func(context.Context, string, string) (string, error)
type completeAdminAudit func(context.Context, string, int, bool) error

func serveAuditedAdminMutation(w http.ResponseWriter, r *http.Request, next http.HandlerFunc, begin beginAdminAudit, complete completeAdminAudit) {
	id, err := begin(r.Context(), r.Method, r.Pattern)
	if err != nil {
		writeError(w, 503, "audit service unavailable")
		return
	}
	tracked := &auditResponseWriter{ResponseWriter: w}
	responded := false
	defer func() {
		// A disconnect or revoked session must not erase an already executed request.
		// Preserve the authenticated principal, but bound the independent DB write.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
		defer cancel()
		if err := complete(ctx, id, tracked.status, responded); err != nil {
			// The response may already have reached the client. Do not replace it with
			// a retryable error after the mutation; the durable intent remains visible.
			log.Print("administrative request outcome unavailable; intent retained")
		}
	}()
	next(tracked, r)
	if tracked.status == 0 {
		tracked.status = http.StatusOK
	}
	responded = tracked.status >= 200 && tracked.status <= 599
}
