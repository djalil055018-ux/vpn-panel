package main

import (
	"net/http"
	"time"
)

// The authenticated agent can read only its own safe lifecycle metadata.
// No administrator credential or desired-state secret is needed by installers.
func (a *application) agentSelfStatus(w http.ResponseWriter, r *http.Request) {
	node := currentNode(r.Context())
	status, err := a.store.NodeLifecycle(r.Context(), node.ID, time.Now().UTC())
	if err != nil {
		writeError(w, 503, "node status temporarily unavailable")
		return
	}
	writeJSON(w, 200, status)
}
